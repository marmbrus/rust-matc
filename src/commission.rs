use anyhow::{Context, Result};
use rand::RngCore;

use crate::{
    cert_matter, cert_x509, certmanager, controller::auth_sigma, fabric::Fabric, messages,
    retransmit, session, tlv, transport::ConnectionTrait,
};

const CLUSTER_OPERATIONAL_CREDENTIALS: u32 = 0x3e;
const CMD_OPERATIONAL_CREDENTIALS_ADDTRUSTEDROOTCERTIFICATE: u32 = 0xb;
const CMD_OPERATIONAL_CREDENTIALS_ADDNOC: u32 = 0x6;
const CMD_OPERATIONAL_CSRREQUEST: u32 = 0x4;
//const CMD_OPERATIONAL_ATTESTATION_REQUEST: u32 = 0x0;
//const CMD_OPERATIONAL_CERTCHAIN_REQUEST: u32 = 0x2;

const CLUSTER_GENERAL_COMMISSIONING: u32 = 0x30;
const CMD_GENERAL_COMMISSIONING_ARMFAILSAFE: u32 = 0;
const CMD_GENERAL_COMMISSIONING_SETREGULATORYCONFIG: u32 = 2;
const CMD_GENERAL_COMMISSIONING_COMMISSIONINGCOMPLETE: u32 = 4;

#[cfg(feature = "ble")]
const CLUSTER_NETWORK_COMMISSIONING: u32 = 0x31;
#[cfg(feature = "ble")]
const CMD_NETWORK_ADD_OR_UPDATE_WIFI: u32 = 2;
#[cfg(feature = "ble")]
const CMD_NETWORK_ADD_OR_UPDATE_THREAD: u32 = 3;
#[cfg(feature = "ble")]
const CMD_NETWORK_CONNECT: u32 = 6;

/// Credentials for the network the device should join after commissioning.
#[derive(Clone)]
pub enum NetworkCreds {
    /// Commission a Wi-Fi device: provide SSID and passphrase bytes.
    WiFi { ssid: Vec<u8>, creds: Vec<u8> },
    /// Commission a Thread device: provide the operational dataset bytes.
    Thread { dataset: Vec<u8> },
    /// Device is already on the IP network (Ethernet or pre-provisioned); skip
    /// NetworkCommissioning cluster writes.
    AlreadyOnNetwork,
    /// Whichever of these fits the device, for a device whose kind of network isn't known
    /// beforehand: its Network Commissioning cluster says whether it joins Wi-Fi or Thread (or is
    /// on Ethernet, and needs none), which is read before the device is given anything.
    Any(Vec<NetworkCreds>),
}

/// The kind of network interface a device's Network Commissioning cluster on endpoint 0 is for,
/// from its feature map.
#[cfg(feature = "ble")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkInterface {
    WiFi,
    Thread,
    Ethernet,
}

#[cfg(feature = "ble")]
impl NetworkInterface {
    /// The interface a feature map says, or `None` when it doesn't say exactly one: each instance
    /// of the cluster is for one interface.
    fn from_feature_map(features: u64) -> Option<Self> {
        match features & 0b111 {
            0b001 => Some(Self::WiFi),
            0b010 => Some(Self::Thread),
            0b100 => Some(Self::Ethernet),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::WiFi => "Wi-Fi",
            Self::Thread => "Thread",
            Self::Ethernet => "Ethernet",
        }
    }

    /// The interface `creds` are for, if they're for one.
    fn of(creds: &NetworkCreds) -> Option<Self> {
        match creds {
            NetworkCreds::WiFi { .. } => Some(Self::WiFi),
            NetworkCreds::Thread { .. } => Some(Self::Thread),
            NetworkCreds::AlreadyOnNetwork | NetworkCreds::Any(_) => None,
        }
    }
}

/// The credentials to give a device whose Network Commissioning cluster is for `interface`
/// (`None` when reading it failed): one of `offered`'s, which can't be [`NetworkCreds::Any`].
/// Fails when none fit, before anything has been sent to the device but reads.
#[cfg(feature = "ble")]
fn credentials_for(offered: &NetworkCreds, interface: Option<NetworkInterface>) -> Result<NetworkCreds> {
    match (offered, interface) {
        (NetworkCreds::AlreadyOnNetwork, _) => Ok(NetworkCreds::AlreadyOnNetwork),
        (NetworkCreds::Any(_), Some(NetworkInterface::Ethernet)) => Ok(NetworkCreds::AlreadyOnNetwork),
        (NetworkCreds::Any(all), Some(interface)) => all
            .iter()
            .find(|creds| NetworkInterface::of(creds) == Some(interface))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("the device joins {} networks, and no {} credentials were given", interface.name(), interface.name())),
        (NetworkCreds::Any(all), None) => match all.as_slice() {
            [only] if NetworkInterface::of(only).is_some() => Ok(only.clone()),
            _ => Err(anyhow::anyhow!("the device didn't say which kind of network it joins, so it can't be chosen for it")),
        },
        (creds, Some(interface)) if NetworkInterface::of(creds) != Some(interface) => Err(anyhow::anyhow!(
            "the device joins {} networks, not {}",
            interface.name(),
            NetworkInterface::of(creds).map_or("this kind", NetworkInterface::name)
        )),
        (creds, _) => Ok(creds.clone()),
    }
}

/// The status in a command's response fields (tag 0, as General Commissioning's, Network
/// Commissioning's and AddNOC's responses carry it). A device that turns the command itself down
/// answers with a status for the command instead of its response, which is an error naming it.
fn command_status(resp: &messages::Message, command: &str) -> Result<u64> {
    if let Some(status) = resp.tlv.get_int(&[1, 0, 0, 1, 0]) {
        return Ok(status);
    }
    // An InvokeResponse's CommandStatusIB, or a StatusResponse.
    let status = if resp.protocol_header.opcode == messages::ProtocolMessageHeader::INTERACTION_OPCODE_STATUS_RESP {
        resp.tlv.get_int(&[0])
    } else {
        resp.tlv.get_int(&[1, 0, 1, 1, 0])
    };
    match status {
        Some(status) if status != 0 => Err(anyhow::anyhow!(
            "{} turned down: {} (0x{:02x})",
            command,
            im_status_name(status),
            status
        )),
        _ => Err(anyhow::anyhow!("{}: status missing", command)),
    }
}

/// Interaction Model status codes' names, for errors.
fn im_status_name(status: u64) -> &'static str {
    match status {
        0x00 => "SUCCESS",
        0x01 => "FAILURE",
        0x7e => "UNSUPPORTED_ACCESS",
        0x7f => "UNSUPPORTED_ENDPOINT",
        0x80 => "INVALID_ACTION",
        0x81 => "UNSUPPORTED_COMMAND",
        0x85 => "INVALID_COMMAND",
        0x86 => "UNSUPPORTED_ATTRIBUTE",
        0x87 => "CONSTRAINT_ERROR",
        0x89 => "RESOURCE_EXHAUSTED",
        0x8b => "NOT_FOUND",
        0x8d => "INVALID_DATA_TYPE",
        0x94 => "TIMEOUT",
        0x9c => "BUSY",
        0xc3 => "UNSUPPORTED_CLUSTER",
        0xc6 => "NEEDS_TIMED_INTERACTION",
        0xca => "FAILSAFE_REQUIRED",
        0xcb => "INVALID_IN_STATE",
        _ => "unknown status",
    }
}


/*async fn run_attestation(
    retrctx: &mut retransmit::RetrContext<'_>,
    exchange_base: u16,
) -> Result<()> {
    // CertificateChainRequest(PAI)
    {
        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_uint8(0, 2)?; // certificateType = 2 = PAI
        let req = messages::im_invoke_request(
            0,
            CLUSTER_OPERATIONAL_CREDENTIALS,
            CMD_OPERATIONAL_CERTCHAIN_REQUEST,
            exchange_base,
            &tlv_buf.data,
            false,
        )?;
        retrctx.send(&req).await?;
        let _resp = retrctx.get_next_message().await.context("CertChainRequest PAI")?;
    }

    // CertificateChainRequest(DAC)
    {
        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_uint8(0, 1)?; // certificateType = 1 = DAC
        let req = messages::im_invoke_request(
            0,
            CLUSTER_OPERATIONAL_CREDENTIALS,
            CMD_OPERATIONAL_CERTCHAIN_REQUEST,
            exchange_base.wrapping_add(1),
            &tlv_buf.data,
            false,
        )?;
        retrctx.send(&req).await?;
        let _resp = retrctx.get_next_message().await.context("CertChainRequest DAC")?;
    }

    // AttestationRequest
    {
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut tlv_buf = tlv::TlvBuffer::new();
        tlv_buf.write_octetstring(0, &nonce)?;
        let req = messages::im_invoke_request(
            0,
            CLUSTER_OPERATIONAL_CREDENTIALS,
            CMD_OPERATIONAL_ATTESTATION_REQUEST,
            exchange_base.wrapping_add(2),
            &tlv_buf.data,
            false,
        )?;
        retrctx.send(&req).await?;
        let _resp = retrctx.get_next_message().await.context("AttestationRequest")?;
    }

    Ok(())
}*/

async fn push_ca_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
    exchange_id: u16,
) -> Result<()> {
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let ca_cert = cm.get_ca_cert()?;
    let mcert = cert_matter::convert_x509_bytes_to_matter(&ca_cert, &ca_pubkey)?;
    log::debug!("AddTrustedRootCertificate: matter cert TLV ({} bytes): {}", mcert.len(),
        mcert.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(""));
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &mcert)?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CREDENTIALS_ADDTRUSTEDROOTCERTIFICATE,
        exchange_id,
        &tlv.data,
        false,
    )?;
    retrcrx.send(&t1).await?;

    // push ca cert response
    let resp = retrcrx.get_next_message().await?;
    let noc_status = {
        resp.tlv
            .get_int(&[1, 0, 1, 1, 0])
            .context("can't get status for AddTrustedRootCertificate")?
    };
    if noc_status != 0 {
        return Err(anyhow::anyhow!(
            "AddTrustedRootCertificate failed with status {}/{}",
            noc_status,
            noc_status_to_str(noc_status)
        ));
    }
    Ok(())
}

fn noc_status_to_str(status: u64) -> &'static str {
    match status {
        0 => "Success",
        1 => "InvalidPublicKey",
        2 => "InvalidNodeOpId",
        3 => "InvalidNOC",
        4 => "MissingCsr",
        5 => "TableFull",
        6 => "InvalidAdminSubject",
        7 => "?",
        8 => "?",
        9 => "FabricConflict",
        10 => "LabelConflict",
        11 => "InvalidFabricIndex",
        _ => "UnknownStatus",
    }
}

async fn push_device_cert(
    retrcrx: &mut retransmit::RetrContext<'_>,
    cm: &dyn certmanager::CertManager,
    csrd: x509_cert::request::CertReq,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
    exchange_id: u16,
) -> Result<()> {
    let ca_id = fabric.ca_id;
    let ca_pubkey = cm.get_ca_key()?.public_key().to_sec1_bytes();
    let node_public_key = csrd
        .info
        .public_key
        .subject_public_key
        .as_bytes()
        .context("can't extract pubkey from csr")?;
    let ca_private = cm.get_ca_key()?;
    let noc_x509 = cert_x509::encode_x509(
        node_public_key,
        node_id,
        cm.get_fabric_id(),
        ca_id,
        &ca_private,
        false,
    )?;
    let noc = cert_matter::convert_x509_bytes_to_matter(&noc_x509, &ca_pubkey)?;
    let mut tlv = tlv::TlvBuffer::new();
    tlv.write_octetstring(0, &noc)?;
    tlv.write_octetstring(2, &fabric.ipk_epoch_key)?;
    tlv.write_uint64(3, controller_id)?;
    tlv.write_uint16(4, 101)?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CREDENTIALS_ADDNOC,
        exchange_id,
        &tlv.data,
        false,
    )?;
    retrcrx.send(&t1).await?;

    let resp = retrcrx.get_next_message().await?;
    let noc_status = command_status(&resp, "AddNOC")?;
    if noc_status != 0 {
        return Err(anyhow::anyhow!("AddNOC failed with status {}/{}", noc_status, noc_status_to_str(noc_status)));
    }
    Ok(())
}

async fn send_csr(
    retrcrx: &mut retransmit::RetrContext<'_>,
    exchange_id: u16,
) -> Result<x509_cert::request::CertReq> {
    let mut tlv = tlv::TlvBuffer::new();
    let mut random_csr_nonce = vec![0; 32];
    rand::thread_rng().fill_bytes(&mut random_csr_nonce);
    tlv.write_octetstring(0, &random_csr_nonce)?;
    let csr_request = messages::im_invoke_request(
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS,
        CMD_OPERATIONAL_CSRREQUEST,
        exchange_id,
        &tlv.data,
        false,
    )?;
    retrcrx.send(&csr_request).await?;

    let csr_msg = retrcrx.get_next_message().await?;

    let csr_tlve = csr_msg
        .tlv
        .get_octet_string(&[1, 0, 0, 1, 0])
        .context("csr tlv missing")?;
    let csr_t = tlv::decode_tlv(csr_tlve).context("csr tlv can't decode")?;
    let csr = csr_t
        .get_octet_string(&[1])
        .context("csr tlv in tlv missing")?;
    let csrd = x509_cert::request::CertReq::try_from(csr)?;
    Ok(csrd)
}

async fn commissioning_complete(
    connection: &dyn ConnectionTrait,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<session::Session> {
    // resumption ignored for now - we do not support resumption on connections used for commissioning
    let (ses, _resumption) = auth_sigma(connection, fabric, cm, node_id, controller_id).await?;
    let t1 = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_COMMISSIONINGCOMPLETE,
        30,
        &[],
        false,
    )?;
    let mut retrctx = retransmit::RetrContext::new(connection, &ses);

    retrctx.send(&t1).await?;
    let resp = retrctx.get_next_message().await?;
    let comresp_status = command_status(&resp, "CommissioningComplete")?;
    if comresp_status != 0 {
        return Err(anyhow::anyhow!(
            "CommissioningComplete failed with status {}",
            comresp_status
        ));
    }
    Ok(ses)
}

pub(crate) async fn commission(
    connection: &dyn ConnectionTrait,
    session: &mut session::Session,
    fabric: &Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
) -> Result<session::Session> {
    // node operational credentials procedure
    let mut retrctx = retransmit::RetrContext::new(connection, session);
    let base: u16 = rand::random();

    arm_failsafe(&mut retrctx, 60, base).await?;

    let csrd = send_csr(&mut retrctx, base.wrapping_add(1)).await?;

    push_ca_cert(&mut retrctx, cm, base.wrapping_add(2)).await?;

    push_device_cert(&mut retrctx, cm, csrd, node_id, controller_id, fabric, base.wrapping_add(3)).await?;

    let ses = commissioning_complete(connection, cm, node_id, controller_id, fabric).await?;

    Ok(ses)
}

async fn arm_failsafe(
    retrctx: &mut retransmit::RetrContext<'_>,
    timeout_secs: u16,
    exchange_id: u16,
) -> Result<()> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_uint16(0, timeout_secs)?;
    tlv_buf.write_uint64(1, 0)?; // breadcrumb
    let req = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_ARMFAILSAFE,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = command_status(&resp, "ArmFailSafe")?;
    if status != 0 {
        return Err(anyhow::anyhow!("ArmFailSafe failed with status {}", status));
    }
    Ok(())
}

#[cfg(feature = "ble")]
async fn set_regulatory_config(
    retrctx: &mut retransmit::RetrContext<'_>,
    location: u8,
    exchange_id: u16,
) -> Result<()> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_uint8(0, location)?;
    tlv_buf.write_string(1, "XX")?; // country unknown, which the spec allows
    tlv_buf.write_uint64(2, 0)?;  // breadcrumb
    let req = messages::im_invoke_request(
        0,
        CLUSTER_GENERAL_COMMISSIONING,
        CMD_GENERAL_COMMISSIONING_SETREGULATORYCONFIG,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = command_status(&resp, "SetRegulatoryConfig")?;
    if status != 0 {
        return Err(anyhow::anyhow!("SetRegulatoryConfig failed with status {}", status));
    }
    Ok(())
}

/// What a device says about being commissioned, read before its network step. Each is `None`
/// when the device doesn't answer.
#[cfg(feature = "ble")]
#[derive(Debug, Default)]
struct CommissioningInfo {
    /// General Commissioning BasicCommissioningInfo.MaxCumulativeFailsafeSeconds.
    max_cumulative_failsafe_secs: Option<u16>,
    /// General Commissioning LocationCapability: 0 indoor, 1 outdoor, 2 both.
    location_capability: Option<u8>,
    /// General Commissioning SupportsConcurrentConnection: whether the device keeps the
    /// commissioning channel (Bluetooth) up while it joins the network.
    concurrent_connection: Option<bool>,
    /// Network Commissioning ConnectMaxTimeSeconds: how long joining the network can take.
    connect_max_secs: Option<u8>,
    /// Network Commissioning's feature map: which kind of network the device joins.
    network_interface: Option<NetworkInterface>,
}

#[cfg(feature = "ble")]
impl CommissioningInfo {
    /// The fail-safe to arm before ConnectNetwork: long enough to join the network, then be found
    /// over operational mDNS and finish over IP. The device caps it at its cumulative maximum.
    fn network_failsafe_secs(&self) -> u16 {
        u16::from(self.connect_max_secs.unwrap_or(60)) + 120
    }

    /// How long to wait for ConnectNetworkResponse, or `None` when the device won't send one over
    /// the commissioning channel because it drops that channel to join the network.
    fn connect_response_wait(&self) -> Option<std::time::Duration> {
        if self.concurrent_connection == Some(false) {
            return None;
        }
        Some(std::time::Duration::from_secs(u64::from(self.connect_max_secs.unwrap_or(60)) + 30))
    }

    /// The location for SetRegulatoryConfig: the device's own, or indoor and outdoor when it can be both.
    fn regulatory_location(&self) -> u8 {
        match self.location_capability {
            Some(location @ 0..=1) => location,
            _ => 2,
        }
    }
}

/// Reads one attribute from endpoint 0 and returns the ReportData message.
#[cfg(feature = "ble")]
async fn read_attribute(
    retrctx: &mut retransmit::RetrContext<'_>,
    cluster: u32,
    attr: u32,
    exchange_id: u16,
) -> Result<messages::Message> {
    let req = messages::im_read_request(0, cluster, attr, exchange_id)?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    if resp.protocol_header.opcode != messages::ProtocolMessageHeader::INTERACTION_OPCODE_REPORT_DATA {
        anyhow::bail!("reading 0x{:04x}/0x{:04x} answered with opcode 0x{:02x}", cluster, attr, resp.protocol_header.opcode);
    }
    Ok(resp)
}

/// Reads what the device says about being commissioned. A device that doesn't answer one of these
/// still gets commissioned, with the defaults.
#[cfg(feature = "ble")]
async fn read_commissioning_info(retrctx: &mut retransmit::RetrContext<'_>, exchange_id: u16) -> CommissioningInfo {
    const ATTR_BASIC_COMMISSIONING_INFO: u32 = 0x0001;
    const ATTR_LOCATION_CAPABILITY: u32 = 0x0003;
    const ATTR_SUPPORTS_CONCURRENT_CONNECTION: u32 = 0x0004;
    const ATTR_CONNECT_MAX_TIME_SECONDS: u32 = 0x0003;
    const ATTR_FEATURE_MAP: u32 = 0xfffc;
    const VALUE: [u8; 4] = [1, 0, 1, 2];
    let mut info = CommissioningInfo::default();
    let reads = [
        (CLUSTER_GENERAL_COMMISSIONING, ATTR_BASIC_COMMISSIONING_INFO),
        (CLUSTER_GENERAL_COMMISSIONING, ATTR_LOCATION_CAPABILITY),
        (CLUSTER_GENERAL_COMMISSIONING, ATTR_SUPPORTS_CONCURRENT_CONNECTION),
        (CLUSTER_NETWORK_COMMISSIONING, ATTR_CONNECT_MAX_TIME_SECONDS),
        (CLUSTER_NETWORK_COMMISSIONING, ATTR_FEATURE_MAP),
    ];
    for (i, (cluster, attr)) in reads.into_iter().enumerate() {
        let resp = match read_attribute(retrctx, cluster, attr, exchange_id.wrapping_add(i as u16)).await {
            Ok(resp) => resp,
            Err(e) => {
                log::debug!("reading 0x{:04x}/0x{:04x} failed: {:?}", cluster, attr, e);
                continue;
            }
        };
        match (cluster, attr) {
            (CLUSTER_GENERAL_COMMISSIONING, ATTR_BASIC_COMMISSIONING_INFO) => {
                info.max_cumulative_failsafe_secs = resp.tlv.get_u16(&[1, 0, 1, 2, 1]);
            }
            (CLUSTER_GENERAL_COMMISSIONING, ATTR_LOCATION_CAPABILITY) => {
                info.location_capability = resp.tlv.get_u8(&VALUE);
            }
            (CLUSTER_GENERAL_COMMISSIONING, ATTR_SUPPORTS_CONCURRENT_CONNECTION) => {
                if let Some(tlv::TlvItemValue::Bool(b)) = resp.tlv.get(&VALUE) {
                    info.concurrent_connection = Some(*b);
                }
            }
            (CLUSTER_NETWORK_COMMISSIONING, ATTR_CONNECT_MAX_TIME_SECONDS) => {
                info.connect_max_secs = resp.tlv.get_u8(&VALUE);
            }
            _ => info.network_interface = resp.tlv.get_int(&VALUE).and_then(NetworkInterface::from_feature_map),
        }
    }
    info
}


#[cfg(feature = "ble")]
async fn add_or_update_wifi(
    retrctx: &mut retransmit::RetrContext<'_>,
    ssid: &[u8],
    creds: &[u8],
    exchange_id: u16,
) -> Result<Vec<u8>> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_octetstring(0, ssid)?;
    tlv_buf.write_octetstring(1, creds)?;
    let req = messages::im_invoke_request(
        0,
        CLUSTER_NETWORK_COMMISSIONING,
        CMD_NETWORK_ADD_OR_UPDATE_WIFI,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = command_status(&resp, "AddOrUpdateWifiNetwork")?;
    if status != 0 {
        return Err(anyhow::anyhow!("AddOrUpdateWifiNetwork failed with status {}", status));
    }
    Ok(ssid.to_vec())
}

#[cfg(feature = "ble")]
// Parse a Thread Operational Dataset (simple TLV: 1-byte type, 1-byte length, N-byte value)
// and return the Extended PAN ID bytes (type 0x02, length 8).
fn extract_thread_extended_pan_id(dataset: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= dataset.len() {
        let tlv_type = dataset[i];
        let tlv_len = dataset[i + 1] as usize;
        if i + 2 + tlv_len > dataset.len() {
            break;
        }
        if tlv_type == 0x02 && tlv_len == 8 {
            return Some(&dataset[i + 2..i + 2 + tlv_len]);
        }
        i += 2 + tlv_len;
    }
    None
}

#[cfg(feature = "ble")]
async fn add_or_update_thread(
    retrctx: &mut retransmit::RetrContext<'_>,
    dataset: &[u8],
    exchange_id: u16,
) -> Result<Vec<u8>> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_octetstring(0, dataset)?;
    let req = messages::im_invoke_request(
        0,
        CLUSTER_NETWORK_COMMISSIONING,
        CMD_NETWORK_ADD_OR_UPDATE_THREAD,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let resp = retrctx.get_next_message().await?;
    let status = command_status(&resp, "AddOrUpdateThreadNetwork")?;
    if status != 0 {
        return Err(anyhow::anyhow!("AddOrUpdateThreadNetwork failed with status {}", status));
    }
    let ext_pan_id = extract_thread_extended_pan_id(dataset)
        .ok_or_else(|| anyhow::anyhow!("Thread dataset missing Extended PAN ID (TLV type 0x02)"))?
        .to_vec();
    Ok(ext_pan_id)
}

/// NetworkingStatusEnum names, for errors.
#[cfg(feature = "ble")]
fn networking_status(status: u64) -> &'static str {
    match status {
        1 => "OutOfRange",
        2 => "BoundsExceeded",
        3 => "NetworkIDNotFound",
        4 => "DuplicateNetworkID",
        5 => "NetworkNotFound",
        6 => "RegulatoryError",
        7 => "AuthFailure",
        8 => "UnsupportedSecurity",
        9 => "OtherConnectionFailure",
        10 => "IPV6Failed",
        11 => "IPBindFailed",
        _ => "UnknownError",
    }
}

/// Sends ConnectNetwork. Waits up to `wait` for the response; with no wait, or none arriving, the
/// device is looked for on the network next, where it shows up once it has joined.
#[cfg(feature = "ble")]
async fn connect_network(
    retrctx: &mut retransmit::RetrContext<'_>,
    network_id: &[u8],
    exchange_id: u16,
    wait: Option<std::time::Duration>,
) -> Result<()> {
    let mut tlv_buf = tlv::TlvBuffer::new();
    tlv_buf.write_octetstring(0, network_id)?;
    tlv_buf.write_uint64(1, 0)?; // breadcrumb
    let req = messages::im_invoke_request(
        0,
        CLUSTER_NETWORK_COMMISSIONING,
        CMD_NETWORK_CONNECT,
        exchange_id,
        &tlv_buf.data,
        false,
    )?;
    retrctx.send(&req).await?;
    let Some(wait) = wait else {
        log::info!("Not waiting for ConnectNetworkResponse: the device drops Bluetooth to join the network");
        return Ok(());
    };
    let resp = match tokio::time::timeout(wait, retrctx.get_next_message()).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            log::warn!("No ConnectNetworkResponse ({:#}); looking for the device on the network anyway", e);
            return Ok(());
        }
        Err(_) => {
            log::warn!("No ConnectNetworkResponse in {}s; looking for the device on the network anyway", wait.as_secs());
            return Ok(());
        }
    };
    let status = command_status(&resp, "ConnectNetwork")?;
    if status != 0 {
        return Err(anyhow::anyhow!("ConnectNetwork failed: {} ({})", networking_status(status), status));
    }
    Ok(())
}

#[cfg(feature = "ble")]
pub(crate) async fn commission_ble_phase(
    ble_connection: &dyn ConnectionTrait,
    pase_session: &mut session::Session,
    fabric: &Fabric,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    network_creds: &NetworkCreds,
) -> Result<()> {
    let mut retrctx = retransmit::RetrContext::new(ble_connection, pase_session);
    let base: u16 = rand::random();
    let e_arm      = base;
    let e_reg      = base.wrapping_add(1);
    // run_attestation uses e_attest+0, e_attest+1, e_attest+2 (3 exchanges)
    //let e_attest   = base.wrapping_add(2);
    let e_csr      = base.wrapping_add(5);
    let e_ca       = base.wrapping_add(6);
    let e_noc      = base.wrapping_add(7);
    let e_net1     = base.wrapping_add(8);
    let e_net2     = base.wrapping_add(9);
    let e_arm2     = base.wrapping_add(10);
    let e_info     = base.wrapping_add(11); // five reads: 11..=15

    arm_failsafe(&mut retrctx, 60, e_arm).await.context("ArmFailSafe")?;
    log::debug!("Failsafe armed for 60 seconds");

    let info = read_commissioning_info(&mut retrctx, e_info).await;
    log::info!("Commissionee: {:?}", info);
    // Chosen before the device is given anything, so one that can't join is left as it was.
    let network_creds = credentials_for(network_creds, info.network_interface)?;
    if let Some(interface) = NetworkInterface::of(&network_creds) {
        log::info!("Giving the device {} credentials", interface.name());
    }
    // matc paired devices without this before; one that turns it down still gets commissioned.
    match set_regulatory_config(&mut retrctx, info.regulatory_location(), e_reg).await {
        Ok(()) => log::debug!("Regulatory configuration set"),
        Err(e) => log::warn!("SetRegulatoryConfig: {:#}", e),
    }

    //run_attestation(&mut retrctx, e_attest).await.context("Attestation")?;
    //log::debug!("Attestation completed");

    let csrd = send_csr(&mut retrctx, e_csr).await?;
    log::debug!("CSR received");
    push_ca_cert(&mut retrctx, cm, e_ca).await?;
    log::debug!("CA certificate pushed");
    push_device_cert(&mut retrctx, cm, csrd, node_id, controller_id, fabric, e_noc).await?;
    log::debug!("Device certificate pushed");

    match &network_creds {
        NetworkCreds::WiFi { ssid, creds } => {
            let net_id = add_or_update_wifi(&mut retrctx, ssid, creds, e_net1).await?;
            rearm_for_network(&mut retrctx, &info, e_arm2).await?;
            connect_network(&mut retrctx, &net_id, e_net2, info.connect_response_wait()).await?;
            log::debug!("WiFi network connected");
            // Give the device time to join the network before the caller probes mDNS.
            //tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        NetworkCreds::Thread { dataset } => {
            let net_id = add_or_update_thread(&mut retrctx, dataset, e_net1).await?;
            rearm_for_network(&mut retrctx, &info, e_arm2).await?;
            connect_network(&mut retrctx, &net_id, e_net2, info.connect_response_wait()).await?;
            log::debug!("Thread network connected");
            //tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
        // credentials_for never gives back Any.
        NetworkCreds::AlreadyOnNetwork | NetworkCreds::Any(_) => {}
    }

    Ok(())
}

/// Re-arms the fail-safe so it outlasts joining the network and finishing over IP; the first 60
/// seconds can run out before a slow device has joined.
#[cfg(feature = "ble")]
async fn rearm_for_network(retrctx: &mut retransmit::RetrContext<'_>, info: &CommissioningInfo, exchange_id: u16) -> Result<()> {
    let secs = info.network_failsafe_secs();
    arm_failsafe(retrctx, secs, exchange_id).await.context("re-arming the fail-safe for the network step")?;
    log::debug!("Failsafe re-armed for {} seconds", secs);
    Ok(())
}

#[cfg(feature = "ble")]
pub(crate) async fn commissioning_complete_udp(
    udp_connection: &dyn ConnectionTrait,
    cm: &dyn certmanager::CertManager,
    node_id: u64,
    controller_id: u64,
    fabric: &Fabric,
) -> Result<session::Session> {
    commissioning_complete(udp_connection, cm, node_id, controller_id, fabric).await
}

#[cfg(all(test, feature = "ble"))]
mod network_step_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_waits_and_failsafe_follow_the_device() {
        // A device that drops Bluetooth to join gets no wait; the fail-safe still covers joining.
        let drops = CommissioningInfo { concurrent_connection: Some(false), connect_max_secs: Some(90), ..Default::default() };
        assert_eq!(drops.connect_response_wait(), None);
        assert_eq!(drops.network_failsafe_secs(), 210);

        let keeps = CommissioningInfo { concurrent_connection: Some(true), connect_max_secs: Some(20), ..Default::default() };
        assert_eq!(keeps.connect_response_wait(), Some(Duration::from_secs(50)));
        assert_eq!(keeps.network_failsafe_secs(), 140);

        // A device that answers none of the reads gets the spec's defaults.
        let silent = CommissioningInfo::default();
        assert_eq!(silent.connect_response_wait(), Some(Duration::from_secs(90)));
        assert_eq!(silent.network_failsafe_secs(), 180);
    }

    #[test]
    fn test_regulatory_location() {
        let at = |location| CommissioningInfo { location_capability: location, ..Default::default() }.regulatory_location();
        assert_eq!(at(Some(0)), 0);
        assert_eq!(at(Some(1)), 1);
        assert_eq!(at(Some(2)), 2);
        assert_eq!(at(None), 2);
    }

    #[test]
    fn test_networking_status_names() {
        assert_eq!(networking_status(5), "NetworkNotFound");
        assert_eq!(networking_status(7), "AuthFailure");
        assert_eq!(networking_status(200), "UnknownError");
    }

    #[test]
    fn test_interface_from_feature_map() {
        assert_eq!(NetworkInterface::from_feature_map(0b001), Some(NetworkInterface::WiFi));
        assert_eq!(NetworkInterface::from_feature_map(0b010), Some(NetworkInterface::Thread));
        assert_eq!(NetworkInterface::from_feature_map(0b100), Some(NetworkInterface::Ethernet));
        // Feature bits past the interface's don't matter; none, or more than one, says nothing.
        assert_eq!(NetworkInterface::from_feature_map(0b1010), Some(NetworkInterface::Thread));
        assert_eq!(NetworkInterface::from_feature_map(0), None);
        assert_eq!(NetworkInterface::from_feature_map(0b011), None);
    }

    #[test]
    fn test_credentials_follow_the_device() {
        let wifi = NetworkCreds::WiFi { ssid: b"IOT.NET".to_vec(), creds: b"secret".to_vec() };
        let thread = NetworkCreds::Thread { dataset: vec![0x0e, 0x08] };
        let kind = |creds: Result<NetworkCreds>| creds.map(|c| NetworkInterface::of(&c)).map_err(|e| e.to_string());
        let any = NetworkCreds::Any(vec![thread.clone(), wifi.clone()]);

        assert_eq!(kind(credentials_for(&any, Some(NetworkInterface::WiFi))), Ok(Some(NetworkInterface::WiFi)));
        assert_eq!(kind(credentials_for(&any, Some(NetworkInterface::Thread))), Ok(Some(NetworkInterface::Thread)));
        assert!(matches!(credentials_for(&any, Some(NetworkInterface::Ethernet)), Ok(NetworkCreds::AlreadyOnNetwork)));
        assert_eq!(
            kind(credentials_for(&NetworkCreds::Any(vec![thread.clone()]), Some(NetworkInterface::WiFi))),
            Err("the device joins Wi-Fi networks, and no Wi-Fi credentials were given".to_string())
        );
        // A device that doesn't say gets the only kind there is, and can't be guessed between two.
        assert_eq!(kind(credentials_for(&NetworkCreds::Any(vec![wifi.clone()]), None)), Ok(Some(NetworkInterface::WiFi)));
        assert!(credentials_for(&any, None).is_err());

        // Credentials of one kind go only to a device of that kind, or one that doesn't say.
        assert_eq!(
            kind(credentials_for(&thread, Some(NetworkInterface::WiFi))),
            Err("the device joins Wi-Fi networks, not Thread".to_string())
        );
        assert_eq!(kind(credentials_for(&thread, Some(NetworkInterface::Thread))), Ok(Some(NetworkInterface::Thread)));
        assert_eq!(kind(credentials_for(&wifi, None)), Ok(Some(NetworkInterface::WiFi)));
        assert!(matches!(credentials_for(&NetworkCreds::AlreadyOnNetwork, Some(NetworkInterface::WiFi)), Ok(NetworkCreds::AlreadyOnNetwork)));
    }

    /// An InvokeResponse with `fields_status` in the command's response fields, or else
    /// `command_status` for the whole command.
    fn invoke_response(fields_status: Option<u8>, command_status: Option<u8>) -> messages::Message {
        let mut b = tlv::TlvBuffer::new();
        b.write_anon_struct().unwrap();
        b.write_bool(0, false).unwrap();
        b.write_array(1).unwrap();
        b.write_anon_struct().unwrap();
        let (tag, status) = match (fields_status, command_status) {
            (Some(status), _) => (0, status),
            (None, Some(status)) => (1, status),
            (None, None) => (0, 0),
        };
        b.write_struct(tag).unwrap();
        b.write_list(0).unwrap();
        b.write_uint16(0, 0).unwrap();
        b.write_uint32(1, CLUSTER_NETWORK_COMMISSIONING).unwrap();
        b.write_uint32(2, CMD_NETWORK_ADD_OR_UPDATE_THREAD).unwrap();
        b.write_struct_end().unwrap();
        b.write_struct(1).unwrap();
        if fields_status.is_some() || command_status.is_some() {
            b.write_uint8(0, status).unwrap();
        }
        b.write_struct_end().unwrap();
        b.write_struct_end().unwrap();
        b.write_struct_end().unwrap();
        b.write_struct_end().unwrap();
        b.write_struct_end().unwrap();
        messages::Message {
            message_header: messages::MessageHeader {
                flags: 0,
                security_flags: 0,
                session_id: 0,
                message_counter: 0,
                source_node_id: None,
                destination_node_id: None,
            },
            protocol_header: messages::ProtocolMessageHeader {
                exchange_flags: 0,
                opcode: messages::ProtocolMessageHeader::INTERACTION_OPCODE_INVOKE_RESP,
                exchange_id: 0,
                protocol_id: messages::ProtocolMessageHeader::PROTOCOL_ID_INTERACTION,
                ack_counter: 0,
            },
            payload: Vec::new(),
            tlv: tlv::decode_tlv(&b.data).unwrap(),
            status_report_info: None,
        }
    }

    #[test]
    fn test_command_status() {
        let status = |resp: messages::Message| command_status(&resp, "AddOrUpdateThreadNetwork").map_err(|e| e.to_string());
        assert_eq!(status(invoke_response(Some(0), None)), Ok(0));
        assert_eq!(status(invoke_response(Some(5), None)), Ok(5));
        // A command the device doesn't have, as AddOrUpdateThreadNetwork is on a Wi-Fi device.
        assert_eq!(
            status(invoke_response(None, Some(0x81))),
            Err("AddOrUpdateThreadNetwork turned down: UNSUPPORTED_COMMAND (0x81)".to_string())
        );
        assert_eq!(status(invoke_response(None, None)), Err("AddOrUpdateThreadNetwork: status missing".to_string()));
    }
}
