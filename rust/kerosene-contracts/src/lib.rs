//! Canonical Kerosene discovery, membership, and admin wire contracts.
//!
//! Signatures are always calculated over [`CanonicalSignable::signing_bytes`],
//! never over an arbitrary JSON serialization.
//!
//! Cross-language signing uses canonical JSON
//! ([`canonical_json_bytes`]) which produces the same bytes in Rust and Java.

use serde::{de, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub const DISCOVERY_CONTRACT_VERSION: &str = "0.2.0";
pub const SECURITY_CONTRACT_VERSION: &str = "0.3.0";
pub const PEER_HELLO_DOMAIN: &[u8] = b"KEROSENE_PEER_HELLO_V1";
pub const ADMISSION_REQUEST_DOMAIN: &[u8] = b"KEROSENE_ADMISSION_REQUEST_V1";
pub const MEMBERSHIP_MANIFEST_DOMAIN: &[u8] = b"KEROSENE_MEMBERSHIP_MANIFEST_V1";
pub const GENESIS_TRUST_BUNDLE_DOMAIN: &[u8] = b"KEROSENE_GENESIS_TRUST_BUNDLE_V1";
pub const ADMIN_CONTRACT_VERSION: &str = "0.1.0";
pub const ADMIN_NODE_STATUS_DOMAIN: &[u8] = b"KEROSENE_ADMIN_NODE_STATUS_V1";
pub const ADMIN_VAULT_STATUS_DOMAIN: &[u8] = b"KEROSENE_ADMIN_VAULT_STATUS_V1";
pub const ADMIN_ERROR_ENVELOPE_DOMAIN: &[u8] = b"KEROSENE_ADMIN_ERROR_ENVELOPE_V1";
pub const ADMIN_AUDIT_REFERENCE_DOMAIN: &[u8] = b"KEROSENE_ADMIN_AUDIT_REFERENCE_V1";
pub const ADMIN_CORE_LEDGER_ACCOUNT_DOMAIN: &[u8] = b"KEROSENE_ADMIN_CORE_LEDGER_ACCOUNT_V1";
pub const ADMIN_CORE_LEDGER_JOURNAL_DOMAIN: &[u8] = b"KEROSENE_ADMIN_CORE_LEDGER_JOURNAL_V1";
pub const ADMIN_P2P_DOMAIN: &[u8] = b"KEROSENE_ADMIN_P2P_V1";
pub const ADMIN_ONRAMP_DOMAIN: &[u8] = b"KEROSENE_ADMIN_ONRAMP_V1";
pub const ADMIN_RECONCILIATION_DOMAIN: &[u8] = b"KEROSENE_ADMIN_RECONCILIATION_V1";
pub const ADMIN_PROVIDER_DOMAIN: &[u8] = b"KEROSENE_ADMIN_PROVIDER_V1";
pub const WORKLOAD_ID_DOMAIN: &[u8] = b"KEROSENE_WORKLOAD_ID_V1";
pub const WORKLOAD_IDENTITY_DOMAIN: &[u8] = b"KEROSENE_WORKLOAD_IDENTITY_V1";
pub const SIGNED_SERVICE_ROSTER_DOMAIN: &[u8] = b"KEROSENE_SIGNED_SERVICE_ROSTER_V1";
pub const SIGNING_INTENT_DOMAIN: &[u8] = b"KEROSENE_SIGNING_INTENT_V1";

// ---------------------------------------------------------------------------
// Admin error envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminErrorEnvelopeV1 {
    pub contract_version: String,
    pub code: String,
    pub message: String,
    pub request_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Audit reference
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReferenceV1 {
    pub event_id: String,
    pub request_id: String,
    pub occurred_at: String,
}

// ---------------------------------------------------------------------------
// Node / vault admin status
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAdminStatusV1 {
    pub contract_version: String,
    pub request_id: String,
    pub network_id: String,
    pub plane: DiscoveryPlane,
    pub local_ready: bool,
    pub member_ready: bool,
    pub quorum_ready: bool,
    pub financial_ready: bool,
    pub live_members: u64,
    pub threshold: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultAdminStatusV1 {
    pub contract_version: String,
    pub request_id: String,
    pub local_ready: bool,
    pub financial_ready: bool,
    pub node_id: String,
    pub ceremony_mode: String,
    pub bitcoin_network: String,
}

// ---------------------------------------------------------------------------
// Ledger account (multi-saldo model)
// ---------------------------------------------------------------------------

/// Admin/core: ledger account for financial read operations.
///
/// Uses a multi-saldo satoshi model — all balances are denominated in sats
/// (1 sat = 1e-8 BTC).  `state_root` is the hex-encoded SHA-256 of the
/// account's internal state and is opaque to the wire protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerAccountV1 {
    pub contract_version: String,
    pub account_id: String,
    pub account_type: String,
    pub available_sats: u64,
    pub reserved_sats: u64,
    pub pending_incoming_sats: u64,
    pub pending_outgoing_sats: u64,
    pub confirmed_onchain_sats: u64,
    pub unconfirmed_onchain_sats: u64,
    pub spendable_by_kerosene_sats: u64,
    pub state_version: u64,
    pub state_root: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Ledger journal (sats-based)
// ---------------------------------------------------------------------------

/// Admin/core: ledger journal entry for financial reconciliation.
///
/// `amount_sats` replaces the old generic `amount` + `currency` pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerJournalV1 {
    pub contract_version: String,
    pub entry_id: String,
    pub account_id: String,
    pub direction: JournalDirection,
    pub amount_sats: u64,
    pub description: String,
    pub reference: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalDirection {
    Debit,
    Credit,
}

impl JournalDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debit => "debit",
            Self::Credit => "credit",
        }
    }
}

// ---------------------------------------------------------------------------
// P2P admin contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminP2PV1 {
    pub contract_version: String,
    pub request_id: String,
    pub channel_id: String,
    pub remote_node_id: String,
    pub capacity_sats: u64,
    pub local_balance_sats: u64,
    pub remote_balance_sats: u64,
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// On-ramp admin contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminOnrampV1 {
    pub contract_version: String,
    pub request_id: String,
    pub order_id: String,
    pub user_id: String,
    pub fiat_currency: String,
    pub fiat_amount: String,
    pub sats: u64,
    pub provider: String,
    pub status: String,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Reconciliation admin contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminReconciliationV1 {
    pub contract_version: String,
    pub request_id: String,
    pub reconciliation_id: String,
    pub ledger_sats: u64,
    pub onchain_sats: u64,
    pub lightning_sats: u64,
    pub delta_sats: i64,
    pub status: String,
    pub reconciled_at: String,
}

// ---------------------------------------------------------------------------
// Provider admin contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminProviderV1 {
    pub contract_version: String,
    pub request_id: String,
    pub provider_id: String,
    pub provider_type: String,
    pub is_online: bool,
    pub last_heartbeat: String,
    pub version: String,
}

// ---------------------------------------------------------------------------
// Discovery / membership types (unchanged)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryPlane {
    Bank,
    Vault,
}

impl DiscoveryPlane {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bank => "bank",
            Self::Vault => "vault",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustMember {
    pub member_id: String,
    /// Ed25519 root public key encoded as 64 lowercase hexadecimal characters.
    pub root_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPlane {
    pub threshold: u16,
    pub members: Vec<TrustMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisTrustBundleV1 {
    pub contract_version: String,
    pub network_id: String,
    pub bank: TrustPlane,
    pub vault: TrustPlane,
    pub created_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerHelloV1 {
    pub contract_version: String,
    pub network_id: String,
    pub plane: DiscoveryPlane,
    pub member_id: String,
    pub root_public_key: String,
    pub challenge: String,
    pub issued_at_epoch_ms: u64,
    pub endpoint: String,
    /// Ed25519 signature encoded as 128 lowercase hexadecimal characters.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRequestV1 {
    pub contract_version: String,
    pub network_id: String,
    pub plane: DiscoveryPlane,
    pub candidate: ManifestMember,
    pub sponsor_id: String,
    pub challenge: String,
    pub issued_at_epoch_ms: u64,
    /// Candidate Ed25519 signature encoded as 128 lowercase hexadecimal characters.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipPhase {
    Stable,
    Joint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestMember {
    pub member_id: String,
    pub root_public_key: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    pub signer_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipManifestV1 {
    pub contract_version: String,
    pub network_id: String,
    pub plane: DiscoveryPlane,
    pub epoch: u64,
    pub phase: MembershipPhase,
    pub previous_manifest_hash: String,
    pub threshold: u16,
    pub members: Vec<ManifestMember>,
    /// Required only during joint consensus and names the intended stable epoch.
    /// A value of `Some(0)` is invalid (schema minimum is 1) and will fail
    /// deserialization with a clear error message.
    #[serde(default, deserialize_with = "deserialize_next_epoch")]
    pub next_epoch: Option<u64>,
    pub signatures: Vec<ManifestSignature>,
}

// ---------------------------------------------------------------------------
// Inter-service identity and KFE -> Vault authorization contracts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadRole {
    Auth,
    Kfe,
    Vault,
    Node,
    Admin,
}

impl WorkloadRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Kfe => "kfe",
            Self::Vault => "vault",
            Self::Node => "node",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityV1 {
    pub contract_version: String,
    pub network_id: String,
    pub workload_id: String,
    pub spiffe_id: String,
    pub role: WorkloadRole,
    pub instance_id: String,
    pub ed25519_public_key: String,
    pub valid_from_epoch_ms: u64,
    pub valid_until_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRosterMemberV1 {
    pub identity: WorkloadIdentityV1,
    /// Routing data only. The peer identity is always verified from mTLS.
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterSignatureV1 {
    /// Member id from the trusted discovery membership manifest.
    pub signer_member_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceRosterV1 {
    pub contract_version: String,
    pub network_id: String,
    pub authority_plane: DiscoveryPlane,
    pub authority_manifest_hash: String,
    pub roster_hash: String,
    pub epoch: u64,
    pub previous_roster_hash: String,
    pub valid_from_epoch_ms: u64,
    pub valid_until_epoch_ms: u64,
    pub members: Vec<ServiceRosterMemberV1>,
    pub signatures: Vec<RosterSignatureV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOperation {
    SignPsbt,
}

impl SigningOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SignPsbt => "sign_psbt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyBucket {
    Users,
    Channels,
}

impl CustodyBucket {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Channels => "channels",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentCommitMode {
    ReserveAndCommit,
    SignReserved,
}

impl IntentCommitMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReserveAndCommit => "reserve_and_commit",
            Self::SignReserved => "sign_reserved",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningIntentV1 {
    pub contract_version: String,
    pub network_id: String,
    pub request_id: String,
    pub intent_id: String,
    pub issuer_workload_id: String,
    pub audience_workload_id: String,
    pub caller_spiffe_id: String,
    pub audience_spiffe_id: String,
    pub issuer_roster_hash: String,
    pub audience_roster_hash: String,
    pub operation: SigningOperation,
    pub wallet_id: String,
    pub bitcoin_network: BitcoinNetwork,
    pub custody_bucket: CustodyBucket,
    pub destination: String,
    pub psbt_sha256: String,
    pub change_descriptor_sha256: String,
    pub policy_hash: String,
    pub policy_epoch: u64,
    pub participant_epoch: u64,
    pub amount_sats: u64,
    pub max_fee_sats: u64,
    pub max_fee_rate_sat_vb: u64,
    pub expected_input_count: u32,
    pub commit_mode: IntentCommitMode,
    pub authorization_hash: String,
    pub nonce: String,
    pub sequence: u64,
    pub issued_at_epoch_ms: u64,
    pub expires_at_epoch_ms: u64,
    pub signature: String,
}

pub trait ValidateContract {
    fn validate(&self) -> Result<(), String>;
}

impl WorkloadIdentityV1 {
    pub fn derive_workload_id(
        network_id: &str,
        spiffe_id: &str,
        role: WorkloadRole,
        instance_id: &str,
        ed25519_public_key: &str,
    ) -> String {
        let mut out = domain(WORKLOAD_ID_DOMAIN);
        field(&mut out, SECURITY_CONTRACT_VERSION.as_bytes());
        field(&mut out, network_id.as_bytes());
        field(&mut out, spiffe_id.as_bytes());
        field(&mut out, role.as_str().as_bytes());
        field(&mut out, instance_id.as_bytes());
        field(&mut out, ed25519_public_key.as_bytes());
        hex::encode(Sha256::digest(out))
    }

    fn encode_fields(&self, out: &mut Vec<u8>) {
        field(out, self.contract_version.as_bytes());
        field(out, self.network_id.as_bytes());
        field(out, self.workload_id.as_bytes());
        field(out, self.spiffe_id.as_bytes());
        field(out, self.role.as_str().as_bytes());
        field(out, self.instance_id.as_bytes());
        field(out, self.ed25519_public_key.as_bytes());
        integer(out, self.valid_from_epoch_ms);
        integer(out, self.valid_until_epoch_ms);
    }
}

impl SignedServiceRosterV1 {
    pub fn computed_roster_hash(&self) -> String {
        hex::encode(Sha256::digest(self.signing_bytes()))
    }

    /// Validate that the roster was authorized by the pinned discovery
    /// manifest. Cryptographic signature verification remains the consumer's
    /// responsibility and MUST use each signer's root public key.
    pub fn validate_authority(&self, authority: &MembershipManifestV1) -> Result<(), String> {
        if authority.contract_version != DISCOVERY_CONTRACT_VERSION {
            return Err("authority contract_version mismatch".into());
        }
        if authority.network_id != self.network_id || authority.plane != self.authority_plane {
            return Err("authority network_id or plane mismatch".into());
        }
        if authority.phase != MembershipPhase::Stable {
            return Err("service roster authority must be a stable manifest".into());
        }
        if canonical_hash(authority) != self.authority_manifest_hash {
            return Err("authority_manifest_hash mismatch".into());
        }
        let threshold = usize::from(authority.threshold);
        if threshold == 0 || threshold > authority.members.len() {
            return Err("invalid authority threshold".into());
        }
        if self.signatures.len() < threshold {
            return Err("service roster does not meet authority threshold".into());
        }
        let authority_ids = authority
            .members
            .iter()
            .map(|member| member.member_id.as_str())
            .collect::<std::collections::HashSet<_>>();
        if self
            .signatures
            .iter()
            .any(|signature| !authority_ids.contains(signature.signer_member_id.as_str()))
        {
            return Err("service roster contains a signer outside the authority manifest".into());
        }
        Ok(())
    }

    /// Reject rollback, skipped epochs and forks from the locally trusted
    /// roster head. Authority validation for the new roster is still required.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), String> {
        previous.validate()?;
        self.validate()?;
        if self.network_id != previous.network_id
            || self.authority_plane != previous.authority_plane
        {
            return Err("service roster successor changed network_id or authority plane".into());
        }
        let expected_epoch = previous
            .epoch
            .checked_add(1)
            .ok_or_else(|| "service roster epoch overflow".to_string())?;
        if self.epoch != expected_epoch {
            return Err("service roster successor must advance exactly one epoch".into());
        }
        if self.previous_roster_hash != previous.roster_hash {
            return Err(
                "service roster successor does not reference the trusted roster head".into(),
            );
        }
        Ok(())
    }
}

impl ValidateContract for WorkloadIdentityV1 {
    fn validate(&self) -> Result<(), String> {
        require_version(&self.contract_version)?;
        require_network(&self.network_id)?;
        require_hex(&self.workload_id, 64, "workload_id")?;
        require_spiffe(&self.spiffe_id)?;
        require_instance(&self.instance_id)?;
        require_hex(&self.ed25519_public_key, 64, "ed25519_public_key")?;
        require_window(self.valid_from_epoch_ms, self.valid_until_epoch_ms)?;
        let expected = Self::derive_workload_id(
            &self.network_id,
            &self.spiffe_id,
            self.role,
            &self.instance_id,
            &self.ed25519_public_key,
        );
        if self.workload_id != expected {
            return Err("workload_id does not match canonical identity material".into());
        }
        Ok(())
    }
}

impl ValidateContract for SignedServiceRosterV1 {
    fn validate(&self) -> Result<(), String> {
        require_version(&self.contract_version)?;
        require_network(&self.network_id)?;
        require_hex(&self.authority_manifest_hash, 64, "authority_manifest_hash")?;
        require_hex(&self.roster_hash, 64, "roster_hash")?;
        require_positive_i64(self.epoch, "epoch")?;
        require_hex(&self.previous_roster_hash, 64, "previous_roster_hash")?;
        let zero_hash = "0".repeat(64);
        if (self.epoch == 1) != (self.previous_roster_hash == zero_hash) {
            return Err("only epoch 1 may use a zero previous_roster_hash".into());
        }
        require_window(self.valid_from_epoch_ms, self.valid_until_epoch_ms)?;
        if self.members.is_empty() {
            return Err("members must not be empty".into());
        }
        if self.signatures.is_empty() {
            return Err("signatures must not be empty".into());
        }
        let mut member_ids = std::collections::HashSet::new();
        for member in &self.members {
            member.identity.validate()?;
            require_endpoint(&member.endpoint)?;
            if member.identity.network_id != self.network_id {
                return Err("member network_id mismatch".into());
            }
            if member.identity.valid_from_epoch_ms > self.valid_from_epoch_ms
                || member.identity.valid_until_epoch_ms < self.valid_until_epoch_ms
            {
                return Err("roster exceeds member validity".into());
            }
            if !member_ids.insert(&member.identity.workload_id) {
                return Err("duplicate member workload_id".into());
            }
        }
        require_sorted_unique(
            self.members
                .iter()
                .map(|member| member.identity.workload_id.as_str()),
            "members",
        )?;
        let mut signers = std::collections::HashSet::new();
        for signature in &self.signatures {
            require_hex(&signature.signer_member_id, 64, "signer_member_id")?;
            require_hex(&signature.signature, 128, "signature")?;
            if !signers.insert(&signature.signer_member_id) {
                return Err("duplicate signature signer".into());
            }
        }
        require_sorted_unique(
            self.signatures
                .iter()
                .map(|signature| signature.signer_member_id.as_str()),
            "signatures",
        )?;
        if self.roster_hash != self.computed_roster_hash() {
            return Err("roster_hash does not match canonical unsigned roster".into());
        }
        Ok(())
    }
}

impl ValidateContract for SigningIntentV1 {
    fn validate(&self) -> Result<(), String> {
        require_version(&self.contract_version)?;
        require_network(&self.network_id)?;
        require_token(&self.request_id, 128, "request_id")?;
        require_token(&self.intent_id, 128, "intent_id")?;
        require_hex(&self.issuer_workload_id, 64, "issuer_workload_id")?;
        require_hex(&self.audience_workload_id, 64, "audience_workload_id")?;
        if self.issuer_workload_id == self.audience_workload_id {
            return Err("issuer and audience must differ".into());
        }
        require_spiffe(&self.caller_spiffe_id)?;
        require_spiffe(&self.audience_spiffe_id)?;
        if self.caller_spiffe_id == self.audience_spiffe_id {
            return Err("caller and audience SPIFFE IDs must differ".into());
        }
        require_hex(&self.issuer_roster_hash, 64, "issuer_roster_hash")?;
        require_hex(&self.audience_roster_hash, 64, "audience_roster_hash")?;
        require_token(&self.wallet_id, 128, "wallet_id")?;
        require_nonblank(&self.destination, 256, "destination")?;
        require_hex(&self.psbt_sha256, 64, "psbt_sha256")?;
        require_hex(
            &self.change_descriptor_sha256,
            64,
            "change_descriptor_sha256",
        )?;
        require_hex(&self.policy_hash, 64, "policy_hash")?;
        require_positive_i64(self.policy_epoch, "policy_epoch")?;
        require_positive_i64(self.participant_epoch, "participant_epoch")?;
        require_positive_i64(self.amount_sats, "amount_sats")?;
        require_i64(self.max_fee_sats, "max_fee_sats")?;
        if self.max_fee_sats > self.amount_sats {
            return Err("max_fee_sats must not exceed amount_sats".into());
        }
        if self.max_fee_rate_sat_vb == 0 || self.max_fee_rate_sat_vb > 1_000_000 {
            return Err("max_fee_rate_sat_vb is outside the supported range".into());
        }
        if self.expected_input_count == 0 || self.expected_input_count > 10_000 {
            return Err("expected_input_count is outside the supported range".into());
        }
        require_hex(&self.authorization_hash, 64, "authorization_hash")?;
        require_hex(&self.nonce, 64, "nonce")?;
        require_positive_i64(self.sequence, "sequence")?;
        require_window(self.issued_at_epoch_ms, self.expires_at_epoch_ms)?;
        if self.expires_at_epoch_ms - self.issued_at_epoch_ms > 60_000 {
            return Err("signing intent lifetime exceeds 60 seconds".into());
        }
        require_hex(&self.signature, 128, "signature")
    }
}

impl SigningIntentV1 {
    /// Bind application authorization to both roster entries and, therefore,
    /// to the exact SPIFFE identities expected on the mTLS connection.
    pub fn validate_roster_binding(
        &self,
        issuer_roster: &SignedServiceRosterV1,
        audience_roster: &SignedServiceRosterV1,
    ) -> Result<(), String> {
        issuer_roster.validate()?;
        audience_roster.validate()?;
        if issuer_roster.network_id != self.network_id
            || audience_roster.network_id != self.network_id
        {
            return Err("signing intent roster network_id mismatch".into());
        }
        if issuer_roster.roster_hash != self.issuer_roster_hash
            || audience_roster.roster_hash != self.audience_roster_hash
        {
            return Err("signing intent roster hash mismatch".into());
        }
        let issuer = issuer_roster
            .members
            .iter()
            .find(|member| member.identity.workload_id == self.issuer_workload_id)
            .ok_or_else(|| "issuer workload is absent from issuer roster".to_string())?;
        let audience = audience_roster
            .members
            .iter()
            .find(|member| member.identity.workload_id == self.audience_workload_id)
            .ok_or_else(|| "audience workload is absent from audience roster".to_string())?;
        if issuer.identity.role != WorkloadRole::Kfe
            || audience.identity.role != WorkloadRole::Vault
        {
            return Err("signing intent requires a KFE issuer and Vault audience".into());
        }
        if issuer.identity.spiffe_id != self.caller_spiffe_id
            || audience.identity.spiffe_id != self.audience_spiffe_id
        {
            return Err("signing intent SPIFFE identity does not match roster".into());
        }
        if self.issued_at_epoch_ms < issuer_roster.valid_from_epoch_ms
            || self.expires_at_epoch_ms > issuer_roster.valid_until_epoch_ms
            || self.issued_at_epoch_ms < audience_roster.valid_from_epoch_ms
            || self.expires_at_epoch_ms > audience_roster.valid_until_epoch_ms
        {
            return Err("signing intent exceeds roster validity".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON — cross-language deterministic JSON
// ---------------------------------------------------------------------------

/// Return the canonical JSON bytes for a serde-serializable value.
///
/// Canonical JSON guarantees:
/// 1. Keys are sorted lexicographically at every nesting level.
/// 2. Output is compact (no whitespace).
/// 3. Integers are serialized as bare numbers.
///
/// These properties are verified by KAT test vectors shared between Rust and
/// Java so that both languages produce identical bytes for the same struct.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let raw = serde_json::to_value(value).unwrap_or(serde_json::Value::Null);
    sort_value(&raw).to_string().into_bytes()
}

/// Recursively sort all JSON object keys using a BTreeMap.
fn sort_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_value(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_value).collect())
        }
        other => other.clone(),
    }
}

/// SHA-256 hash of the canonical JSON bytes.
pub fn canonical_json_hash<T: Serialize>(value: &T) -> String {
    let bytes = canonical_json_bytes(value);
    hex::encode(Sha256::digest(&bytes))
}

// ---------------------------------------------------------------------------
// Binary canonical encoding (legacy — used for discovery signatures)
// ---------------------------------------------------------------------------

pub trait CanonicalSignable {
    fn signing_bytes(&self) -> Vec<u8>;
}

impl CanonicalSignable for GenesisTrustBundleV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(GENESIS_TRUST_BUNDLE_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        trust_plane(&mut out, &self.bank);
        trust_plane(&mut out, &self.vault);
        integer(&mut out, self.created_at_epoch_ms);
        out
    }
}

impl CanonicalSignable for PeerHelloV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(PEER_HELLO_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        field(&mut out, self.plane.as_str().as_bytes());
        field(&mut out, self.member_id.as_bytes());
        field(&mut out, self.root_public_key.as_bytes());
        field(&mut out, self.challenge.as_bytes());
        integer(&mut out, self.issued_at_epoch_ms);
        field(&mut out, self.endpoint.as_bytes());
        out
    }
}

impl CanonicalSignable for AdmissionRequestV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMISSION_REQUEST_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        field(&mut out, self.plane.as_str().as_bytes());
        field(&mut out, self.candidate.member_id.as_bytes());
        field(&mut out, self.candidate.root_public_key.as_bytes());
        field(&mut out, self.candidate.endpoint.as_bytes());
        field(&mut out, self.sponsor_id.as_bytes());
        field(&mut out, self.challenge.as_bytes());
        integer(&mut out, self.issued_at_epoch_ms);
        out
    }
}

impl CanonicalSignable for MembershipManifestV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(MEMBERSHIP_MANIFEST_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        field(&mut out, self.plane.as_str().as_bytes());
        integer(&mut out, self.epoch);
        field(
            &mut out,
            match self.phase {
                MembershipPhase::Stable => b"stable",
                MembershipPhase::Joint => b"joint",
            },
        );
        field(&mut out, self.previous_manifest_hash.as_bytes());
        integer(&mut out, u64::from(self.threshold));
        integer(&mut out, self.members.len() as u64);
        for member in &self.members {
            field(&mut out, member.member_id.as_bytes());
            field(&mut out, member.root_public_key.as_bytes());
            field(&mut out, member.endpoint.as_bytes());
        }
        match self.next_epoch {
            Some(epoch) => {
                field(&mut out, b"some");
                integer(&mut out, epoch);
            }
            None => field(&mut out, b"none"),
        }
        out
    }
}

impl CanonicalSignable for WorkloadIdentityV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(WORKLOAD_IDENTITY_DOMAIN);
        self.encode_fields(&mut out);
        out
    }
}

impl CanonicalSignable for SignedServiceRosterV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(SIGNED_SERVICE_ROSTER_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        field(&mut out, self.authority_plane.as_str().as_bytes());
        field(&mut out, self.authority_manifest_hash.as_bytes());
        integer(&mut out, self.epoch);
        field(&mut out, self.previous_roster_hash.as_bytes());
        integer(&mut out, self.valid_from_epoch_ms);
        integer(&mut out, self.valid_until_epoch_ms);
        integer(&mut out, self.members.len() as u64);
        for member in &self.members {
            member.identity.encode_fields(&mut out);
            field(&mut out, member.endpoint.as_bytes());
        }
        out
    }
}

impl CanonicalSignable for SigningIntentV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(SIGNING_INTENT_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.intent_id.as_bytes());
        field(&mut out, self.issuer_workload_id.as_bytes());
        field(&mut out, self.audience_workload_id.as_bytes());
        field(&mut out, self.caller_spiffe_id.as_bytes());
        field(&mut out, self.audience_spiffe_id.as_bytes());
        field(&mut out, self.issuer_roster_hash.as_bytes());
        field(&mut out, self.audience_roster_hash.as_bytes());
        field(&mut out, self.operation.as_str().as_bytes());
        field(&mut out, self.wallet_id.as_bytes());
        field(&mut out, self.bitcoin_network.as_str().as_bytes());
        field(&mut out, self.custody_bucket.as_str().as_bytes());
        field(&mut out, self.destination.as_bytes());
        field(&mut out, self.psbt_sha256.as_bytes());
        field(&mut out, self.change_descriptor_sha256.as_bytes());
        field(&mut out, self.policy_hash.as_bytes());
        integer(&mut out, self.policy_epoch);
        integer(&mut out, self.participant_epoch);
        integer(&mut out, self.amount_sats);
        integer(&mut out, self.max_fee_sats);
        integer(&mut out, self.max_fee_rate_sat_vb);
        integer(&mut out, u64::from(self.expected_input_count));
        field(&mut out, self.commit_mode.as_str().as_bytes());
        field(&mut out, self.authorization_hash.as_bytes());
        field(&mut out, self.nonce.as_bytes());
        integer(&mut out, self.sequence);
        integer(&mut out, self.issued_at_epoch_ms);
        integer(&mut out, self.expires_at_epoch_ms);
        out
    }
}

impl CanonicalSignable for NodeAdminStatusV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_NODE_STATUS_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.network_id.as_bytes());
        field(&mut out, self.plane.as_str().as_bytes());
        field(&mut out, if self.local_ready { b"true" } else { b"false" });
        field(&mut out, if self.member_ready { b"true" } else { b"false" });
        field(&mut out, if self.quorum_ready { b"true" } else { b"false" });
        field(
            &mut out,
            if self.financial_ready {
                b"true"
            } else {
                b"false"
            },
        );
        integer(&mut out, self.live_members);
        integer(&mut out, u64::from(self.threshold));
        out
    }
}

impl CanonicalSignable for VaultAdminStatusV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_VAULT_STATUS_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, if self.local_ready { b"true" } else { b"false" });
        field(
            &mut out,
            if self.financial_ready {
                b"true"
            } else {
                b"false"
            },
        );
        field(&mut out, self.node_id.as_bytes());
        field(&mut out, self.ceremony_mode.as_bytes());
        field(&mut out, self.bitcoin_network.as_bytes());
        out
    }
}

impl CanonicalSignable for AdminErrorEnvelopeV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_ERROR_ENVELOPE_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.code.as_bytes());
        field(&mut out, self.message.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        // Sign the canonical JSON of details for determinism
        let details_json: Vec<u8> = sort_value(&self.details).to_string().into_bytes();
        field(&mut out, &details_json);
        out
    }
}

impl CanonicalSignable for AuditReferenceV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_AUDIT_REFERENCE_DOMAIN);
        field(&mut out, self.event_id.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.occurred_at.as_bytes());
        out
    }
}

impl CanonicalSignable for LedgerAccountV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_CORE_LEDGER_ACCOUNT_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.account_id.as_bytes());
        field(&mut out, self.account_type.as_bytes());
        integer(&mut out, self.available_sats);
        integer(&mut out, self.reserved_sats);
        integer(&mut out, self.pending_incoming_sats);
        integer(&mut out, self.pending_outgoing_sats);
        integer(&mut out, self.confirmed_onchain_sats);
        integer(&mut out, self.unconfirmed_onchain_sats);
        integer(&mut out, self.spendable_by_kerosene_sats);
        integer(&mut out, self.state_version);
        field(&mut out, self.state_root.as_bytes());
        integer(&mut out, self.tags.len() as u64);
        for tag in &self.tags {
            field(&mut out, tag.as_bytes());
        }
        field(&mut out, self.created_at.as_bytes());
        field(&mut out, self.updated_at.as_bytes());
        out
    }
}

impl CanonicalSignable for LedgerJournalV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_CORE_LEDGER_JOURNAL_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.entry_id.as_bytes());
        field(&mut out, self.account_id.as_bytes());
        field(&mut out, self.direction.as_str().as_bytes());
        integer(&mut out, self.amount_sats);
        field(&mut out, self.description.as_bytes());
        field(&mut out, self.reference.as_bytes());
        field(&mut out, self.recorded_at.as_bytes());
        out
    }
}

impl CanonicalSignable for AdminP2PV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_P2P_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.channel_id.as_bytes());
        field(&mut out, self.remote_node_id.as_bytes());
        integer(&mut out, self.capacity_sats);
        integer(&mut out, self.local_balance_sats);
        integer(&mut out, self.remote_balance_sats);
        field(&mut out, if self.is_active { b"true" } else { b"false" });
        out
    }
}

impl CanonicalSignable for AdminOnrampV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_ONRAMP_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.order_id.as_bytes());
        field(&mut out, self.user_id.as_bytes());
        field(&mut out, self.fiat_currency.as_bytes());
        field(&mut out, self.fiat_amount.as_bytes());
        integer(&mut out, self.sats);
        field(&mut out, self.provider.as_bytes());
        field(&mut out, self.status.as_bytes());
        field(&mut out, self.created_at.as_bytes());
        out
    }
}

impl CanonicalSignable for AdminReconciliationV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_RECONCILIATION_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.reconciliation_id.as_bytes());
        integer(&mut out, self.ledger_sats);
        integer(&mut out, self.onchain_sats);
        integer(&mut out, self.lightning_sats);
        // i64 → canonical u64 encoding (two's complement)
        let delta = self.delta_sats as u64;
        integer(&mut out, delta);
        field(&mut out, self.status.as_bytes());
        field(&mut out, self.reconciled_at.as_bytes());
        out
    }
}

impl CanonicalSignable for AdminProviderV1 {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = domain(ADMIN_PROVIDER_DOMAIN);
        field(&mut out, self.contract_version.as_bytes());
        field(&mut out, self.request_id.as_bytes());
        field(&mut out, self.provider_id.as_bytes());
        field(&mut out, self.provider_type.as_bytes());
        field(&mut out, if self.is_online { b"true" } else { b"false" });
        field(&mut out, self.last_heartbeat.as_bytes());
        field(&mut out, self.version.as_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

pub fn member_id(network_id: &str, root_public_key: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(network_id.as_bytes());
    digest.update(root_public_key);
    hex::encode(digest.finalize())
}

pub fn canonical_hash<T: CanonicalSignable>(value: &T) -> String {
    hex::encode(Sha256::digest(value.signing_bytes()))
}

fn domain(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    field(&mut out, value);
    out
}

fn trust_plane(out: &mut Vec<u8>, plane: &TrustPlane) {
    integer(out, u64::from(plane.threshold));
    integer(out, plane.members.len() as u64);
    for member in &plane.members {
        field(out, member.member_id.as_bytes());
        field(out, member.root_public_key.as_bytes());
    }
}

fn integer(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    integer(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn require_version(value: &str) -> Result<(), String> {
    if value == SECURITY_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(format!(
            "contract_version must be {SECURITY_CONTRACT_VERSION}"
        ))
    }
}

fn require_network(value: &str) -> Result<(), String> {
    if !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_whitespace) {
        Ok(())
    } else {
        Err("invalid network_id".into())
    }
}

fn require_hex(value: &str, length: usize, field_name: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(format!("invalid {field_name}"))
    }
}

fn require_window(from: u64, until: u64) -> Result<(), String> {
    require_i64(from, "valid_from_epoch_ms")?;
    require_i64(until, "valid_until_epoch_ms")?;
    if until > from {
        Ok(())
    } else {
        Err("validity window must be non-empty and increasing".into())
    }
}

fn require_spiffe(value: &str) -> Result<(), String> {
    if value.len() > 512
        || !value.starts_with("spiffe://")
        || value.contains(char::is_whitespace)
        || value.contains('?')
        || value.contains('#')
    {
        return Err("invalid spiffe_id".into());
    }
    let rest = &value[9..];
    let Some((trust_domain, path)) = rest.split_once('/') else {
        return Err("invalid spiffe_id".into());
    };
    if trust_domain.is_empty()
        || path.is_empty()
        || trust_domain
            .bytes()
            .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'))
        || path.split('/').any(|segment| {
            segment.is_empty()
                || segment
                    .bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b"._~-".contains(&b)))
        })
    {
        return Err("invalid spiffe_id".into());
    }
    Ok(())
}

fn require_endpoint(value: &str) -> Result<(), String> {
    let Some(authority) = value.strip_prefix("https://") else {
        return Err("invalid service endpoint".into());
    };
    if value.len() > 272
        || authority.is_empty()
        || authority.contains('/')
        || authority.contains(char::is_whitespace)
        || authority.contains('@')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err("invalid service endpoint".into());
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || host.len() > 253
        || host.starts_with(['.', '-'])
        || host.ends_with(['.', '-'])
        || host.contains("..")
        || host
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    {
        return Err("invalid service endpoint".into());
    }
    if let Some(port) = port {
        let parsed = port
            .parse::<u16>()
            .map_err(|_| "invalid service endpoint")?;
        if parsed == 0 || port.starts_with('0') {
            return Err("invalid service endpoint".into());
        }
    }
    Ok(())
}

fn require_nonblank(value: &str, max: usize, field_name: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_whitespace) {
        Err(format!("invalid {field_name}"))
    } else {
        Ok(())
    }
}

fn require_sorted_unique<'a>(
    values: impl Iterator<Item = &'a str>,
    field_name: &str,
) -> Result<(), String> {
    let mut previous: Option<&str> = None;
    for value in values {
        if previous.is_some_and(|prior| prior >= value) {
            return Err(format!("{field_name} must be strictly sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn require_token(value: &str, max: usize, field_name: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || value
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b"._:-".contains(&b)))
    {
        Err(format!("invalid {field_name}"))
    } else {
        Ok(())
    }
}

fn require_instance(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || value
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b"._-".contains(&b)))
    {
        Err("invalid instance_id".into())
    } else {
        Ok(())
    }
}

fn require_i64(value: u64, field_name: &str) -> Result<(), String> {
    if value <= i64::MAX as u64 {
        Ok(())
    } else {
        Err(format!(
            "{field_name} exceeds cross-language signed 64-bit range"
        ))
    }
}

fn require_positive_i64(value: u64, field_name: &str) -> Result<(), String> {
    require_i64(value, field_name)?;
    if value == 0 {
        Err(format!("{field_name} must be positive"))
    } else {
        Ok(())
    }
}

/// Custom deserializer for `Option<u64>` that rejects `Some(0)`.
///
/// The JSON schema requires `next_epoch >= 1` when present. This enforces
/// that constraint at deserialization time to prevent invalid state from
/// entering the system through serde-parse boundaries.
fn deserialize_next_epoch<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct NextEpochVisitor;
    impl<'de> de::Visitor<'de> for NextEpochVisitor {
        type Value = Option<u64>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an integer >= 1, null, or absent field")
        }

        fn visit_none<E: de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_some<D: de::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Option<u64>, D::Error> {
            u64::deserialize(deserializer).and_then(|v| {
                if v == 0 {
                    Err(de::Error::custom("next_epoch must be >= 1 when present"))
                } else {
                    Ok(Some(v))
                }
            })
        }

        fn visit_unit<E: de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Option<u64>, E> {
            if value == 0 {
                Err(de::Error::custom("next_epoch must be >= 1 when present"))
            } else {
                Ok(Some(value))
            }
        }
    }
    deserializer.deserialize_option(NextEpochVisitor)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Legacy discovery tests (unchanged)
    // ------------------------------------------------------------------

    #[test]
    fn member_id_is_network_bound() {
        let key = [7_u8; 32];
        assert_ne!(member_id("testnet", &key), member_id("mainnet", &key));
        assert_eq!(member_id("testnet", &key).len(), 64);
    }

    #[test]
    fn signatures_do_not_change_manifest_hash() {
        let mut manifest = MembershipManifestV1 {
            contract_version: DISCOVERY_CONTRACT_VERSION.into(),
            network_id: "kerosene-test".into(),
            plane: DiscoveryPlane::Vault,
            epoch: 1,
            phase: MembershipPhase::Stable,
            previous_manifest_hash: "0".repeat(64),
            threshold: 2,
            members: vec![],
            next_epoch: None,
            signatures: vec![],
        };
        let unsigned = canonical_hash(&manifest);
        manifest.signatures.push(ManifestSignature {
            signer_id: "member-a".into(),
            signature: "1".repeat(128),
        });
        assert_eq!(unsigned, canonical_hash(&manifest));
    }

    #[test]
    fn canonical_bytes_are_not_ambiguous() {
        let mut left = PeerHelloV1 {
            contract_version: DISCOVERY_CONTRACT_VERSION.into(),
            network_id: "ab".into(),
            plane: DiscoveryPlane::Bank,
            member_id: "c".into(),
            root_public_key: "1".repeat(64),
            challenge: "2".repeat(64),
            issued_at_epoch_ms: 1,
            endpoint: "https://example.onion".into(),
            signature: String::new(),
        };
        let mut right = left.clone();
        right.network_id = "a".into();
        right.member_id = "bc".into();
        assert_ne!(left.signing_bytes(), right.signing_bytes());
        left.signature = "f".repeat(128);
        assert_eq!(left.signing_bytes(), {
            right.network_id = "ab".into();
            right.member_id = "c".into();
            right.signing_bytes()
        });
    }

    // ------------------------------------------------------------------
    // Admin unknown-field rejection tests
    // ------------------------------------------------------------------

    #[test]
    fn admin_node_status_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "request_id":"req-1",
            "network_id":"kerosene-test",
            "plane":"bank",
            "local_ready":true,
            "member_ready":true,
            "quorum_ready":false,
            "financial_ready":false,
            "live_members":1,
            "threshold":2,
            "secret":"must-not-pass"
        }"#;
        assert!(serde_json::from_str::<NodeAdminStatusV1>(payload).is_err());
    }

    #[test]
    fn admin_vault_status_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "request_id":"req-1",
            "local_ready":true,
            "financial_ready":true,
            "node_id":"node-1",
            "ceremony_mode":"production",
            "bitcoin_network":"mainnet",
            "unknown_field":"xyz"
        }"#;
        assert!(serde_json::from_str::<VaultAdminStatusV1>(payload).is_err());
    }

    #[test]
    fn admin_error_envelope_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "code":"ERR_TEST",
            "message":"test error",
            "request_id":"req-1",
            "details":{},
            "extra":"should-fail"
        }"#;
        assert!(serde_json::from_str::<AdminErrorEnvelopeV1>(payload).is_err());
    }

    #[test]
    fn admin_audit_reference_rejects_unknown_fields() {
        let payload = r#"{
            "event_id":"evt-1",
            "request_id":"req-1",
            "occurred_at":"2026-07-30T12:00:00Z",
            "bogus":null
        }"#;
        assert!(serde_json::from_str::<AuditReferenceV1>(payload).is_err());
    }

    // ------------------------------------------------------------------
    // Multi-saldo ledger tests
    // ------------------------------------------------------------------

    #[test]
    fn ledger_account_serde_roundtrip() {
        let account = LedgerAccountV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            account_id: "acc-123".into(),
            account_type: "checking".into(),
            available_sats: 800_000_000,
            reserved_sats: 100_000_000,
            pending_incoming_sats: 50_000_000,
            pending_outgoing_sats: 20_000_000,
            confirmed_onchain_sats: 500_000_000,
            unconfirmed_onchain_sats: 10_000_000,
            spendable_by_kerosene_sats: 700_000_000,
            state_version: 42,
            state_root: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".into(),
            tags: vec!["hot".into(), "operational".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-07-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&account).unwrap();
        let deserialized: LedgerAccountV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(account, deserialized);
    }

    #[test]
    fn ledger_account_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "account_id":"acc-1",
            "account_type":"savings",
            "available_sats":500000000,
            "reserved_sats":0,
            "pending_incoming_sats":0,
            "pending_outgoing_sats":0,
            "confirmed_onchain_sats":500000000,
            "unconfirmed_onchain_sats":0,
            "spendable_by_kerosene_sats":500000000,
            "state_version":1,
            "state_root":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "tags":[],
            "created_at":"2026-01-01T00:00:00Z",
            "updated_at":"2026-07-01T00:00:00Z",
            "unknown":"rejected"
        }"#;
        assert!(serde_json::from_str::<LedgerAccountV1>(payload).is_err());
    }

    #[test]
    fn ledger_account_has_no_legacy_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "account_id":"acc-1",
            "account_type":"savings",
            "balance":"500000",
            "currency":"BTC",
            "tags":[],
            "created_at":"2026-01-01T00:00:00Z",
            "updated_at":"2026-07-01T00:00:00Z"
        }"#;
        assert!(
            serde_json::from_str::<LedgerAccountV1>(payload).is_err(),
            "legacy balance/currency fields must be rejected"
        );
    }

    #[test]
    fn ledger_journal_serde_roundtrip() {
        let entry = LedgerJournalV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            entry_id: "entry-001".into(),
            account_id: "acc-123".into(),
            direction: JournalDirection::Debit,
            amount_sats: 50_000,
            description: "Initial deposit".into(),
            reference: "ref-tx-001".into(),
            recorded_at: "2026-07-30T12:00:00Z".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: LedgerJournalV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, deserialized);
    }

    #[test]
    fn ledger_journal_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "entry_id":"entry-1",
            "account_id":"acc-1",
            "direction":"debit",
            "amount_sats":100,
            "description":"test",
            "reference":"ref-1",
            "recorded_at":"2026-07-30T12:00:00Z",
            "invalid":"rejected"
        }"#;
        assert!(serde_json::from_str::<LedgerJournalV1>(payload).is_err());
    }

    #[test]
    fn ledger_journal_has_no_legacy_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "entry_id":"entry-1",
            "account_id":"acc-1",
            "direction":"debit",
            "amount":"100",
            "currency":"BTC",
            "description":"test",
            "reference":"ref-1",
            "recorded_at":"2026-07-30T12:00:00Z"
        }"#;
        assert!(
            serde_json::from_str::<LedgerJournalV1>(payload).is_err(),
            "legacy amount/currency fields must be rejected"
        );
    }

    #[test]
    fn journal_direction_serialization() {
        assert_eq!(
            serde_json::to_string(&JournalDirection::Debit).unwrap(),
            "\"debit\""
        );
        assert_eq!(
            serde_json::to_string(&JournalDirection::Credit).unwrap(),
            "\"credit\""
        );
    }

    // ------------------------------------------------------------------
    // Canonical JSON tests
    // ------------------------------------------------------------------

    #[test]
    fn canonical_json_is_deterministic() {
        let node = NodeAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-1".into(),
            network_id: "kerosene-test".into(),
            plane: DiscoveryPlane::Bank,
            local_ready: true,
            member_ready: false,
            quorum_ready: false,
            financial_ready: true,
            live_members: 3,
            threshold: 2,
        };
        let bytes1 = canonical_json_bytes(&node);
        let bytes2 = canonical_json_bytes(&node);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let node = NodeAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-1".into(),
            network_id: "kerosene-test".into(),
            plane: DiscoveryPlane::Bank,
            local_ready: true,
            member_ready: false,
            quorum_ready: false,
            financial_ready: true,
            live_members: 3,
            threshold: 2,
        };
        let json_str = String::from_utf8(canonical_json_bytes(&node)).unwrap();
        // Verify that "contract_version" appears before "financial_ready" (c < f)
        let cv_pos = json_str.find("\"contract_version\"").unwrap();
        let fr_pos = json_str.find("\"financial_ready\"").unwrap();
        assert!(
            cv_pos < fr_pos,
            "keys must be sorted: contract_version before financial_ready"
        );
    }

    #[test]
    fn canonical_json_hash_is_stable() {
        let node = NodeAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-canonical".into(),
            network_id: "kerosene-test".into(),
            plane: DiscoveryPlane::Vault,
            local_ready: true,
            member_ready: true,
            quorum_ready: true,
            financial_ready: false,
            live_members: 5,
            threshold: 3,
        };
        let hash1 = canonical_json_hash(&node);
        let hash2 = canonical_json_hash(&node);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn canonical_json_and_binary_hash_differ() {
        let node = NodeAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-dual".into(),
            network_id: "kerosene-test".into(),
            plane: DiscoveryPlane::Vault,
            local_ready: true,
            member_ready: true,
            quorum_ready: true,
            financial_ready: false,
            live_members: 5,
            threshold: 3,
        };
        let json_hash = canonical_json_hash(&node);
        let binary_hash = canonical_hash(&node);
        assert_ne!(
            json_hash, binary_hash,
            "canonical JSON and binary hashes must differ"
        );
    }

    // ------------------------------------------------------------------
    // Binary canonical hash stability tests
    // ------------------------------------------------------------------

    #[test]
    fn admin_canonical_hash_is_stable() {
        let node = NodeAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-canonical".into(),
            network_id: "kerosene-test".into(),
            plane: DiscoveryPlane::Vault,
            local_ready: true,
            member_ready: true,
            quorum_ready: true,
            financial_ready: false,
            live_members: 5,
            threshold: 3,
        };
        let hash1 = canonical_hash(&node);
        let hash2 = canonical_hash(&node);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn vault_admin_canonical_hash() {
        let vault = VaultAdminStatusV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-vault".into(),
            local_ready: true,
            financial_ready: true,
            node_id: "vault-node-1".into(),
            ceremony_mode: "production".into(),
            bitcoin_network: "mainnet".into(),
        };
        let hash = canonical_hash(&vault);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn ledger_journal_canonical_hash() {
        let entry = LedgerJournalV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            entry_id: "entry-canon".into(),
            account_id: "acc-456".into(),
            direction: JournalDirection::Credit,
            amount_sats: 250_000,
            description: "Settlement".into(),
            reference: "ref-settle-001".into(),
            recorded_at: "2026-07-29T18:30:00Z".into(),
        };
        let hash = canonical_hash(&entry);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn ledger_account_canonical_hash() {
        let account = LedgerAccountV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            account_id: "acc-hash-001".into(),
            account_type: "checking".into(),
            available_sats: 800_000_000,
            reserved_sats: 100_000_000,
            pending_incoming_sats: 50_000_000,
            pending_outgoing_sats: 20_000_000,
            confirmed_onchain_sats: 500_000_000,
            unconfirmed_onchain_sats: 10_000_000,
            spendable_by_kerosene_sats: 700_000_000,
            state_version: 42,
            state_root: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".into(),
            tags: vec!["hot".into(), "operational".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-07-01T00:00:00Z".into(),
        };
        let hash = canonical_hash(&account);
        assert_eq!(hash.len(), 64);
    }

    // ------------------------------------------------------------------
    // Missing contract serialization tests
    // ------------------------------------------------------------------

    #[test]
    fn admin_p2p_serde_roundtrip() {
        let p2p = AdminP2PV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-p2p-001".into(),
            channel_id: "chan-001".into(),
            remote_node_id: "node-9876".into(),
            capacity_sats: 10_000_000,
            local_balance_sats: 6_000_000,
            remote_balance_sats: 4_000_000,
            is_active: true,
        };
        let json = serde_json::to_string(&p2p).unwrap();
        let deserialized: AdminP2PV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(p2p, deserialized);
    }

    #[test]
    fn admin_onramp_serde_roundtrip() {
        let onramp = AdminOnrampV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-onramp-001".into(),
            order_id: "order-abc".into(),
            user_id: "user-xyz".into(),
            fiat_currency: "USD".into(),
            fiat_amount: "100.00".into(),
            sats: 1_000_000,
            provider: "stripe".into(),
            status: "completed".into(),
            created_at: "2026-07-30T12:00:00Z".into(),
        };
        let json = serde_json::to_string(&onramp).unwrap();
        let deserialized: AdminOnrampV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(onramp, deserialized);
    }

    #[test]
    fn admin_reconciliation_serde_roundtrip() {
        let rec = AdminReconciliationV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-rec-001".into(),
            reconciliation_id: "rec-001".into(),
            ledger_sats: 1_000_000_000,
            onchain_sats: 999_800_000,
            lightning_sats: 200_000,
            delta_sats: -200_000,
            status: "settled".into(),
            reconciled_at: "2026-07-30T12:00:00Z".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let deserialized: AdminReconciliationV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, deserialized);
    }

    #[test]
    fn admin_provider_serde_roundtrip() {
        let prov = AdminProviderV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            request_id: "req-prov-001".into(),
            provider_id: "lnd-mainnet".into(),
            provider_type: "lightning".into(),
            is_online: true,
            last_heartbeat: "2026-07-30T12:00:00Z".into(),
            version: "0.18.3".into(),
        };
        let json = serde_json::to_string(&prov).unwrap();
        let deserialized: AdminProviderV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(prov, deserialized);
    }

    #[test]
    fn admin_p2p_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "request_id":"req-1",
            "channel_id":"chan-1",
            "remote_node_id":"node-1",
            "capacity_sats":10000000,
            "local_balance_sats":6000000,
            "remote_balance_sats":4000000,
            "is_active":true,
            "bogus":true
        }"#;
        assert!(serde_json::from_str::<AdminP2PV1>(payload).is_err());
    }

    #[test]
    fn admin_onramp_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "request_id":"req-1",
            "order_id":"order-1",
            "user_id":"user-1",
            "fiat_currency":"USD",
            "fiat_amount":"100.00",
            "sats":1000000,
            "provider":"stripe",
            "status":"pending",
            "created_at":"2026-07-30T12:00:00Z",
            "extra":"nope"
        }"#;
        assert!(serde_json::from_str::<AdminOnrampV1>(payload).is_err());
    }

    #[test]
    fn admin_reconciliation_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "request_id":"req-1",
            "reconciliation_id":"rec-1",
            "ledger_sats":1000000000,
            "onchain_sats":999800000,
            "lightning_sats":200000,
            "delta_sats":-200000,
            "status":"settled",
            "reconciled_at":"2026-07-30T12:00:00Z",
            "unknown":"reject"
        }"#;
        assert!(serde_json::from_str::<AdminReconciliationV1>(payload).is_err());
    }

    #[test]
    fn admin_provider_rejects_unknown_fields() {
        let payload = r#"{
            "contract_version":"0.1.0",
            "request_id":"req-1",
            "provider_id":"lnd-mainnet",
            "provider_type":"lightning",
            "is_online":true,
            "last_heartbeat":"2026-07-30T12:00:00Z",
            "version":"0.18.3",
            "invalid":"reject"
        }"#;
        assert!(serde_json::from_str::<AdminProviderV1>(payload).is_err());
    }

    // ------------------------------------------------------------------
    // KAT — Known Answer Tests (cross-language with Java)
    // ------------------------------------------------------------------
    //
    // These tests load {name}.json test vectors from the test-vectors/
    // directory and verify that canonical JSON bytes and binary signing
    // bytes produce the expected SHA-256 hashes.
    //
    // Java tests in AdminContractsCanonicalJsonTest.java verify the same
    // vectors produce identical hashes.

    fn load_json(path: &str) -> serde_json::Value {
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read test vector {path}: {e}"));
        serde_json::from_str(&content).unwrap()
    }

    fn hex_hash(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    /// Strip test-vector metadata fields before deserializing into a contract.
    fn strip_vector_meta(mut json: serde_json::Value) -> serde_json::Value {
        if let Some(obj) = json.as_object_mut() {
            obj.remove("vector_label");
            obj.remove("expected_json_hash");
            obj.remove("expected_binary_hash");
        }
        json
    }

    /// Run KAT: deserialize from JSON, re-serialize to canonical JSON,
    /// and verify the SHA-256 matches `expected_json_hash`.
    fn kat_canonical_json<T>(json: &serde_json::Value, expected_hash: &str)
    where
        T: serde::de::DeserializeOwned + Serialize + std::fmt::Debug,
    {
        let stripped = strip_vector_meta(json.clone());
        let obj: T = serde_json::from_value(stripped)
            .unwrap_or_else(|e| panic!("KAT deserialize failed: {e}"));
        let canonical = canonical_json_bytes(&obj);
        let actual = hex_hash(&canonical);
        assert_eq!(
            actual,
            expected_hash,
            "KAT canonical JSON hash mismatch for {}",
            std::any::type_name::<T>(),
        );
    }

    /// Run KAT: deserialize from JSON, compute binary signing bytes,
    /// and verify the SHA-256 matches `expected_binary_hash`.
    fn kat_binary_signable<T>(json: &serde_json::Value, expected_hash: &str)
    where
        T: serde::de::DeserializeOwned + CanonicalSignable + std::fmt::Debug,
    {
        let stripped = strip_vector_meta(json.clone());
        let obj: T = serde_json::from_value(stripped)
            .unwrap_or_else(|e| panic!("KAT deserialize failed: {e}"));
        let actual = canonical_hash(&obj);
        assert_eq!(
            actual,
            expected_hash,
            "KAT binary hash mismatch for {}",
            std::any::type_name::<T>(),
        );
    }

    /// Path to test vector JSON files.
    fn vectors_dir() -> String {
        // When tests run from workspace root or crate root
        let candidates: Vec<&str> = vec![
            "../../test-vectors",
            "../test-vectors",
            "test-vectors",
            "../test-vectors",
        ];
        for c in &candidates {
            if std::path::Path::new(c).exists() {
                return c.to_string();
            }
        }
        panic!("cannot find test-vectors directory (tried: {candidates:?})");
    }

    macro_rules! kat_test {
        ($name:ident, $ty:ty, $fname:expr, $hash_field:expr) => {
            #[test]
            fn $name() {
                let dir = vectors_dir();
                let path = std::path::Path::new(&dir).join($fname);
                let json = load_json(path.to_str().unwrap());
                let expected = json[$hash_field]
                    .as_str()
                    .unwrap_or_else(|| panic!("test vector {} missing hash", $fname))
                    .to_string();
                kat_canonical_json::<$ty>(&json, &expected);
            }
        };
    }

    macro_rules! kat_binary_test {
        ($name:ident, $ty:ty, $fname:expr, $hash_field:expr) => {
            #[test]
            fn $name() {
                let dir = vectors_dir();
                let path = std::path::Path::new(&dir).join($fname);
                let json = load_json(path.to_str().unwrap());
                let expected = json[$hash_field]
                    .as_str()
                    .unwrap_or_else(|| panic!("test vector {} missing hash", $fname))
                    .to_string();
                kat_binary_signable::<$ty>(&json, &expected);
            }
        };
    }

    // Canonical JSON KATs (every struct with a test vector)
    kat_test!(
        kat_json_node_admin_status,
        NodeAdminStatusV1,
        "node-admin-status-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_vault_admin_status,
        VaultAdminStatusV1,
        "vault-admin-status-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_admin_error_envelope,
        AdminErrorEnvelopeV1,
        "admin-error-envelope-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_audit_reference,
        AuditReferenceV1,
        "audit-reference-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_ledger_account,
        LedgerAccountV1,
        "ledger-account-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_ledger_journal,
        LedgerJournalV1,
        "ledger-journal-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_admin_p2p,
        AdminP2PV1,
        "admin-p2p-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_admin_onramp,
        AdminOnrampV1,
        "admin-onramp-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_admin_reconciliation,
        AdminReconciliationV1,
        "admin-reconciliation-v1.json",
        "expected_json_hash"
    );
    kat_test!(
        kat_json_admin_provider,
        AdminProviderV1,
        "admin-provider-v1.json",
        "expected_json_hash"
    );

    // Binary signing-bytes KATs
    kat_binary_test!(
        kat_binary_node_admin_status,
        NodeAdminStatusV1,
        "node-admin-status-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_vault_admin_status,
        VaultAdminStatusV1,
        "vault-admin-status-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_admin_error_envelope,
        AdminErrorEnvelopeV1,
        "admin-error-envelope-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_audit_reference,
        AuditReferenceV1,
        "audit-reference-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_ledger_account,
        LedgerAccountV1,
        "ledger-account-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_ledger_journal,
        LedgerJournalV1,
        "ledger-journal-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_admin_p2p,
        AdminP2PV1,
        "admin-p2p-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_admin_onramp,
        AdminOnrampV1,
        "admin-onramp-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_admin_reconciliation,
        AdminReconciliationV1,
        "admin-reconciliation-v1.json",
        "expected_binary_hash"
    );
    kat_binary_test!(
        kat_binary_admin_provider,
        AdminProviderV1,
        "admin-provider-v1.json",
        "expected_binary_hash"
    );

    // ------------------------------------------------------------------
    // Security v1 cross-language KATs and fail-closed semantics
    // ------------------------------------------------------------------

    fn security_vector(file: &str) -> serde_json::Value {
        let path = std::path::Path::new(&vectors_dir())
            .join("security")
            .join(file);
        load_json(path.to_str().unwrap())
    }

    fn security_contract<T: serde::de::DeserializeOwned>(file: &str) -> (T, String) {
        let vector = security_vector(file);
        let contract = serde_json::from_value(vector["contract"].clone())
            .unwrap_or_else(|error| panic!("security KAT deserialize failed for {file}: {error}"));
        let expected = vector["expected_signing_hash"]
            .as_str()
            .unwrap_or_else(|| panic!("security KAT {file} is missing expected_signing_hash"))
            .to_string();
        (contract, expected)
    }

    #[test]
    fn security_workload_identity_kats_match_java() {
        for file in [
            "workload-identity-kfe-v1.kat.json",
            "workload-identity-vault-v1.kat.json",
        ] {
            let (identity, expected): (WorkloadIdentityV1, String) = security_contract(file);
            identity.validate().unwrap();
            assert_eq!(canonical_hash(&identity), expected);
            assert_eq!(
                identity.workload_id,
                WorkloadIdentityV1::derive_workload_id(
                    &identity.network_id,
                    &identity.spiffe_id,
                    identity.role,
                    &identity.instance_id,
                    &identity.ed25519_public_key,
                )
            );
        }
    }

    #[test]
    fn security_roster_kats_match_java_and_external_authority() {
        for file in [
            "signed-service-roster-bank-v1.kat.json",
            "signed-service-roster-vault-v1.kat.json",
        ] {
            let (mut roster, expected): (SignedServiceRosterV1, String) = security_contract(file);
            roster.validate().unwrap();
            assert_eq!(canonical_hash(&roster), expected);
            assert_eq!(roster.roster_hash, expected);

            let authority = MembershipManifestV1 {
                contract_version: DISCOVERY_CONTRACT_VERSION.into(),
                network_id: roster.network_id.clone(),
                plane: roster.authority_plane,
                epoch: 1,
                phase: MembershipPhase::Stable,
                previous_manifest_hash: "0".repeat(64),
                threshold: 1,
                members: vec![ManifestMember {
                    member_id: roster.signatures[0].signer_member_id.clone(),
                    root_public_key:
                        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
                    endpoint:
                        "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
                            .into(),
                }],
                next_epoch: None,
                signatures: vec![],
            };
            roster.authority_manifest_hash = canonical_hash(&authority);
            roster.roster_hash = roster.computed_roster_hash();
            roster.validate().unwrap();
            roster.validate_authority(&authority).unwrap();

            roster.signatures[0].signer_member_id = "f".repeat(64);
            assert!(roster.validate_authority(&authority).is_err());
        }
    }

    #[test]
    fn security_roster_rejects_noncanonical_member_order() {
        let (mut bank, _): (SignedServiceRosterV1, String) =
            security_contract("signed-service-roster-bank-v1.kat.json");
        let (vault, _): (SignedServiceRosterV1, String) =
            security_contract("signed-service-roster-vault-v1.kat.json");
        bank.members = vec![vault.members[0].clone(), bank.members[0].clone()];
        bank.roster_hash = bank.computed_roster_hash();
        assert!(bank.validate().unwrap_err().contains("strictly sorted"));
    }

    #[test]
    fn security_roster_successor_rejects_rollback_and_forks() {
        let (previous, _): (SignedServiceRosterV1, String) =
            security_contract("signed-service-roster-bank-v1.kat.json");
        let mut successor = previous.clone();
        successor.epoch = 2;
        successor.previous_roster_hash = previous.roster_hash.clone();
        successor.roster_hash = successor.computed_roster_hash();
        successor.validate_successor(&previous).unwrap();

        successor.epoch = 3;
        successor.roster_hash = successor.computed_roster_hash();
        assert!(successor.validate_successor(&previous).is_err());
        successor.epoch = 2;
        successor.previous_roster_hash = "f".repeat(64);
        successor.roster_hash = successor.computed_roster_hash();
        assert!(successor.validate_successor(&previous).is_err());
    }

    #[test]
    fn security_signing_intent_kat_binds_kfe_to_vault_rosters() {
        let (bank, _): (SignedServiceRosterV1, String) =
            security_contract("signed-service-roster-bank-v1.kat.json");
        let (vault, _): (SignedServiceRosterV1, String) =
            security_contract("signed-service-roster-vault-v1.kat.json");
        let (mut intent, expected): (SigningIntentV1, String) =
            security_contract("signing-intent-v1.kat.json");
        intent.validate().unwrap();
        assert_eq!(canonical_hash(&intent), expected);
        intent.validate_roster_binding(&bank, &vault).unwrap();

        intent.caller_spiffe_id = "spiffe://staging.kerosene/service/kfe/instance/attacker".into();
        assert_ne!(canonical_hash(&intent), expected);
        assert!(intent.validate_roster_binding(&bank, &vault).is_err());
    }

    #[test]
    fn security_contracts_reject_removed_or_unsafe_fields() {
        let mut identity = security_vector("workload-identity-kfe-v1.kat.json")["contract"].clone();
        identity["certificate_sha256"] = serde_json::Value::String("0".repeat(64));
        assert!(serde_json::from_value::<WorkloadIdentityV1>(identity).is_err());

        let (mut intent, _): (SigningIntentV1, String) =
            security_contract("signing-intent-v1.kat.json");
        intent.expires_at_epoch_ms = intent.issued_at_epoch_ms + 60_001;
        assert!(intent.validate().unwrap_err().contains("60 seconds"));
        intent.expires_at_epoch_ms = intent.issued_at_epoch_ms + 30_000;
        intent.sequence = 0;
        assert!(intent.validate().unwrap_err().contains("sequence"));
    }
}
