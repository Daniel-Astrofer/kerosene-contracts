//! Canonical Kerosene discovery, membership, and admin wire contracts.
//!
//! Signatures are always calculated over [`CanonicalSignable::signing_bytes`],
//! never over an arbitrary JSON serialization.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DISCOVERY_CONTRACT_VERSION: &str = "0.2.0";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminErrorEnvelopeV1 {
    pub contract_version: String,
    pub code: String,
    pub message: String,
    pub request_id: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReferenceV1 {
    pub event_id: String,
    pub request_id: String,
    pub occurred_at: String,
}

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

/// Admin/core: ledger account for financial read operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerAccountV1 {
    pub contract_version: String,
    pub account_id: String,
    pub account_type: String,
    pub balance: String,
    pub currency: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Admin/core: ledger journal entry for financial reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerJournalV1 {
    pub contract_version: String,
    pub entry_id: String,
    pub account_id: String,
    pub direction: JournalDirection,
    pub amount: String,
    pub currency: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub next_epoch: Option<u64>,
    pub signatures: Vec<ManifestSignature>,
}

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
        field(&mut out, if self.financial_ready { b"true" } else { b"false" });
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
        field(&mut out, if self.financial_ready { b"true" } else { b"false" });
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
        let details_json = serde_json::to_string(&self.details)
            .unwrap_or_default();
        field(&mut out, details_json.as_bytes());
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
        field(&mut out, self.balance.as_bytes());
        field(&mut out, self.currency.as_bytes());
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
        field(&mut out, self.amount.as_bytes());
        field(&mut out, self.currency.as_bytes());
        field(&mut out, self.description.as_bytes());
        field(&mut out, self.reference.as_bytes());
        field(&mut out, self.recorded_at.as_bytes());
        out
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn ledger_account_serde_roundtrip() {
        let account = LedgerAccountV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            account_id: "acc-123".into(),
            account_type: "checking".into(),
            balance: "1000000".into(),
            currency: "BTC".into(),
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
            "balance":"500000",
            "currency":"BTC",
            "tags":[],
            "created_at":"2026-01-01T00:00:00Z",
            "updated_at":"2026-07-01T00:00:00Z",
            "unknown":"rejected"
        }"#;
        assert!(serde_json::from_str::<LedgerAccountV1>(payload).is_err());
    }

    #[test]
    fn ledger_journal_serde_roundtrip() {
        let entry = LedgerJournalV1 {
            contract_version: ADMIN_CONTRACT_VERSION.into(),
            entry_id: "entry-001".into(),
            account_id: "acc-123".into(),
            direction: JournalDirection::Debit,
            amount: "50000".into(),
            currency: "BTC".into(),
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
            "amount":"100",
            "currency":"BTC",
            "description":"test",
            "reference":"ref-1",
            "recorded_at":"2026-07-30T12:00:00Z",
            "invalid":"rejected"
        }"#;
        assert!(serde_json::from_str::<LedgerJournalV1>(payload).is_err());
    }

    #[test]
    fn journal_direction_serialization() {
        assert_eq!(serde_json::to_string(&JournalDirection::Debit).unwrap(), "\"debit\"");
        assert_eq!(serde_json::to_string(&JournalDirection::Credit).unwrap(), "\"credit\"");
    }

    #[test]
    fn admin_json_output_is_deterministic() {
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
        let json1 = serde_json::to_string(&node).unwrap();
        let json2 = serde_json::to_string(&node).unwrap();
        assert_eq!(json1, json2);
    }

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
            amount: "250000".into(),
            currency: "BTC".into(),
            description: "Settlement".into(),
            reference: "ref-settle-001".into(),
            recorded_at: "2026-07-29T18:30:00Z".into(),
        };
        let hash = canonical_hash(&entry);
        assert_eq!(hash.len(), 64);
    }
}
