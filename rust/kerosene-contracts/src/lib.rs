//! Canonical Kerosene discovery and membership wire contracts.
//!
//! Signatures are always calculated over [`CanonicalSignable::signing_bytes`],
//! never over an arbitrary JSON serialization.

use serde::{de, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const DISCOVERY_CONTRACT_VERSION: &str = "0.2.0";
pub const PEER_HELLO_DOMAIN: &[u8] = b"KEROSENE_PEER_HELLO_V1";
pub const ADMISSION_REQUEST_DOMAIN: &[u8] = b"KEROSENE_ADMISSION_REQUEST_V1";
pub const MEMBERSHIP_MANIFEST_DOMAIN: &[u8] = b"KEROSENE_MEMBERSHIP_MANIFEST_V1";
pub const GENESIS_TRUST_BUNDLE_DOMAIN: &[u8] = b"KEROSENE_GENESIS_TRUST_BUNDLE_V1";

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
    /// A value of `Some(0)` is invalid (schema minimum is 1) and will fail
    /// deserialization with a clear error message.
    #[serde(default, deserialize_with = "deserialize_next_epoch")]
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

/// Custom deserializer for `Option<u64>` that rejects `Some(0)`.
///
/// The JSON schema requires `next_epoch >= 1` when present. This enforces
/// that constraint at deserialization time to prevent invalid state from
/// entering the system through serde-parse boundaries.
fn deserialize_next_epoch<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: de::Deserializer<'de>,
{
    // serde passes a "missing" unit-like value when the field is absent.
    // We must detect that and return None instead of failing.
    struct NextEpochVisitor;
    impl<'de> de::Visitor<'de> for NextEpochVisitor {
        type Value = Option<u64>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an integer >= 1, null, or absent field")
        }

        fn visit_none<E: de::Error>(self) -> Result<Option<u64>, E> {
            Ok(None)
        }

        fn visit_some<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Option<u64>, D::Error> {
            // When the option is Some(...), deserialize the inner value as u64
            u64::deserialize(deserializer).and_then(|v| {
                if v == 0 {
                    Err(de::Error::custom(
                        "next_epoch must be >= 1 when present",
                    ))
                } else {
                    Ok(Some(v))
                }
            })
        }

        fn visit_unit<E: de::Error>(self) -> Result<Option<u64>, E> {
            // This is called when the field is absent (serde passes unit for
            // optional fields that use deserialize_with).
            Ok(None)
        }

        fn visit_u64<E: de::Error>(self, value: u64) -> Result<Option<u64>, E> {
            if value == 0 {
                Err(de::Error::custom(
                    "next_epoch must be >= 1 when present",
                ))
            } else {
                Ok(Some(value))
            }
        }
    }
    deserializer.deserialize_option(NextEpochVisitor)
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
    fn next_epoch_rejects_zero() {
        let json = format!(
            r#"{{"contract_version":"0.2.0","network_id":"test","plane":"vault","epoch":1,"phase":"stable","previous_manifest_hash":"{}","threshold":2,"members":[],"next_epoch":0,"signatures":[]}}"#,
            "0".repeat(64)
        );
        let result: Result<MembershipManifestV1, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "next_epoch: Some(0) must be rejected");
        assert!(
            result.unwrap_err().to_string().contains("next_epoch must be >= 1"),
            "error message must mention the schema constraint"
        );
    }

    #[test]
    fn next_epoch_accepts_valid() {
        let json = format!(
            r#"{{"contract_version":"0.2.0","network_id":"test","plane":"vault","epoch":1,"phase":"stable","previous_manifest_hash":"{}","threshold":2,"members":[],"next_epoch":5,"signatures":[]}}"#,
            "0".repeat(64)
        );
        let result: Result<MembershipManifestV1, _> = serde_json::from_str(&json);
        assert!(result.is_ok(), "next_epoch: Some(5) must be accepted");
        assert_eq!(result.unwrap().next_epoch, Some(5));
    }

    #[test]
    fn next_epoch_accepts_none() {
        let json = format!(
            r#"{{"contract_version":"0.2.0","network_id":"test","plane":"vault","epoch":1,"phase":"stable","previous_manifest_hash":"{}","threshold":2,"members":[],"signatures":[]}}"#,
            "0".repeat(64)
        );
        let result: Result<MembershipManifestV1, _> = serde_json::from_str(&json);
        assert!(result.is_ok(), "next_epoch: None must be accepted");
        assert_eq!(result.unwrap().next_epoch, None);
    }
}
