package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;
import java.util.Set;

/**
 * Signed routing roster authorized by an already trusted stable discovery
 * manifest. Signatures never authorize their own signer set.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record SignedServiceRosterV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("network_id") String networkId,
        @JsonProperty("authority_plane") AuthorityPlane authorityPlane,
        @JsonProperty("authority_manifest_hash") String authorityManifestHash,
        @JsonProperty("roster_hash") String rosterHash,
        long epoch,
        @JsonProperty("previous_roster_hash") String previousRosterHash,
        @JsonProperty("valid_from_epoch_ms") long validFromEpochMs,
        @JsonProperty("valid_until_epoch_ms") long validUntilEpochMs,
        List<ServiceRosterMemberV1> members,
        List<RosterSignatureV1> signatures) implements CanonicalSignable {

    private static final String ZERO_HASH = "0".repeat(64);

    public SignedServiceRosterV1 {
        SecurityContract.requireVersion(contractVersion);
        SecurityContract.requireNetwork(networkId);
        SecurityContract.require(authorityPlane != null, "authority_plane is required");
        SecurityContract.requireHex32(authorityManifestHash, "authority_manifest_hash");
        SecurityContract.requireHex32(rosterHash, "roster_hash");
        SecurityContract.require(epoch > 0, "epoch must be positive");
        SecurityContract.requireHex32(previousRosterHash, "previous_roster_hash");
        SecurityContract.require((epoch == 1) == ZERO_HASH.equals(previousRosterHash),
                "only epoch 1 may use a zero previous_roster_hash");
        SecurityContract.requireWindow(validFromEpochMs, validUntilEpochMs);
        members = List.copyOf(members);
        signatures = List.copyOf(signatures);
        SecurityContract.require(!members.isEmpty(), "members must not be empty");
        SecurityContract.require(!signatures.isEmpty(), "signatures must not be empty");
        SecurityContract.requireSortedUnique(members,
                member -> member.identity().workloadId(), "members");
        SecurityContract.requireSortedUnique(signatures,
                RosterSignatureV1::signerMemberId, "signatures");
        for (var member : members) {
            SecurityContract.require(networkId.equals(member.identity().networkId()),
                    "member network_id mismatch");
            SecurityContract.require(member.identity().validFromEpochMs() <= validFromEpochMs
                    && member.identity().validUntilEpochMs() >= validUntilEpochMs,
                    "roster exceeds member validity");
        }
        SecurityContract.require(rosterHash.equals(computeRosterHash(contractVersion, networkId,
                authorityPlane, authorityManifestHash, epoch, previousRosterHash,
                validFromEpochMs, validUntilEpochMs, members)),
                "roster_hash does not match canonical unsigned roster");
    }

    /**
     * Validate signer membership and quorum against trusted bootstrap state.
     * Callers must additionally verify every Ed25519 signature using the
     * corresponding root key from that trusted manifest.
     */
    public void validateAuthority(String trustedNetworkId, AuthorityPlane trustedPlane,
                                  String trustedManifestHash, int trustedThreshold,
                                  Set<String> trustedMemberIds) {
        SecurityContract.require(networkId.equals(trustedNetworkId), "authority network_id mismatch");
        SecurityContract.require(authorityPlane == trustedPlane, "authority plane mismatch");
        SecurityContract.require(authorityManifestHash.equals(trustedManifestHash),
                "authority_manifest_hash mismatch");
        SecurityContract.require(trustedThreshold > 0 && trustedThreshold <= trustedMemberIds.size(),
                "invalid authority threshold");
        SecurityContract.require(signatures.size() >= trustedThreshold,
                "service roster does not meet authority threshold");
        for (var signature : signatures) {
            SecurityContract.require(trustedMemberIds.contains(signature.signerMemberId()),
                    "service roster contains a signer outside the authority manifest");
        }
    }

    /** Reject rollback, skipped epochs and forks from a trusted roster head. */
    public void validateSuccessor(SignedServiceRosterV1 previous) {
        SecurityContract.require(networkId.equals(previous.networkId)
                        && authorityPlane == previous.authorityPlane,
                "service roster successor changed network_id or authority plane");
        SecurityContract.require(previous.epoch < Long.MAX_VALUE && epoch == previous.epoch + 1,
                "service roster successor must advance exactly one epoch");
        SecurityContract.require(previousRosterHash.equals(previous.rosterHash),
                "service roster successor does not reference the trusted roster head");
    }

    public static String computeRosterHash(String version, String networkId,
                                           AuthorityPlane authorityPlane, String authorityManifestHash,
                                           long epoch, String previousHash, long validFrom, long validUntil,
                                           List<ServiceRosterMemberV1> members) {
        return SecurityContract.sha256Hex(unsignedBytes(version, networkId, authorityPlane,
                authorityManifestHash, epoch, previousHash, validFrom, validUntil, members));
    }

    @Override public byte[] signingBytes() {
        return unsignedBytes(contractVersion, networkId, authorityPlane, authorityManifestHash,
                epoch, previousRosterHash, validFromEpochMs, validUntilEpochMs, members);
    }

    private static byte[] unsignedBytes(String version, String networkId,
                                        AuthorityPlane authorityPlane, String authorityManifestHash,
                                        long epoch, String previousHash, long validFrom, long validUntil,
                                        List<ServiceRosterMemberV1> members) {
        return SecurityContract.transcript(SecurityContract.SERVICE_ROSTER_DOMAIN, out -> {
            SecurityContract.field(out, version);
            SecurityContract.field(out, networkId);
            SecurityContract.field(out, authorityPlane.wireValue());
            SecurityContract.field(out, authorityManifestHash);
            SecurityContract.integer(out, epoch);
            SecurityContract.field(out, previousHash);
            SecurityContract.integer(out, validFrom);
            SecurityContract.integer(out, validUntil);
            SecurityContract.integer(out, members.size());
            for (var member : members) {
                member.identity().encodeFields(out);
                SecurityContract.field(out, member.endpoint());
            }
        });
    }
}
