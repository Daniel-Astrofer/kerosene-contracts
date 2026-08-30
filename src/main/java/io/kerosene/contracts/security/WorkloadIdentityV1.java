package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record WorkloadIdentityV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("network_id") String networkId,
        @JsonProperty("workload_id") String workloadId,
        @JsonProperty("spiffe_id") String spiffeId,
        WorkloadRole role,
        @JsonProperty("instance_id") String instanceId,
        @JsonProperty("ed25519_public_key") String ed25519PublicKey,
        @JsonProperty("valid_from_epoch_ms") long validFromEpochMs,
        @JsonProperty("valid_until_epoch_ms") long validUntilEpochMs) implements CanonicalSignable {

    public WorkloadIdentityV1 {
        SecurityContract.requireVersion(contractVersion);
        SecurityContract.requireNetwork(networkId);
        SecurityContract.requireHex32(workloadId, "workload_id");
        SecurityContract.requireSpiffeId(spiffeId);
        SecurityContract.require(role != null, "role is required");
        SecurityContract.requireInstance(instanceId);
        SecurityContract.requireHex32(ed25519PublicKey, "ed25519_public_key");
        SecurityContract.requireWindow(validFromEpochMs, validUntilEpochMs);
        SecurityContract.require(workloadId.equals(deriveWorkloadId(networkId, spiffeId, role, instanceId,
                ed25519PublicKey)), "workload_id does not match canonical identity material");
    }

    public static String deriveWorkloadId(String networkId, String spiffeId, WorkloadRole role,
                                          String instanceId, String ed25519PublicKey) {
        return SecurityContract.sha256Hex(SecurityContract.transcript(SecurityContract.WORKLOAD_ID_DOMAIN, out -> {
            SecurityContract.field(out, SecurityContract.VERSION);
            SecurityContract.field(out, networkId);
            SecurityContract.field(out, spiffeId);
            SecurityContract.field(out, role.wireValue());
            SecurityContract.field(out, instanceId);
            SecurityContract.field(out, ed25519PublicKey);
        }));
    }

    @Override public byte[] signingBytes() {
        return SecurityContract.transcript(SecurityContract.WORKLOAD_IDENTITY_DOMAIN, out -> encodeFields(out));
    }

    void encodeFields(java.io.ByteArrayOutputStream out) {
        SecurityContract.field(out, contractVersion);
        SecurityContract.field(out, networkId);
        SecurityContract.field(out, workloadId);
        SecurityContract.field(out, spiffeId);
        SecurityContract.field(out, role.wireValue());
        SecurityContract.field(out, instanceId);
        SecurityContract.field(out, ed25519PublicKey);
        SecurityContract.integer(out, validFromEpochMs);
        SecurityContract.integer(out, validUntilEpochMs);
    }
}
