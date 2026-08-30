package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/** Canonical KFE authorization for one bounded Vault PSBT signing attempt. */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record SigningIntentV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("network_id") String networkId,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("intent_id") String intentId,
        @JsonProperty("issuer_workload_id") String issuerWorkloadId,
        @JsonProperty("audience_workload_id") String audienceWorkloadId,
        @JsonProperty("caller_spiffe_id") String callerSpiffeId,
        @JsonProperty("audience_spiffe_id") String audienceSpiffeId,
        @JsonProperty("issuer_roster_hash") String issuerRosterHash,
        @JsonProperty("audience_roster_hash") String audienceRosterHash,
        SigningOperation operation,
        @JsonProperty("wallet_id") String walletId,
        @JsonProperty("bitcoin_network") BitcoinNetwork bitcoinNetwork,
        @JsonProperty("custody_bucket") CustodyBucket custodyBucket,
        String destination,
        @JsonProperty("psbt_sha256") String psbtSha256,
        @JsonProperty("change_descriptor_sha256") String changeDescriptorSha256,
        @JsonProperty("policy_hash") String policyHash,
        @JsonProperty("policy_epoch") long policyEpoch,
        @JsonProperty("participant_epoch") long participantEpoch,
        @JsonProperty("amount_sats") long amountSats,
        @JsonProperty("max_fee_sats") long maxFeeSats,
        @JsonProperty("max_fee_rate_sat_vb") long maxFeeRateSatVb,
        @JsonProperty("expected_input_count") int expectedInputCount,
        @JsonProperty("commit_mode") IntentCommitMode commitMode,
        @JsonProperty("authorization_hash") String authorizationHash,
        String nonce,
        long sequence,
        @JsonProperty("issued_at_epoch_ms") long issuedAtEpochMs,
        @JsonProperty("expires_at_epoch_ms") long expiresAtEpochMs,
        String signature) implements CanonicalSignable {

    public SigningIntentV1 {
        SecurityContract.requireVersion(contractVersion);
        SecurityContract.requireNetwork(networkId);
        SecurityContract.requireIdentifier(requestId, "request_id");
        SecurityContract.requireIntentId(intentId);
        SecurityContract.requireHex32(issuerWorkloadId, "issuer_workload_id");
        SecurityContract.requireHex32(audienceWorkloadId, "audience_workload_id");
        SecurityContract.require(!issuerWorkloadId.equals(audienceWorkloadId),
                "issuer and audience must differ");
        SecurityContract.requireSpiffeId(callerSpiffeId);
        SecurityContract.requireSpiffeId(audienceSpiffeId);
        SecurityContract.require(!callerSpiffeId.equals(audienceSpiffeId),
                "caller and audience SPIFFE IDs must differ");
        SecurityContract.requireHex32(issuerRosterHash, "issuer_roster_hash");
        SecurityContract.requireHex32(audienceRosterHash, "audience_roster_hash");
        SecurityContract.require(operation == SigningOperation.SIGN_PSBT,
                "operation must be sign_psbt");
        SecurityContract.requireIdentifier(walletId, "wallet_id");
        SecurityContract.require(bitcoinNetwork != null, "bitcoin_network is required");
        SecurityContract.require(custodyBucket != null, "custody_bucket is required");
        SecurityContract.requireNonblank(destination, 256, "destination");
        SecurityContract.requireHex32(psbtSha256, "psbt_sha256");
        SecurityContract.requireHex32(changeDescriptorSha256, "change_descriptor_sha256");
        SecurityContract.requireHex32(policyHash, "policy_hash");
        SecurityContract.require(policyEpoch > 0 && participantEpoch > 0,
                "policy_epoch and participant_epoch must be positive");
        SecurityContract.require(amountSats > 0, "amount_sats must be positive");
        SecurityContract.require(maxFeeSats >= 0 && maxFeeSats <= amountSats,
                "max_fee_sats must be between zero and amount_sats");
        SecurityContract.require(maxFeeRateSatVb > 0 && maxFeeRateSatVb <= 1_000_000,
                "max_fee_rate_sat_vb is outside the supported range");
        SecurityContract.require(expectedInputCount > 0 && expectedInputCount <= 10_000,
                "expected_input_count is outside the supported range");
        SecurityContract.require(commitMode != null, "commit_mode is required");
        SecurityContract.requireHex32(authorizationHash, "authorization_hash");
        SecurityContract.requireHex32(nonce, "nonce");
        SecurityContract.require(sequence > 0, "sequence must be positive");
        SecurityContract.requireWindow(issuedAtEpochMs, expiresAtEpochMs);
        SecurityContract.require(expiresAtEpochMs - issuedAtEpochMs <= 60_000,
                "signing intent lifetime exceeds 60 seconds");
        SecurityContract.requireHex64(signature, "signature");
    }

    public void validateRosterBinding(SignedServiceRosterV1 issuerRoster,
                                      SignedServiceRosterV1 audienceRoster) {
        SecurityContract.require(networkId.equals(issuerRoster.networkId())
                        && networkId.equals(audienceRoster.networkId()),
                "signing intent roster network_id mismatch");
        SecurityContract.require(issuerRosterHash.equals(issuerRoster.rosterHash())
                        && audienceRosterHash.equals(audienceRoster.rosterHash()),
                "signing intent roster hash mismatch");
        var issuer = issuerRoster.members().stream()
                .filter(member -> member.identity().workloadId().equals(issuerWorkloadId))
                .findFirst().orElseThrow(() -> new IllegalArgumentException(
                        "issuer workload is absent from issuer roster"));
        var audience = audienceRoster.members().stream()
                .filter(member -> member.identity().workloadId().equals(audienceWorkloadId))
                .findFirst().orElseThrow(() -> new IllegalArgumentException(
                        "audience workload is absent from audience roster"));
        SecurityContract.require(issuer.identity().role() == WorkloadRole.KFE
                        && audience.identity().role() == WorkloadRole.VAULT,
                "signing intent requires a KFE issuer and Vault audience");
        SecurityContract.require(callerSpiffeId.equals(issuer.identity().spiffeId())
                        && audienceSpiffeId.equals(audience.identity().spiffeId()),
                "signing intent SPIFFE identity does not match roster");
        SecurityContract.require(issuedAtEpochMs >= issuerRoster.validFromEpochMs()
                        && expiresAtEpochMs <= issuerRoster.validUntilEpochMs()
                        && issuedAtEpochMs >= audienceRoster.validFromEpochMs()
                        && expiresAtEpochMs <= audienceRoster.validUntilEpochMs(),
                "signing intent exceeds roster validity");
    }

    @Override public byte[] signingBytes() {
        return SecurityContract.transcript(SecurityContract.SIGNING_INTENT_DOMAIN, out -> {
            SecurityContract.field(out, contractVersion);
            SecurityContract.field(out, networkId);
            SecurityContract.field(out, requestId);
            SecurityContract.field(out, intentId);
            SecurityContract.field(out, issuerWorkloadId);
            SecurityContract.field(out, audienceWorkloadId);
            SecurityContract.field(out, callerSpiffeId);
            SecurityContract.field(out, audienceSpiffeId);
            SecurityContract.field(out, issuerRosterHash);
            SecurityContract.field(out, audienceRosterHash);
            SecurityContract.field(out, operation.wireValue());
            SecurityContract.field(out, walletId);
            SecurityContract.field(out, bitcoinNetwork.wireValue());
            SecurityContract.field(out, custodyBucket.wireValue());
            SecurityContract.field(out, destination);
            SecurityContract.field(out, psbtSha256);
            SecurityContract.field(out, changeDescriptorSha256);
            SecurityContract.field(out, policyHash);
            SecurityContract.integer(out, policyEpoch);
            SecurityContract.integer(out, participantEpoch);
            SecurityContract.integer(out, amountSats);
            SecurityContract.integer(out, maxFeeSats);
            SecurityContract.integer(out, maxFeeRateSatVb);
            SecurityContract.integer(out, expectedInputCount);
            SecurityContract.field(out, commitMode.wireValue());
            SecurityContract.field(out, authorizationHash);
            SecurityContract.field(out, nonce);
            SecurityContract.integer(out, sequence);
            SecurityContract.integer(out, issuedAtEpochMs);
            SecurityContract.integer(out, expiresAtEpochMs);
        });
    }
}
