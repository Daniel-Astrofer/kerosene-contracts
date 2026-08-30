package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record RosterSignatureV1(
        @JsonProperty("signer_member_id") String signerMemberId,
        String signature) {
    public RosterSignatureV1 {
        SecurityContract.requireHex32(signerMemberId, "signer_member_id");
        SecurityContract.requireHex64(signature, "signature");
    }
}
