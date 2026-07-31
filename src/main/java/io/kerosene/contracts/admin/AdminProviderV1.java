package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Provider admin contract.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AdminProviderV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("provider_id") String providerId,
        @JsonProperty("provider_type") String providerType,
        @JsonProperty("is_online") boolean isOnline,
        @JsonProperty("last_heartbeat") String lastHeartbeat,
        String version) {

    public AdminProviderV1 {
        if (contractVersion == null || contractVersion.isBlank())
            throw new IllegalArgumentException("contractVersion required");
        if (requestId == null || requestId.isBlank())
            throw new IllegalArgumentException("requestId required");
        if (providerId == null || providerId.isBlank())
            throw new IllegalArgumentException("providerId required");
        if (providerType == null || providerType.isBlank())
            throw new IllegalArgumentException("providerType required");
    }
}
