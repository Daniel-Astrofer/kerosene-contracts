package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * On-ramp order admin contract.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AdminOnrampV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("order_id") String orderId,
        @JsonProperty("user_id") String userId,
        @JsonProperty("fiat_currency") String fiatCurrency,
        @JsonProperty("fiat_amount") String fiatAmount,
        long sats,
        String provider,
        String status,
        @JsonProperty("created_at") String createdAt) {

    public AdminOnrampV1 {
        if (contractVersion == null || contractVersion.isBlank())
            throw new IllegalArgumentException("contractVersion required");
        if (requestId == null || requestId.isBlank())
            throw new IllegalArgumentException("requestId required");
        if (orderId == null || orderId.isBlank())
            throw new IllegalArgumentException("orderId required");
        if (fiatCurrency == null || fiatCurrency.isBlank())
            throw new IllegalArgumentException("fiatCurrency required");
        if (sats <= 0) throw new IllegalArgumentException("sats must be > 0");
        if (provider == null || provider.isBlank())
            throw new IllegalArgumentException("provider required");
        if (status == null || status.isBlank())
            throw new IllegalArgumentException("status required");
    }
}
