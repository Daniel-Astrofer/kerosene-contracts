package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * P2P channel admin contract.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AdminP2PV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("channel_id") String channelId,
        @JsonProperty("remote_node_id") String remoteNodeId,
        @JsonProperty("capacity_sats") long capacitySats,
        @JsonProperty("local_balance_sats") long localBalanceSats,
        @JsonProperty("remote_balance_sats") long remoteBalanceSats,
        @JsonProperty("is_active") boolean isActive) {

    public AdminP2PV1 {
        if (contractVersion == null || contractVersion.isBlank())
            throw new IllegalArgumentException("contractVersion required");
        if (requestId == null || requestId.isBlank())
            throw new IllegalArgumentException("requestId required");
        if (channelId == null || channelId.isBlank())
            throw new IllegalArgumentException("channelId required");
        if (remoteNodeId == null || remoteNodeId.isBlank())
            throw new IllegalArgumentException("remoteNodeId required");
        if (capacitySats <= 0) throw new IllegalArgumentException("capacitySats must be > 0");
        if (localBalanceSats < 0) throw new IllegalArgumentException("localBalanceSats must be >= 0");
        if (remoteBalanceSats < 0) throw new IllegalArgumentException("remoteBalanceSats must be >= 0");
    }
}
