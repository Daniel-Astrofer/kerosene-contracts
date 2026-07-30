package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record VaultAdminStatusV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("local_ready") boolean localReady,
        @JsonProperty("financial_ready") boolean financialReady,
        @JsonProperty("node_id") String nodeId,
        @JsonProperty("ceremony_mode") String ceremonyMode,
        @JsonProperty("bitcoin_network") String bitcoinNetwork) {}
