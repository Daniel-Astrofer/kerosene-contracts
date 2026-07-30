package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record NodeAdminStatusV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("network_id") String networkId,
        String plane,
        @JsonProperty("local_ready") boolean localReady,
        @JsonProperty("member_ready") boolean memberReady,
        @JsonProperty("quorum_ready") boolean quorumReady,
        @JsonProperty("financial_ready") boolean financialReady,
        @JsonProperty("live_members") long liveMembers,
        int threshold) {}
