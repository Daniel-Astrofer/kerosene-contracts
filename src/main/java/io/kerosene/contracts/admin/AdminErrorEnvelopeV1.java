package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.Map;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AdminErrorEnvelopeV1(
        @JsonProperty("contract_version") String contractVersion,
        String code,
        String message,
        @JsonProperty("request_id") String requestId,
        Map<String, Object> details) {}
