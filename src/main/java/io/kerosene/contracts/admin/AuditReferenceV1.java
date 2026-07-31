package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuditReferenceV1(
        @JsonProperty("event_id") String eventId,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("occurred_at") String occurredAt) {}
