package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LedgerAccountV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("account_id") String accountId,
        @JsonProperty("account_type") String accountType,
        String balance,
        String currency,
        List<String> tags,
        @JsonProperty("created_at") String createdAt,
        @JsonProperty("updated_at") String updatedAt) {}
