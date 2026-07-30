package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LedgerJournalV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("entry_id") String entryId,
        @JsonProperty("account_id") String accountId,
        String direction,
        String amount,
        String currency,
        String description,
        String reference,
        @JsonProperty("recorded_at") String recordedAt) {}
