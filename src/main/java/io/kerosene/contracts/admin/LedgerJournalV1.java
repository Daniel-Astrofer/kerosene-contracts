package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Admin/core: ledger journal entry for financial reconciliation.
 * <p>
 * {@code amountSats} replaces the old generic {@code amount} + {@code currency} pair.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LedgerJournalV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("entry_id") String entryId,
        @JsonProperty("account_id") String accountId,
        String direction,
        @JsonProperty("amount_sats") long amountSats,
        String description,
        String reference,
        @JsonProperty("recorded_at") String recordedAt) {

    public LedgerJournalV1 {
        if (contractVersion == null || contractVersion.isBlank())
            throw new IllegalArgumentException("contractVersion required");
        if (entryId == null || entryId.isBlank())
            throw new IllegalArgumentException("entryId required");
        if (accountId == null || accountId.isBlank())
            throw new IllegalArgumentException("accountId required");
        if (direction == null || direction.isBlank())
            throw new IllegalArgumentException("direction required");
        if (!direction.equals("debit") && !direction.equals("credit"))
            throw new IllegalArgumentException("direction must be 'debit' or 'credit', got: " + direction);
        if (amountSats <= 0) throw new IllegalArgumentException("amountSats must be > 0");
    }
}
