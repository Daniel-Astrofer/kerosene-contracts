package io.kerosene.contracts.admin.core;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

public record LedgerAccountV1(
        String id,
        String ownerId,
        String currency,
        String balance,
        String status,
        long createdAt,
        long updatedAt,
        List<String> tags) {}

public record LedgerJournalV1(
        String id,
        String accountId,
        String entryType,
        String amount,
        String currency,
        String description,
        String referenceId,
        long occurredAt,
        String status) {}
