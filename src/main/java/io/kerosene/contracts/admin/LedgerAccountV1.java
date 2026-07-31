package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

/**
 * Admin/core: ledger account for financial read operations.
 * <p>
 * Uses a multi-saldo satoshi model — all balances are denominated in sats
 * (1 sat = 1e-8 BTC). {@code stateRoot} is the hex-encoded SHA-256 of the
 * account's internal state and is opaque to the wire protocol.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record LedgerAccountV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("account_id") String accountId,
        @JsonProperty("account_type") String accountType,
        @JsonProperty("available_sats") long availableSats,
        @JsonProperty("reserved_sats") long reservedSats,
        @JsonProperty("pending_incoming_sats") long pendingIncomingSats,
        @JsonProperty("pending_outgoing_sats") long pendingOutgoingSats,
        @JsonProperty("confirmed_onchain_sats") long confirmedOnchainSats,
        @JsonProperty("unconfirmed_onchain_sats") long unconfirmedOnchainSats,
        @JsonProperty("spendable_by_kerosene_sats") long spendableByKeroseneSats,
        @JsonProperty("state_version") long stateVersion,
        @JsonProperty("state_root") String stateRoot,
        List<String> tags,
        @JsonProperty("created_at") String createdAt,
        @JsonProperty("updated_at") String updatedAt) {

    public LedgerAccountV1 {
        if (contractVersion == null || contractVersion.isBlank())
            throw new IllegalArgumentException("contractVersion required");
        if (accountId == null || accountId.isBlank())
            throw new IllegalArgumentException("accountId required");
        if (availableSats < 0) throw new IllegalArgumentException("availableSats must be >= 0");
        if (reservedSats < 0) throw new IllegalArgumentException("reservedSats must be >= 0");
        if (pendingIncomingSats < 0) throw new IllegalArgumentException("pendingIncomingSats must be >= 0");
        if (pendingOutgoingSats < 0) throw new IllegalArgumentException("pendingOutgoingSats must be >= 0");
        if (confirmedOnchainSats < 0) throw new IllegalArgumentException("confirmedOnchainSats must be >= 0");
        if (unconfirmedOnchainSats < 0) throw new IllegalArgumentException("unconfirmedOnchainSats must be >= 0");
        if (spendableByKeroseneSats < 0) throw new IllegalArgumentException("spendableByKeroseneSats must be >= 0");
        if (stateRoot != null && !stateRoot.matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("stateRoot must be 64 hex chars, got: " + stateRoot);
    }
}
