package io.kerosene.contracts.admin;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Reconciliation admin contract.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AdminReconciliationV1(
        @JsonProperty("contract_version") String contractVersion,
        @JsonProperty("request_id") String requestId,
        @JsonProperty("reconciliation_id") String reconciliationId,
        @JsonProperty("ledger_sats") long ledgerSats,
        @JsonProperty("onchain_sats") long onchainSats,
        @JsonProperty("lightning_sats") long lightningSats,
        @JsonProperty("delta_sats") long deltaSats,
        String status,
        @JsonProperty("reconciled_at") String reconciledAt) {

    public AdminReconciliationV1 {
        if (contractVersion == null || contractVersion.isBlank())
            throw new IllegalArgumentException("contractVersion required");
        if (requestId == null || requestId.isBlank())
            throw new IllegalArgumentException("requestId required");
        if (reconciliationId == null || reconciliationId.isBlank())
            throw new IllegalArgumentException("reconciliationId required");
        if (ledgerSats < 0) throw new IllegalArgumentException("ledgerSats must be >= 0");
        if (onchainSats < 0) throw new IllegalArgumentException("onchainSats must be >= 0");
        if (lightningSats < 0) throw new IllegalArgumentException("lightningSats must be >= 0");
        if (status == null || status.isBlank())
            throw new IllegalArgumentException("status required");
    }
}
