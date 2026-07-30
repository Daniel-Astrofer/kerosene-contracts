package io.kerosene.contracts.admin.core;

import java.util.Map;

public record ReconciliationStatusV1(
        String state,
        String lastRunAt,
        long totalDiscrepancies,
        long resolvedDiscrepancies,
        Map<String, Long> countsByType) {}
