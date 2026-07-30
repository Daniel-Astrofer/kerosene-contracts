package io.kerosene.contracts.admin.core;

public record P2pOrderV1(
        String id,
        String makerId,
        String takerId,
        String side,
        String asset,
        String fiatCurrency,
        String amount,
        String price,
        String status,
        long createdAt,
        long updatedAt) {}
