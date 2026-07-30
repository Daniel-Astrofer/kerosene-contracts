package io.kerosene.contracts.admin.core;

public record OnrampOrderV1(
        String id,
        String userId,
        String sourceCurrency,
        String targetAsset,
        String sourceAmount,
        String targetAmount,
        String providerId,
        String status,
        String failureReason,
        long createdAt,
        long updatedAt) {}
