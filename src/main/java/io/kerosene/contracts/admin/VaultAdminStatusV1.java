package io.kerosene.contracts.admin;

public record VaultAdminStatusV1(
        String contractVersion,
        String requestId,
        boolean localReady,
        boolean financialReady,
        String nodeId,
        String ceremonyMode,
        String bitcoinNetwork) {}
