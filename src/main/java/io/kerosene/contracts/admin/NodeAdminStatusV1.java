package io.kerosene.contracts.admin;

public record NodeAdminStatusV1(
        String contractVersion,
        String requestId,
        String networkId,
        String plane,
        boolean localReady,
        boolean memberReady,
        boolean quorumReady,
        boolean financialReady,
        long liveMembers,
        int threshold) {}
