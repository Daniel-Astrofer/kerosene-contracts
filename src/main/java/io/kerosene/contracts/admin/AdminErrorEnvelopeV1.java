package io.kerosene.contracts.admin;

import java.util.Map;

public record AdminErrorEnvelopeV1(
        String contractVersion,
        String code,
        String message,
        String requestId,
        Map<String, Object> details) {}
