package io.kerosene.contracts.admin.core;

import java.util.List;

public record ProviderConnectionValidationV1(
        String providerId,
        String providerType,
        boolean reachable,
        boolean authenticated,
        boolean functional,
        String latencyMs,
        List<String> warnings,
        List<String> errors) {}
