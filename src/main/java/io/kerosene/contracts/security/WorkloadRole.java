package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum WorkloadRole {
    AUTH("auth"), KFE("kfe"), VAULT("vault"), NODE("node"), ADMIN("admin");

    private final String wireValue;
    WorkloadRole(String wireValue) { this.wireValue = wireValue; }
    @JsonValue public String wireValue() { return wireValue; }

    @JsonCreator
    public static WorkloadRole fromWireValue(String value) {
        for (var role : values()) if (role.wireValue.equals(value)) return role;
        throw new IllegalArgumentException("unknown workload role: " + value);
    }
}
