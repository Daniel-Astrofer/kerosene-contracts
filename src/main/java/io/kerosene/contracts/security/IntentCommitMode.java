package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum IntentCommitMode {
    RESERVE_AND_COMMIT("reserve_and_commit"), SIGN_RESERVED("sign_reserved");

    private final String wireValue;
    IntentCommitMode(String wireValue) { this.wireValue = wireValue; }
    @JsonValue public String wireValue() { return wireValue; }

    @JsonCreator
    public static IntentCommitMode fromWireValue(String value) {
        for (var mode : values()) if (mode.wireValue.equals(value)) return mode;
        throw new IllegalArgumentException("unknown intent commit mode: " + value);
    }
}
