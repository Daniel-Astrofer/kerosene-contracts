package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum SigningOperation {
    SIGN_PSBT("sign_psbt");

    private final String wireValue;
    SigningOperation(String wireValue) { this.wireValue = wireValue; }
    @JsonValue public String wireValue() { return wireValue; }

    @JsonCreator
    public static SigningOperation fromWireValue(String value) {
        for (var operation : values()) if (operation.wireValue.equals(value)) return operation;
        throw new IllegalArgumentException("unknown signing operation: " + value);
    }
}
