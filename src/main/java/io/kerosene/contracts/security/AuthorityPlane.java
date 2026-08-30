package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Discovery plane whose stable manifest authorizes a service roster. */
public enum AuthorityPlane {
    BANK("bank"), VAULT("vault");

    private final String wireValue;
    AuthorityPlane(String wireValue) { this.wireValue = wireValue; }
    @JsonValue public String wireValue() { return wireValue; }

    @JsonCreator
    public static AuthorityPlane fromWireValue(String value) {
        for (var plane : values()) if (plane.wireValue.equals(value)) return plane;
        throw new IllegalArgumentException("unknown authority plane: " + value);
    }
}
