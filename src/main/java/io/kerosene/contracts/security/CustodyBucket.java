package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum CustodyBucket {
    USERS("users"), CHANNELS("channels");

    private final String wireValue;
    CustodyBucket(String wireValue) { this.wireValue = wireValue; }
    @JsonValue public String wireValue() { return wireValue; }

    @JsonCreator
    public static CustodyBucket fromWireValue(String value) {
        for (var bucket : values()) if (bucket.wireValue.equals(value)) return bucket;
        throw new IllegalArgumentException("unknown custody bucket: " + value);
    }
}
