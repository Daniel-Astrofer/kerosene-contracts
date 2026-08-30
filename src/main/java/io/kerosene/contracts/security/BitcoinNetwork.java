package io.kerosene.contracts.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum BitcoinNetwork {
    MAINNET("mainnet"), TESTNET("testnet"), SIGNET("signet"), REGTEST("regtest");

    private final String wireValue;
    BitcoinNetwork(String wireValue) { this.wireValue = wireValue; }
    @JsonValue public String wireValue() { return wireValue; }

    @JsonCreator
    public static BitcoinNetwork fromWireValue(String value) {
        for (var network : values()) if (network.wireValue.equals(value)) return network;
        throw new IllegalArgumentException("unknown bitcoin network: " + value);
    }
}
