package io.kerosene.contracts.security;

/** A wire object with an unambiguous, domain-separated signing transcript. */
public interface CanonicalSignable {
    byte[] signingBytes();

    default String canonicalHash() {
        return SecurityContract.sha256Hex(signingBytes());
    }
}
