package io.kerosene.contracts.security;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/** Shared validation and canonical binary encoding for security contracts v1. */
public final class SecurityContract {
    public static final String VERSION = "0.3.0";
    static final byte[] WORKLOAD_ID_DOMAIN = bytes("KEROSENE_WORKLOAD_ID_V1");
    static final byte[] WORKLOAD_IDENTITY_DOMAIN = bytes("KEROSENE_WORKLOAD_IDENTITY_V1");
    static final byte[] SERVICE_ROSTER_DOMAIN = bytes("KEROSENE_SIGNED_SERVICE_ROSTER_V1");
    static final byte[] SIGNING_INTENT_DOMAIN = bytes("KEROSENE_SIGNING_INTENT_V1");

    private static final Pattern HEX_32 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern HEX_64 = Pattern.compile("[0-9a-f]{128}");
    private static final Pattern NETWORK = Pattern.compile("[^\\s]{1,128}");
    private static final Pattern INSTANCE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Pattern INTENT = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern SPIFFE = Pattern.compile(
            "spiffe://[a-z0-9.-]+/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]+");
    private static final Pattern ENDPOINT = Pattern.compile(
            "https://[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[1-9][0-9]{0,4})?");

    private SecurityContract() {}

    static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    static void requireVersion(String value) {
        require(VERSION.equals(value), "contract_version must be " + VERSION);
    }

    static void requireNetwork(String value) {
        require(value != null && NETWORK.matcher(value).matches(), "invalid network_id");
    }

    static void requireHex32(String value, String field) {
        require(value != null && HEX_32.matcher(value).matches(), field + " must be 32-byte lowercase hex");
    }

    static void requireHex64(String value, String field) {
        require(value != null && HEX_64.matcher(value).matches(), field + " must be 64-byte lowercase hex");
    }

    static void requireWindow(long from, long until) {
        require(from >= 0 && until > from, "validity window must be non-empty and increasing");
    }

    static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }

    static void requireInstance(String value) {
        require(value != null && INSTANCE.matcher(value).matches(), "invalid instance_id");
    }

    static void requireIntentId(String value) {
        require(value != null && INTENT.matcher(value).matches(), "invalid intent_id");
    }

    static void requireIdentifier(String value, String field) {
        require(value != null && INTENT.matcher(value).matches(), "invalid " + field);
    }

    static void requireSpiffeId(String value) {
        require(value != null && value.length() <= 512 && SPIFFE.matcher(value).matches(), "invalid spiffe_id");
    }

    static void requireEndpoint(String value) {
        require(value != null && value.length() <= 272 && ENDPOINT.matcher(value).matches(),
                "invalid service endpoint");
        int separator = value.lastIndexOf(':');
        if (separator > "https://".length()) {
            int port = Integer.parseInt(value.substring(separator + 1));
            require(port <= 65535, "invalid service endpoint");
        }
    }

    static void requireNonblank(String value, int max, String field) {
        require(value != null && !value.isEmpty() && value.length() <= max
                        && value.chars().noneMatch(Character::isWhitespace),
                "invalid " + field);
    }

    static <T> void requireUnique(Collection<T> values, Function<T, String> key, String field) {
        Set<String> seen = new HashSet<>();
        for (T value : values) require(seen.add(key.apply(value)), "duplicate " + field);
    }

    static <T> void requireSortedUnique(Collection<T> values, Function<T, String> key, String field) {
        String previous = null;
        for (T value : values) {
            String current = key.apply(value);
            require(previous == null || Comparator.<String>naturalOrder().compare(previous, current) < 0,
                    field + " must be strictly sorted and unique");
            previous = current;
        }
    }

    static byte[] transcript(byte[] domain, Encoder encoder) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        field(out, domain);
        encoder.encode(out);
        return out.toByteArray();
    }

    static void field(ByteArrayOutputStream out, String value) {
        field(out, bytes(value));
    }

    static void field(ByteArrayOutputStream out, byte[] value) {
        integer(out, value.length);
        out.writeBytes(value);
    }

    static void integer(ByteArrayOutputStream out, long value) {
        out.writeBytes(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
    }

    public static String sha256Hex(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    @FunctionalInterface
    interface Encoder { void encode(ByteArrayOutputStream out); }
}
