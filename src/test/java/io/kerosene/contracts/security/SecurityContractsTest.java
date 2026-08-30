package io.kerosene.contracts.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SecurityContractsTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SIGNER_MEMBER_ID =
            "98191e7416f040cebda3e8cd8bbf69d69f9e46a6553c8778ae39df827586c9df";
    private static final byte[] ED25519_SPKI_PREFIX =
            HexFormat.of().parseHex("302a300506032b6570032100");

    @Test
    void workloadIdentityVectorsMatchCanonicalJavaEncoding() throws Exception {
        var kfe = kat("workload-identity-kfe-v1.kat.json", WorkloadIdentityV1.class);
        var vault = kat("workload-identity-vault-v1.kat.json", WorkloadIdentityV1.class);

        assertEquals(kfe.value().workloadId(), WorkloadIdentityV1.deriveWorkloadId(
                kfe.value().networkId(), kfe.value().spiffeId(), kfe.value().role(),
                kfe.value().instanceId(), kfe.value().ed25519PublicKey()));
        assertEquals(vault.value().workloadId(), WorkloadIdentityV1.deriveWorkloadId(
                vault.value().networkId(), vault.value().spiffeId(), vault.value().role(),
                vault.value().instanceId(), vault.value().ed25519PublicKey()));
    }

    @Test
    void rosterVectorsHaveCanonicalHashesAndValidEd25519Signatures() throws Exception {
        for (String file : new String[] {
                "signed-service-roster-bank-v1.kat.json",
                "signed-service-roster-vault-v1.kat.json"
        }) {
            var kat = kat(file, SignedServiceRosterV1.class);
            assertEquals(kat.value().rosterHash(), kat.expectedSigningHash());
            assertTrue(verifyEd25519(kat.publicKey(), kat.value().signingBytes(),
                    kat.value().signatures().getFirst().signature()));
            kat.value().validateAuthority("kerosene-test", kat.value().authorityPlane(),
                    kat.value().authorityManifestHash(), 1, Set.of(SIGNER_MEMBER_ID));
            assertThrows(IllegalArgumentException.class, () -> kat.value().validateAuthority(
                    "kerosene-test", kat.value().authorityPlane(), kat.value().authorityManifestHash(),
                    2, Set.of(SIGNER_MEMBER_ID)));
        }
    }

    @Test
    void signingIntentIsBoundToRostersAndHasARealSignature() throws Exception {
        var bank = kat("signed-service-roster-bank-v1.kat.json", SignedServiceRosterV1.class).value();
        var vault = kat("signed-service-roster-vault-v1.kat.json", SignedServiceRosterV1.class).value();
        var intent = kat("signing-intent-v1.kat.json", SigningIntentV1.class);

        intent.value().validateRosterBinding(bank, vault);
        assertTrue(verifyEd25519(intent.publicKey(), intent.value().signingBytes(),
                intent.value().signature()));

        JsonNode mutated = vector("signing-intent-v1.kat.json").deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) mutated.path("contract"))
                .put("caller_spiffe_id", "spiffe://staging.kerosene/service/kfe/instance/attacker");
        var altered = JSON.treeToValue(mutated.path("contract"), SigningIntentV1.class);
        assertThrows(IllegalArgumentException.class, () -> altered.validateRosterBinding(bank, vault));
        assertFalse(verifyEd25519(intent.publicKey(), altered.signingBytes(), altered.signature()));
    }

    @Test
    void rosterSuccessorRejectsRollbackAndForks() throws Exception {
        var previous = kat("signed-service-roster-bank-v1.kat.json", SignedServiceRosterV1.class).value();
        String nextHash = SignedServiceRosterV1.computeRosterHash(previous.contractVersion(),
                previous.networkId(), previous.authorityPlane(), previous.authorityManifestHash(),
                2, previous.rosterHash(), previous.validFromEpochMs(), previous.validUntilEpochMs(),
                previous.members());
        var successor = new SignedServiceRosterV1(previous.contractVersion(), previous.networkId(),
                previous.authorityPlane(), previous.authorityManifestHash(), nextHash, 2,
                previous.rosterHash(), previous.validFromEpochMs(), previous.validUntilEpochMs(),
                previous.members(), previous.signatures());
        successor.validateSuccessor(previous);

        String forkParent = "f".repeat(64);
        String forkHash = SignedServiceRosterV1.computeRosterHash(previous.contractVersion(),
                previous.networkId(), previous.authorityPlane(), previous.authorityManifestHash(),
                2, forkParent, previous.validFromEpochMs(), previous.validUntilEpochMs(), previous.members());
        var fork = new SignedServiceRosterV1(previous.contractVersion(), previous.networkId(),
                previous.authorityPlane(), previous.authorityManifestHash(), forkHash, 2, forkParent,
                previous.validFromEpochMs(), previous.validUntilEpochMs(), previous.members(),
                previous.signatures());
        assertThrows(IllegalArgumentException.class, () -> fork.validateSuccessor(previous));
    }

    @Test
    void malformedSecurityContractsFailClosed() throws Exception {
        JsonNode stale = vector("signed-service-roster-bank-v1.kat.json").deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) stale.path("contract"))
                .put("epoch", 2);
        assertThrows(Exception.class,
                () -> JSON.treeToValue(stale.path("contract"), SignedServiceRosterV1.class));

        JsonNode longLived = vector("signing-intent-v1.kat.json").deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) longLived.path("contract"))
                .put("expires_at_epoch_ms", 1788134460001L);
        assertThrows(Exception.class,
                () -> JSON.treeToValue(longLived.path("contract"), SigningIntentV1.class));

        JsonNode unknown = vector("workload-identity-kfe-v1.kat.json").deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) unknown.path("contract"))
                .put("certificate_sha256", "0".repeat(64));
        assertThrows(Exception.class,
                () -> JSON.treeToValue(unknown.path("contract"), WorkloadIdentityV1.class));
    }

    @Test
    void schemasAndTypedVectorsExposeTheSameRequiredFields() throws Exception {
        assertSchemaSurface("workload-identity-v1.schema.json",
                vector("workload-identity-kfe-v1.kat.json").path("contract"));
        assertSchemaSurface("signed-service-roster-v1.schema.json",
                vector("signed-service-roster-bank-v1.kat.json").path("contract"));
        assertSchemaSurface("signing-intent-v1.schema.json",
                vector("signing-intent-v1.kat.json").path("contract"));

        JsonNode workloadSchema = schema("workload-identity-v1.schema.json");
        Set<String> schemaRoles = new HashSet<>();
        workloadSchema.path("properties").path("role").path("enum")
                .forEach(value -> schemaRoles.add(value.asText()));
        assertEquals(Set.of("auth", "kfe", "vault", "node", "admin"), schemaRoles);
        assertEquals("sign_psbt", schema("signing-intent-v1.schema.json")
                .path("properties").path("operation").path("const").asText());
    }

    private static <T extends CanonicalSignable> Kat<T> kat(String file, Class<T> type) throws Exception {
        JsonNode root = vector(file);
        T value = JSON.treeToValue(root.path("contract"), type);
        String expectedHash = root.path("expected_signing_hash").asText();
        assertEquals(expectedHash, value.canonicalHash(), "canonical hash mismatch for " + file);
        return new Kat<>(value, expectedHash, root.path("signature_public_key").asText());
    }

    private static JsonNode vector(String file) throws Exception {
        Path path = Path.of("test-vectors", "security", file);
        return JSON.readTree(Files.readString(path));
    }

    private static JsonNode schema(String file) throws Exception {
        return JSON.readTree(Files.readString(Path.of("schemas", "security", file)));
    }

    private static void assertSchemaSurface(String schemaFile, JsonNode contract) throws Exception {
        Set<String> required = new HashSet<>();
        schema(schemaFile).path("required").forEach(value -> required.add(value.asText()));
        Set<String> actual = new HashSet<>();
        contract.fieldNames().forEachRemaining(actual::add);
        assertEquals(required, actual, "schema/vector field drift in " + schemaFile);
    }

    private static boolean verifyEd25519(String publicKeyHex, byte[] message, String signatureHex)
            throws Exception {
        byte[] raw = HexFormat.of().parseHex(publicKeyHex);
        byte[] spki = new byte[ED25519_SPKI_PREFIX.length + raw.length];
        System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
        System.arraycopy(raw, 0, spki, ED25519_SPKI_PREFIX.length, raw.length);
        var key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
        var verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(key);
        verifier.update(message);
        return verifier.verify(HexFormat.of().parseHex(signatureHex));
    }

    private record Kat<T>(T value, String expectedSigningHash, String publicKey) {}
}
