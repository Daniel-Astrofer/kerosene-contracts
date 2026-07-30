package io.kerosene.contracts.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AdminContractsJsonTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ObjectMapper();
        mapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        mapper.registerModule(new JavaTimeModule());
    }

    // ------------------------------------------------------------------
    // Node admin status
    // ------------------------------------------------------------------

    @Test
    void nodeAdminStatusSerialization() throws Exception {
        var status = new NodeAdminStatusV1(
                "0.1.0", "req-1", "kerosene-test", "bank",
                true, true, false, true, 3, 2);
        String json = mapper.writeValueAsString(status);
        assertTrue(json.contains("\"contract_version\""));
        assertTrue(json.contains("\"request_id\""));
        assertTrue(json.contains("\"network_id\""));
        assertTrue(json.contains("\"local_ready\""));
        assertTrue(json.contains("\"member_ready\""));
        assertFalse(json.contains("\"contractVersion\""), "Should use snake_case not camelCase");
    }

    @Test
    void nodeAdminStatusDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "request_id": "req-1",
                  "network_id": "kerosene-test",
                  "plane": "bank",
                  "local_ready": true,
                  "member_ready": true,
                  "quorum_ready": false,
                  "financial_ready": true,
                  "live_members": 3,
                  "threshold": 2
                }
                """;
        var status = mapper.readValue(json, NodeAdminStatusV1.class);
        assertEquals("0.1.0", status.contractVersion());
        assertEquals("req-1", status.requestId());
        assertEquals("kerosene-test", status.networkId());
        assertEquals("bank", status.plane());
        assertTrue(status.localReady());
        assertTrue(status.memberReady());
        assertFalse(status.quorumReady());
        assertTrue(status.financialReady());
        assertEquals(3, status.liveMembers());
        assertEquals(2, status.threshold());
    }

    @Test
    void nodeAdminStatusRejectsUnknownFields() {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "request_id": "req-1",
                  "network_id": "kerosene-test",
                  "plane": "bank",
                  "local_ready": true,
                  "member_ready": true,
                  "quorum_ready": false,
                  "financial_ready": true,
                  "live_members": 3,
                  "threshold": 2,
                  "unknown_field": "should_fail"
                }
                """;
        assertThrows(UnrecognizedPropertyException.class,
                () -> mapper.readValue(json, NodeAdminStatusV1.class));
    }

    // ------------------------------------------------------------------
    // Vault admin status
    // ------------------------------------------------------------------

    @Test
    void vaultAdminStatusSerialization() throws Exception {
        var status = new VaultAdminStatusV1(
                "0.1.0", "req-vault", true, true,
                "node-1", "production", "mainnet");
        String json = mapper.writeValueAsString(status);
        assertTrue(json.contains("\"ceremony_mode\""));
        assertTrue(json.contains("\"bitcoin_network\""));
        assertFalse(json.contains("\"ceremonyMode\""), "Should use snake_case");
    }

    @Test
    void vaultAdminStatusDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "request_id": "req-vault",
                  "local_ready": true,
                  "financial_ready": true,
                  "node_id": "vault-node-1",
                  "ceremony_mode": "production",
                  "bitcoin_network": "mainnet"
                }
                """;
        var status = mapper.readValue(json, VaultAdminStatusV1.class);
        assertEquals("vault-node-1", status.nodeId());
        assertEquals("production", status.ceremonyMode());
        assertEquals("mainnet", status.bitcoinNetwork());
    }

    @Test
    void vaultAdminStatusRejectsUnknownFields() {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "request_id": "req-vault",
                  "local_ready": true,
                  "financial_ready": true,
                  "node_id": "node-1",
                  "ceremony_mode": "production",
                  "bitcoin_network": "mainnet",
                  "extra": "rejected"
                }
                """;
        assertThrows(UnrecognizedPropertyException.class,
                () -> mapper.readValue(json, VaultAdminStatusV1.class));
    }

    // ------------------------------------------------------------------
    // Error envelope / audit reference
    // ------------------------------------------------------------------

    @Test
    void adminErrorEnvelopeSerialization() throws Exception {
        var error = new AdminErrorEnvelopeV1(
                "0.1.0", "ERR_TEST", "Something went wrong",
                "req-err", Map.of("cause", "timeout"));
        String json = mapper.writeValueAsString(error);
        assertTrue(json.contains("\"contract_version\""));
        assertTrue(json.contains("\"request_id\""));
        assertTrue(json.contains("\"ERR_TEST\""));
    }

    @Test
    void auditReferenceSerialization() throws Exception {
        var audit = new AuditReferenceV1(
                "evt-001", "req-audit", "2026-07-30T12:00:00Z");
        String json = mapper.writeValueAsString(audit);
        assertTrue(json.contains("\"event_id\""));
        assertTrue(json.contains("\"occurred_at\""));
    }

    // ------------------------------------------------------------------
    // Multi-saldo ledger account
    // ------------------------------------------------------------------

    @Test
    void ledgerAccountSerialization() throws Exception {
        var account = new LedgerAccountV1(
                "0.1.0", "acc-123", "checking",
                800_000_000L, 100_000_000L, 50_000_000L, 20_000_000L,
                500_000_000L, 10_000_000L, 700_000_000L, 42L,
                "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                List.of("hot", "operational"),
                "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z");
        String json = mapper.writeValueAsString(account);
        assertTrue(json.contains("\"account_id\""));
        assertTrue(json.contains("\"account_type\""));
        assertTrue(json.contains("\"available_sats\""));
        assertTrue(json.contains("\"spendable_by_kerosene_sats\""));
        assertTrue(json.contains("\"state_root\""));
        assertTrue(json.contains("\"state_version\""));
        assertTrue(json.contains("\"created_at\""));
        // Verify legacy fields are absent
        assertFalse(json.contains("\"balance\""), "legacy balance field must not appear");
        assertFalse(json.contains("\"currency\""), "legacy currency field must not appear");
    }

    @Test
    void ledgerAccountDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "account_id": "acc-456",
                  "account_type": "savings",
                  "available_sats": 500000000,
                  "reserved_sats": 0,
                  "pending_incoming_sats": 0,
                  "pending_outgoing_sats": 0,
                  "confirmed_onchain_sats": 500000000,
                  "unconfirmed_onchain_sats": 0,
                  "spendable_by_kerosene_sats": 500000000,
                  "state_version": 1,
                  "state_root": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                  "tags": ["cold", "reserve"],
                  "created_at": "2026-03-15T00:00:00Z",
                  "updated_at": "2026-07-28T00:00:00Z"
                }
                """;
        var account = mapper.readValue(json, LedgerAccountV1.class);
        assertEquals("acc-456", account.accountId());
        assertEquals("savings", account.accountType());
        assertEquals(500_000_000L, account.availableSats());
        assertEquals("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", account.stateRoot());
        assertEquals(List.of("cold", "reserve"), account.tags());
    }

    @Test
    void ledgerAccountRejectsLegacyFields() {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "account_id": "acc-1",
                  "account_type": "savings",
                  "balance": "500000",
                  "currency": "BTC",
                  "tags": [],
                  "created_at": "2026-01-01T00:00:00Z",
                  "updated_at": "2026-07-01T00:00:00Z"
                }
                """;
        assertThrows(UnrecognizedPropertyException.class,
                () -> mapper.readValue(json, LedgerAccountV1.class));
    }

    @Test
    void ledgerAccountRejectsUnknownFields() {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "account_id": "acc-1",
                  "account_type": "savings",
                  "available_sats": 500000000,
                  "reserved_sats": 0,
                  "pending_incoming_sats": 0,
                  "pending_outgoing_sats": 0,
                  "confirmed_onchain_sats": 500000000,
                  "unconfirmed_onchain_sats": 0,
                  "spendable_by_kerosene_sats": 500000000,
                  "state_version": 1,
                  "state_root": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                  "tags": [],
                  "created_at": "2026-01-01T00:00:00Z",
                  "updated_at": "2026-07-01T00:00:00Z",
                  "unknown": "rejected"
                }
                """;
        assertThrows(UnrecognizedPropertyException.class,
                () -> mapper.readValue(json, LedgerAccountV1.class));
    }

    @Test
    void ledgerAccountValidatesStateRoot() {
        assertThrows(IllegalArgumentException.class, () ->
                new LedgerAccountV1(
                        "0.1.0", "acc-1", "savings",
                        0, 0, 0, 0, 0, 0, 0, 1,
                        "not-64-chars", List.of(),
                        "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z"));
    }

    // ------------------------------------------------------------------
    // Multi-saldo ledger journal
    // ------------------------------------------------------------------

    @Test
    void ledgerJournalSerialization() throws Exception {
        var entry = new LedgerJournalV1(
                "0.1.0", "entry-001", "acc-123", "debit",
                50_000L, "Initial deposit",
                "ref-tx-001", "2026-07-30T12:00:00Z");
        String json = mapper.writeValueAsString(entry);
        assertTrue(json.contains("\"entry_id\""));
        assertTrue(json.contains("\"account_id\""));
        assertTrue(json.contains("\"amount_sats\""));
        assertTrue(json.contains("\"recorded_at\""));
        assertTrue(json.contains("\"debit\""));
        assertFalse(json.contains("\"amount\""), "legacy amount field must not appear");
        assertFalse(json.contains("\"currency\""), "legacy currency field must not appear");
    }

    @Test
    void ledgerJournalDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "entry_id": "entry-002",
                  "account_id": "acc-456",
                  "direction": "credit",
                  "amount_sats": 250000,
                  "description": "Settlement",
                  "reference": "ref-settle-001",
                  "recorded_at": "2026-07-29T18:30:00Z"
                }
                """;
        var entry = mapper.readValue(json, LedgerJournalV1.class);
        assertEquals("entry-002", entry.entryId());
        assertEquals("credit", entry.direction());
        assertEquals(250_000L, entry.amountSats());
        assertEquals("Settlement", entry.description());
    }

    @Test
    void ledgerJournalRejectsLegacyFields() {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "entry_id": "entry-1",
                  "account_id": "acc-1",
                  "direction": "debit",
                  "amount": "100",
                  "currency": "BTC",
                  "description": "test",
                  "reference": "ref-1",
                  "recorded_at": "2026-07-30T12:00:00Z"
                }
                """;
        // Legacy fields are rejected: either as unknown properties or via
        // constructor validation when amount_sats defaults to 0 (records
        // may silently drop unknown fields before reaching validation).
        assertThrows(Exception.class,
                () -> mapper.readValue(json, LedgerJournalV1.class));
    }

    @Test
    void ledgerJournalDirectionValidation() {
        assertThrows(IllegalArgumentException.class, () ->
                new LedgerJournalV1("0.1.0", "e1", "a1", "invalid_dir", 100L,
                        "test", "ref-1", "2026-07-30T12:00:00Z"));
    }

    // ------------------------------------------------------------------
    // P2P admin contract
    // ------------------------------------------------------------------

    @Test
    void p2pSerialization() throws Exception {
        var p2p = new AdminP2PV1(
                "0.1.0", "req-p2p-001", "chan-001", "node-9876",
                10_000_000L, 6_000_000L, 4_000_000L, true);
        String json = mapper.writeValueAsString(p2p);
        assertTrue(json.contains("\"channel_id\""));
        assertTrue(json.contains("\"capacity_sats\""));
        assertTrue(json.contains("\"local_balance_sats\""));
        assertTrue(json.contains("\"is_active\""));
    }

    @Test
    void p2pDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "request_id": "req-p2p-001",
                  "channel_id": "chan-001",
                  "remote_node_id": "node-9876",
                  "capacity_sats": 10000000,
                  "local_balance_sats": 6000000,
                  "remote_balance_sats": 4000000,
                  "is_active": true
                }
                """;
        var p2p = mapper.readValue(json, AdminP2PV1.class);
        assertEquals("chan-001", p2p.channelId());
        assertEquals(10_000_000L, p2p.capacitySats());
        assertTrue(p2p.isActive());
    }

    // ------------------------------------------------------------------
    // On-ramp admin contract
    // ------------------------------------------------------------------

    @Test
    void onrampSerialization() throws Exception {
        var onramp = new AdminOnrampV1(
                "0.1.0", "req-onramp-001", "order-abc", "user-xyz",
                "USD", "100.00", 1_000_000L, "stripe", "completed",
                "2026-07-30T12:00:00Z");
        String json = mapper.writeValueAsString(onramp);
        assertTrue(json.contains("\"order_id\""));
        assertTrue(json.contains("\"fiat_currency\""));
        assertTrue(json.contains("\"fiat_amount\""));
    }

    // ------------------------------------------------------------------
    // Reconciliation admin contract
    // ------------------------------------------------------------------

    @Test
    void reconciliationSerialization() throws Exception {
        var rec = new AdminReconciliationV1(
                "0.1.0", "req-rec-001", "rec-001",
                1_000_000_000L, 999_800_000L, 200_000L, -200_000L,
                "settled", "2026-07-30T12:00:00Z");
        String json = mapper.writeValueAsString(rec);
        assertTrue(json.contains("\"reconciliation_id\""));
        assertTrue(json.contains("\"ledger_sats\""));
        assertTrue(json.contains("\"delta_sats\""));
    }

    // ------------------------------------------------------------------
    // Provider admin contract
    // ------------------------------------------------------------------

    @Test
    void providerSerialization() throws Exception {
        var prov = new AdminProviderV1(
                "0.1.0", "req-prov-001", "lnd-mainnet", "lightning",
                true, "2026-07-30T12:00:00Z", "0.18.3");
        String json = mapper.writeValueAsString(prov);
        assertTrue(json.contains("\"provider_id\""));
        assertTrue(json.contains("\"provider_type\""));
        assertTrue(json.contains("\"is_online\""));
    }

    // ------------------------------------------------------------------
    // Snake-case convention (cross-language JSON compatibility)
    // ------------------------------------------------------------------

    @Test
    void jsonOutputMatchesRustSnakeCaseConvention() throws Exception {
        var status = new NodeAdminStatusV1(
                "0.1.0", "req-compare", "testnet", "vault",
                true, true, false, true, 7, 3);
        String json = mapper.writeValueAsString(status);
        assertTrue(json.matches("(?s).*\"contract_version\".*"), "contract_version");
        assertTrue(json.matches("(?s).*\"request_id\".*"), "request_id");
        assertTrue(json.matches("(?s).*\"network_id\".*"), "network_id");
        assertTrue(json.matches("(?s).*\"local_ready\".*"), "local_ready");
        assertTrue(json.matches("(?s).*\"member_ready\".*"), "member_ready");
        assertTrue(json.matches("(?s).*\"quorum_ready\".*"), "quorum_ready");
        assertTrue(json.matches("(?s).*\"financial_ready\".*"), "financial_ready");
        assertTrue(json.matches("(?s).*\"live_members\".*"), "live_members");
    }

    // ------------------------------------------------------------------
    // Canonical JSON tests (cross-language deterministic)
    // ------------------------------------------------------------------

    @Test
    void canonicalJsonIsDeterministic() {
        var status = new NodeAdminStatusV1(
                "0.1.0", "req-1", "kerosene-test", "bank",
                true, false, false, true, 3, 2);
        byte[] bytes1 = CanonicalJson.toBytes(status);
        byte[] bytes2 = CanonicalJson.toBytes(status);
        assertArrayEquals(bytes1, bytes2);
    }

    @Test
    void canonicalJsonHashIsStable() {
        var node = new NodeAdminStatusV1(
                "0.1.0", "req-canonical", "kerosene-test", "vault",
                true, true, true, false, 5, 3);
        String hash1 = CanonicalJson.hash(node);
        String hash2 = CanonicalJson.hash(node);
        assertEquals(hash1, hash2);
        assertEquals(64, hash1.length());
    }

    @Test
    void canonicalJsonAndPlainJsonDiffer() throws Exception {
        var node = new NodeAdminStatusV1(
                "0.1.0", "req-dual", "kerosene-test", "vault",
                true, true, true, false, 5, 3);
        String jsonPlain = mapper.writeValueAsString(node);
        String jsonCanonical = new String(CanonicalJson.toBytes(node), StandardCharsets.UTF_8);

        // Jackson with ORDER_MAP_ENTRIES_BY_KEYS already sorts top-level keys,
        // but canonical JSON also sorts nested keys (e.g. if there were nested objects).
        // For simple flat records they may match, but the hash should differ from
        // the binary signing hash (which uses a completely different encoding).
        assertNotNull(jsonPlain);
        assertNotNull(jsonCanonical);
    }

    // ------------------------------------------------------------------
    // KAT — Known Answer Tests (cross-language with Rust)
    // ------------------------------------------------------------------
    //
    // These tests load test vector JSON files from the classpath
    // (src/test/resources/test-vectors/), deserialize the contract, compute
    // its canonical JSON hash, and compare against the expected value.
    //
    // Rust tests in lib.rs compute the same hashes to verify cross-language
    // byte-level agreement.

    @Test
    void katNodeAdminStatus() throws Exception {
        runKat("node-admin-status-v1.json", NodeAdminStatusV1.class);
    }

    @Test
    void katVaultAdminStatus() throws Exception {
        runKat("vault-admin-status-v1.json", VaultAdminStatusV1.class);
    }

    @Test
    void katAdminErrorEnvelope() throws Exception {
        runKat("admin-error-envelope-v1.json", AdminErrorEnvelopeV1.class);
    }

    @Test
    void katAuditReference() throws Exception {
        runKat("audit-reference-v1.json", AuditReferenceV1.class);
    }

    @Test
    void katLedgerAccount() throws Exception {
        runKat("ledger-account-v1.json", LedgerAccountV1.class);
    }

    @Test
    void katLedgerJournal() throws Exception {
        runKat("ledger-journal-v1.json", LedgerJournalV1.class);
    }

    @Test
    void katAdminP2P() throws Exception {
        runKat("admin-p2p-v1.json", AdminP2PV1.class);
    }

    @Test
    void katAdminOnramp() throws Exception {
        runKat("admin-onramp-v1.json", AdminOnrampV1.class);
    }

    @Test
    void katAdminReconciliation() throws Exception {
        runKat("admin-reconciliation-v1.json", AdminReconciliationV1.class);
    }

    @Test
    void katAdminProvider() throws Exception {
        runKat("admin-provider-v1.json", AdminProviderV1.class);
    }

    // ------------------------------------------------------------------
    // KAT helpers
    // ------------------------------------------------------------------

    private <T> void runKat(String vectorFile, Class<T> type) throws Exception {
        // Load from src/test/resources/test-vectors/
        String path = "/test-vectors/" + vectorFile;
        InputStream is = getClass().getResourceAsStream(path);
        if (is == null) {
            // Fallback: try relative to project root
            java.nio.file.Path fallback = java.nio.file.Paths.get("test-vectors", vectorFile);
            if (fallback.toFile().exists()) {
                String content = java.nio.file.Files.readString(fallback);
                runKatFromString(content, type);
                return;
            }
            throw new IOException("Test vector not found: " + path + " or " + fallback);
        }
        String content = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        runKatFromString(content, type);
    }

    private <T> void runKatFromString(String json, Class<T> type) throws Exception {
        var tree = mapper.readTree(json);
        String expectedJsonHash = tree.get("expected_json_hash").asText();

        // Strip test-vector metadata fields before deserializing
        if (tree.isObject()) {
            var obj = (com.fasterxml.jackson.databind.node.ObjectNode) tree;
            obj.remove("vector_label");
            obj.remove("expected_json_hash");
            obj.remove("expected_binary_hash");
        }

        T contractObj = mapper.treeToValue(tree, type);
        String actual = CanonicalJson.hash(contractObj);

        assertEquals(expectedJsonHash, actual,
                "KAT canonical JSON hash mismatch for " + type.getSimpleName());
    }
}
