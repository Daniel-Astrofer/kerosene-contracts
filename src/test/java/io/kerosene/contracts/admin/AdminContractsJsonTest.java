package io.kerosene.contracts.admin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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

    @Test
    void ledgerAccountSerialization() throws Exception {
        var account = new LedgerAccountV1(
                "0.1.0", "acc-123", "checking", "1000000",
                "BTC", List.of("hot", "operational"),
                "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z");
        String json = mapper.writeValueAsString(account);
        assertTrue(json.contains("\"account_id\""));
        assertTrue(json.contains("\"account_type\""));
        assertTrue(json.contains("\"created_at\""));
    }

    @Test
    void ledgerAccountDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "account_id": "acc-456",
                  "account_type": "savings",
                  "balance": "500000",
                  "currency": "BTC",
                  "tags": ["cold", "reserve"],
                  "created_at": "2026-03-15T00:00:00Z",
                  "updated_at": "2026-07-28T00:00:00Z"
                }
                """;
        var account = mapper.readValue(json, LedgerAccountV1.class);
        assertEquals("acc-456", account.accountId());
        assertEquals("savings", account.accountType());
        assertEquals("500000", account.balance());
        assertEquals(List.of("cold", "reserve"), account.tags());
    }

    @Test
    void ledgerJournalSerialization() throws Exception {
        var entry = new LedgerJournalV1(
                "0.1.0", "entry-001", "acc-123", "debit",
                "50000", "BTC", "Initial deposit",
                "ref-tx-001", "2026-07-30T12:00:00Z");
        String json = mapper.writeValueAsString(entry);
        assertTrue(json.contains("\"entry_id\""));
        assertTrue(json.contains("\"account_id\""));
        assertTrue(json.contains("\"recorded_at\""));
        assertTrue(json.contains("\"debit\""));
    }

    @Test
    void ledgerJournalDeserialization() throws Exception {
        String json = """
                {
                  "contract_version": "0.1.0",
                  "entry_id": "entry-002",
                  "account_id": "acc-456",
                  "direction": "credit",
                  "amount": "250000",
                  "currency": "BTC",
                  "description": "Settlement",
                  "reference": "ref-settle-001",
                  "recorded_at": "2026-07-29T18:30:00Z"
                }
                """;
        var entry = mapper.readValue(json, LedgerJournalV1.class);
        assertEquals("entry-002", entry.entryId());
        assertEquals("credit", entry.direction());
        assertEquals("250000", entry.amount());
        assertEquals("Settlement", entry.description());
    }

    @Test
    void jsonOutputMatchesRustSnakeCaseConvention() throws Exception {
        var status = new NodeAdminStatusV1(
                "0.1.0", "req-compare", "testnet", "vault",
                true, true, false, true, 7, 3);
        String json = mapper.writeValueAsString(status);
        // Verify all fields use snake_case as Rust's serde would produce
        assertTrue(json.matches("(?s).*\"contract_version\".*"), "contract_version");
        assertTrue(json.matches("(?s).*\"request_id\".*"), "request_id");
        assertTrue(json.matches("(?s).*\"network_id\".*"), "network_id");
        assertTrue(json.matches("(?s).*\"local_ready\".*"), "local_ready");
        assertTrue(json.matches("(?s).*\"member_ready\".*"), "member_ready");
        assertTrue(json.matches("(?s).*\"quorum_ready\".*"), "quorum_ready");
        assertTrue(json.matches("(?s).*\"financial_ready\".*"), "financial_ready");
        assertTrue(json.matches("(?s).*\"live_members\".*"), "live_members");
    }
}
