package io.kerosene.contracts.security;

/** Workload identity plus routing data. The endpoint never grants trust. */
public record ServiceRosterMemberV1(WorkloadIdentityV1 identity, String endpoint) {
    public ServiceRosterMemberV1 {
        SecurityContract.require(identity != null, "identity is required");
        SecurityContract.requireEndpoint(endpoint);
    }
}
