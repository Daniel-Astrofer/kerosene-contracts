# DTO Schema Index

> **Historical / deprecated index.** This inventory was copied from the former
> monorepo and is retained for migration reference. It is not the canonical
> source for current endpoint DTOs. Current endpoint documentation belongs to
> `kerosene-core/docs/backend/api/`; versioned cross-repository schemas belong
> in this repository under `schemas/`.

Índice auxiliar dos DTOs usados pelos endpoints documentados.

Este arquivo não é a documentação operacional de API. Para entender um
endpoint, consulte `kerosene-core/docs/backend/api/`, especialmente
`kerosene-core/docs/backend/api/KFE.md` para fluxos financeiros.

Fonte técnica histórica: DTOs Java em
`kerosene-core/auth-service/src/main/java/com/kerosene/**` e
`kerosene-kfe/src/main/java/com/kerosene/kfe/**`.

Regra KFE-only: DTOs financeiros legados removidos não devem aparecer neste índice como schemas ativos.

## `AccountActivationStatusDTO`

Fonte histórica: `AccountActivationStatusDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AccountActivationStatusDTO.java`.

- `boolean activated`
- `boolean canReceiveInbound`
- `boolean requiresActivationDeposit`
- `BigDecimal requiredAmountBtc`
- `String paymentLinkId`
- `String depositAddress`
- `String paymentStatus`
- `String warningMessage`
- `LocalDateTime activatedAt`

## `AccountSecurityProfileDTO`

Fonte histórica: `AccountSecurityProfileDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AccountSecurityProfileDTO.java`.

- `AccountSecurityType accountSecurity`
- `Integer shamirTotalShares`
- `Integer shamirThreshold`
- `Integer multisigThreshold`
- `boolean passkeyAvailable`
- `boolean passkeyEnabledForTransactions`
- `AppPinStatusDTO appPin`
- `List<String> requiredFactors`
- `PasskeyInventoryDTO passkeys`

## `AccountSecurityStatusDTO`

Fonte histórica: `AccountSecurityStatusDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AccountSecurityStatusDTO.java`.

- `boolean passwordConfigured`
- `boolean passkeyRegistered`
- `boolean totpEnabled`
- `int backupCodesRemaining`
- `boolean unprotected`
- `String warningMessage`
- `boolean accountActivated`
- `boolean inboundEnabled`
- `PasskeyInventoryDTO passkeys`

## `AccountSecurityUpdateRequestDTO`

Fonte histórica: `AccountSecurityUpdateRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AccountSecurityUpdateRequestDTO.java`.

- `accountSecurity: AccountSecurityType`
- `shamirTotalShares: Integer`
- `shamirThreshold: Integer`
- `multisigThreshold: Integer`

## `AdminAccessAttemptDTO`

Fonte histórica: `AdminAccessAttemptDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminAccessAttemptDTO.java`.

- `UUID attemptId`
- `String status`
- `String deviceId`
- `String deviceName`
- `String browser`
- `String userAgent`
- `String ipFingerprint`
- `LocalDateTime requestedAt`
- `LocalDateTime expiresAt`

## `AdminAccessDecisionRequestDTO`

Fonte histórica: `AdminAccessDecisionRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminAccessDecisionRequestDTO.java`.

- `decision: String`

## `AdminAuthenticatedDeviceDTO`

Fonte histórica: `AdminAuthenticatedDeviceDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminAuthenticatedDeviceDTO.java`.

- `String deviceId`
- `String deviceName`
- `String browser`
- `String userAgent`
- `String status`
- `LocalDateTime firstAccessAt`
- `LocalDateTime lastAccessAt`

## `AdminKeyCreateRequestDTO`

Fonte histórica: `AdminKeyCreateRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminKeyCreateRequestDTO.java`.

- `keyMaterialHash: String`
- `deviceInstallId: String`

## `AdminKeyStatusDTO`

Fonte histórica: `AdminKeyStatusDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminKeyStatusDTO.java`.

- `boolean configured`
- `String status`
- `String fingerprint`
- `LocalDateTime createdAt`
- `LocalDateTime revokedAt`

## `AdminLoginRequestDTO`

Fonte histórica: `AdminLoginRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminLoginRequestDTO.java`.

- `username: String`
- `adminKeyProof: String`
- `deviceId: String`
- `deviceName: String`
- `browser: String`
- `userAgent: String`
- `platform: String`

## `AdminLoginResponseDTO`

Fonte histórica: `AdminLoginResponseDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AdminLoginResponseDTO.java`.

- `String status`
- `boolean requiresMobileApproval`
- `UUID attemptId`
- `LocalDateTime expiresAt`
- `String token`
- `String message`

## `AppPinStatusDTO`

Fonte histórica: `AppPinStatusDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/AppPinStatusDTO.java`.

- `boolean enabled`
- `boolean configured`
- `boolean locked`
- `int failedAttempts`
- `int remainingAttempts`
- `int maxAttempts`
- `int minPinLength`
- `int maxPinLength`
- `boolean resettableWithTotp`
- `boolean deviceScoped`
- `LocalDateTime lockedUntil`
- `LocalDateTime lastVerifiedAt`
- `LocalDateTime updatedAt`

## `BackupCodesStatusDTO`

Fonte histórica: `BackupCodesStatusDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/BackupCodesStatusDTO.java`.

- `boolean enabled`
- `int remainingCodes`
- `List<String> newlyGeneratedCodes`

## `ConfigureAppPinRequestDTO`

Fonte histórica: `ConfigureAppPinRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/ConfigureAppPinRequestDTO.java`.

- `enabled: Boolean`
- `pin: String`
- `currentPin: String`
- `totpCode: String`

## `DeviceKeyChallengeResponse`

Fonte histórica: `DeviceKeyChallengeResponse.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/devicekey/DeviceKeyChallengeResponse.java`.

- `String challengeId`
- `String challenge`
- `long expiresInSeconds`
- `String onionServiceId`
- `String algorithm`
- `String canonicalization`

## `DeviceKeyDeviceDTO`

Fonte histórica: `DeviceKeyDeviceDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/devicekey/DeviceKeyDeviceDTO.java`.

- `String credentialId`
- `String deviceName`
- `String deviceInstallId`
- `String keyStorage`
- `String platform`
- `String browser`
- `String onionServiceId`
- `String status`
- `long counter`
- `LocalDateTime createdAt`
- `LocalDateTime lastUsedAt`
- `LocalDateTime revokedAt`
- `int protocolVersion`

## `DeviceKeyRegistrationRequest`

Fonte histórica: `DeviceKeyRegistrationRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/devicekey/DeviceKeyRegistrationRequest.java`.

- `publicKey: String`
- `publicKeySha256: String`
- `credentialId: String`
- `userHandle: String`
- `deviceName: String`
- `deviceInstallId: String`
- `keyStorage: String`
- `platform: String`
- `browser: String`
- `brand: String`
- `model: String`
- `serialNumber: String`
- `signedPayload: String`
- `signature: String`

## `DeviceKeyVerifyRequest`

Fonte histórica: `DeviceKeyVerifyRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/devicekey/DeviceKeyVerifyRequest.java`.

- `username: String`
- `credentialId: String`
- `deviceInstallId: String`
- `signedPayload: String`
- `signature: String`

## `DeviceTokenRegisterRequest`

Fonte histórica: `DeviceTokenRegisterRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/notification/dto/DeviceTokenRegisterRequest.java`.

- `String platform`
- `String token`
- `String deviceId`
- `String appVersion`

## `DeviceTokenResponse`

Fonte histórica: `DeviceTokenResponse.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/notification/dto/DeviceTokenResponse.java`.

- `Long id`
- `String platform`
- `String tokenRef`
- `String deviceRef`
- `String appVersion`
- `LocalDateTime createdAt`
- `LocalDateTime lastSeenAt`
- `LocalDateTime revokedAt`
- `boolean active`

## `EmergencyRecoveryFinishRequest`

Fonte histórica: `EmergencyRecoveryFinishRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/EmergencyRecoveryFinishRequest.java`.

- `recoverySessionId: String`
- `totpCode: String`
- `publicKey: String`
- `publicKeyCose: String`
- `deviceName: String`
- `signature: String`
- `authData: String`
- `clientDataJSON: String`
- `credentialId: String`
- `userHandle: String`

## `EmergencyRecoveryFinishResponse`

Fonte histórica: `EmergencyRecoveryFinishResponse.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/EmergencyRecoveryFinishResponse.java`.

- `username: String`
- `newBackupCodes: List<String>`

## `EmergencyRecoveryStartRequest`

Fonte histórica: `EmergencyRecoveryStartRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/EmergencyRecoveryStartRequest.java`.

- `username: String`
- `recoveryCodes: List<String>`
- `challenge: String`
- `nonce: String`

## `EmergencyRecoveryStartResponse`

Fonte histórica: `EmergencyRecoveryStartResponse.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/EmergencyRecoveryStartResponse.java`.

- `recoverySessionId: String`
- `otpUri: String`
- `passkeyChallenge: String`
- `expiresInSeconds: long`
- `requiredRecoveryCodes: int`

## `KfeAddressResponse`

Fonte histórica: `KfeAddressResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeAddressResponse.java`.

- `UUID id`
- `UUID walletId`
- `String address`
- `KfeWalletAddressRole role`
- `KfeWalletAddressStatus status`
- `String derivationPath`
- `Integer derivationIndex`
- `String providerReference`
- `LocalDateTime createdAt`
- `LocalDateTime retiredAt`

## `KfeAuditEventResponse`

Fonte histórica: `KfeAuditEventResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeAuditEventResponse.java`.

- `Long sequenceNumber`
- `UUID id`
- `UUID transactionId`
- `UUID walletId`
- `String eventType`
- `String fromStatus`
- `String toStatus`
- `String payloadHash`
- `String previousHash`
- `String eventHash`
- `LocalDateTime createdAt`

## `KfeAuditLatestResponse`

Fonte histórica: `KfeAuditLatestResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeAuditLatestResponse.java`.

- `KfeAuditEventResponse latestEvent`
- `KfeAuditRootResponse root`

## `KfeAuditRootResponse`

Fonte histórica: `KfeAuditRootResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeAuditRootResponse.java`.

- `String merkleRoot`
- `long eventCount`
- `Long fromSequence`
- `Long toSequence`
- `LocalDateTime generatedAt`

## `KfeColdWalletPsbtRequest`

Fonte histórica: `KfeColdWalletPsbtRequest.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeColdWalletPsbtRequest.java`.

- `@NotBlank @Size(max = 128) String destinationAddress`
- `@Min(546) long amountSats`
- `@Min(1) Integer confirmationTarget`
- `@Min(1) Long feeRateSatsPerVbyte`
- `@Valid List<Input> inputs`

## `KfeColdWalletPsbtResponse`

Fonte histórica: `KfeColdWalletPsbtResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeColdWalletPsbtResponse.java`.

- `String psbt`
- `String psbtHash`
- `long feeSats`
- `long amountSats`
- `String destinationAddress`
- `List<KfeColdWalletPsbtRequest.Input> inputs`

## `KfeCreateWalletRequest`

Fonte histórica: `KfeCreateWalletRequest.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeCreateWalletRequest.java`.

- `@NotNull KfeWalletKind kind`
- `KfeWalletName name`
- `@Size(max = 96) String label`
- `String xpub`
- `String descriptor`
- `String fingerprint`
- `String derivationPath`
- `String initialAddress`
- `String initialAddressDerivationPath`
- `Integer initialAddressDerivationIndex`
- `String initialAddressProviderReference`
- `Boolean issueInitialAddress`

## `KfeDashboardResponse`

Fonte histórica: `KfeDashboardResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeDashboardResponse.java`.

- `List<KfeDashboardWallet> wallets`
- `List<KfeStatementItem> recentStatement`
- `long totalSpendableSats`
- `long totalObservedSats`
- `long totalVisibleSats`

## `KfeReceivingCapabilitiesResponse`

Fonte histórica: `KfeReceivingCapabilitiesResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeReceivingCapabilitiesResponse.java`.

- `boolean canReceiveInternal`
- `boolean canReceiveLightning`
- `boolean canReceiveOnchain`
- `String preferredRail`
- `List<String> missingRequirements`
- `String receiverDisplayName`
- `UUID internalWalletId`
- `List<String> availableRails`
- `Limits limits`

## `KfeSubmitTransactionRequest`

Fonte histórica: `KfeSubmitTransactionRequest.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeSubmitTransactionRequest.java`.

- `@NotBlank String idempotencyKey`
- `@NotNull KfeRail rail`
- `@NotNull KfeDirection direction`
- `UUID sourceWalletId`
- `UUID destinationWalletId`
- `@Min(1) long amountSats`
- `@Min(0) long networkFeeSats`
- `String externalReference`
- `String memo`
- `String totpCode`
- `String passkeyAssertionJson`
- `String confirmationPassphrase`

## `KfeTransactionResponse`

Fonte histórica: `KfeTransactionResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeTransactionResponse.java`.

- `UUID id`
- `KfeTransactionStatus status`
- `KfeRail rail`
- `KfeDirection direction`
- `UUID sourceWalletId`
- `UUID destinationWalletId`
- `long grossAmountSats`
- `long receiverAmountSats`
- `long networkFeeSats`
- `long keroseneFeeSats`
- `long totalDebitSats`
- `String quorumProposalHash`
- `int quorumAckCount`
- `String providerReference`
- `String blockchainTxid`
- `String failureCode`
- `String failureMessage`
- `LocalDateTime createdAt`
- `LocalDateTime updatedAt`

## `KfeUtxoResponse`

Fonte histórica: `KfeUtxoResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeUtxoResponse.java`.

- `String txid`
- `int vout`
- `long valueSats`
- `String scriptPubKey`
- `String address`

## `KfeWalletNameOption`

Fonte histórica: `KfeWalletNameOption.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeWalletNameOption.java`.

- `KfeWalletName name`
- `String label`

## `KfeWalletResponse`

Fonte histórica: `KfeWalletResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeWalletResponse.java`.

- `UUID id`
- `KfeWalletKind kind`
- `KfeWalletStatus status`
- `String label`
- `String walletName`
- `String walletTypeDescription`
- `String asset`
- `boolean spendable`
- `boolean xpubConfigured`
- `boolean mpcKeyConfigured`
- `String activeAddress`
- `LocalDateTime createdAt`
- `LocalDateTime updatedAt`

<!-- Mining DTOs removed: MiningAllocationRequestDTO, MiningAllocationResponseDTO, MiningRigOfferDTO — controller and module removed from codebase -->
- `BigDecimal availableHashrate`
- `BigDecimal pricePerUnitDayBtc`
- `BigDecimal projectedBtcYieldPerUnitDay`
- `Integer minRentalHours`
- `Integer maxRentalHours`
- `String provider`

## `PasskeyInventoryDTO`

Fonte histórica: `PasskeyInventoryDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/PasskeyInventoryDTO.java`.

- `boolean passkeyRegistered`
- `boolean compatibleForCurrentLogin`
- `boolean legacyCredentialsPresent`
- `String currentRelyingPartyId`
- `String currentHost`
- `List<PasskeyDeviceDTO> devices`

## `PasskeyRegistrationRequest`

Fonte histórica: `PasskeyRegistrationRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/passkey/PasskeyRegistrationRequest.java`.

- `publicKey: String`
- `deviceName: String`
- `signature: String`
- `authData: String`
- `clientDataJSON: String`
- `credentialId: String`
- `userHandle: String`
- `publicKeyCose: String`
- `brand: String`
- `model: String`
- `serialNumber: String`
- `deviceInstallId: String`
- `platform: String`
- `browser: String`
- `status: String`

## `PasskeyVerifyRequest`

Fonte histórica: `PasskeyVerifyRequest.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/passkey/PasskeyVerifyRequest.java`.

- `username: String`
- `signature: String`
- `authData: String`
- `clientDataJSON: String`
- `credentialId: String`

## `SignupResponseDTO`

Fonte histórica: `SignupResponseDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/SignupResponseDTO.java`.

- `sessionId: String`
- `otpUri: String`
- `backupCodes: List<String>`
- `totpOptional: boolean`

## `SignupTotpVerifyRequestDTO`

Fonte histórica: `SignupTotpVerifyRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/SignupTotpVerifyRequestDTO.java`.

- `sessionId: String`
- `totpCode: String`

## `TotpSetupResponseDTO`

Fonte histórica: `TotpSetupResponseDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/TotpSetupResponseDTO.java`.

- `String otpUri`
- `String secret`

## `KfeReserveOverviewResponse`

Fonte histórica: `KfeReserveOverviewResponse.java` — `kerosene-kfe/src/main/java/com/kerosene/kfe/dto/KfeReserveOverviewResponse.java`.

- `BigDecimal totalOnchainBtc`
- `BigDecimal lightningNodeBtc`
- `BigDecimal inboundLiquidityBtc`
- `BigDecimal outboundLiquidityBtc`
- `BigDecimal reservedOnchainBtc`
- `BigDecimal reservedLightningBtc`
- `BigDecimal availableOnchainBtc`
- `BigDecimal availableLightningBtc`
- `boolean lightningSendsAllowed`
- `String liquidityState`

## `UserDTO`

Fonte histórica: `UserDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/UserDTO.java`.

- `username: String`
- `totpSecret: String`
- `totpCode: String`
- `voucherCode: String`
- `challenge: String`
- `nonce: String`
- `preAuthToken: String`
- `sessionId: String`
- `accountSecurity: AccountSecurityType`
- `shamirTotalShares: Integer`
- `shamirThreshold: Integer`
- `multisigThreshold: Integer`
- `backupCodes: java.util.List<String>`

## `VerifyAppPinRequestDTO`

Fonte histórica: `VerifyAppPinRequestDTO.java` — `kerosene-core/auth-service/src/main/java/com/kerosene/auth/dto/VerifyAppPinRequestDTO.java`.

- `pin: String`
