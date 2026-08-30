# Contratos seguros entre serviços v1

Versão do contrato: `0.3.0`. Estado: formato definido e testado entre
linguagens; ainda não significa que o tráfego de produção esteja protegido.

## O que cada contrato resolve

`WorkloadIdentityV1` liga uma chave Ed25519 de aplicação a um SPIFFE ID, papel,
instância, rede e validade. Ele não contém fingerprint do certificado porque o
SVID X.509 deve girar automaticamente sem trocar a identidade lógica. O servidor
sempre compara o SPIFFE ID do contrato com o URI SAN exato observado na conexão
mTLS atual.

`SignedServiceRosterV1` publica identidades e endpoints. Endpoint é somente
localização; não concede confiança e não pode ser usado como URL arbitrária.
O roster aponta para o hash de um `MembershipManifestV1` estável e previamente
confiável. Os signatários e o quorum vêm desse manifest anterior, nunca do roster
novo. Assim, um atacante não pode criar um roster e autorizar a si mesmo.

`SigningIntentV1` autoriza uma única tentativa limitada de assinatura de PSBT
do KFE para um Vault. Ele vincula:

- requisição, intent, wallet e rede Bitcoin;
- workload e SPIFFE ID exatos de KFE e Vault;
- hashes dos dois rosters;
- PSBT, destino e descriptor de troco;
- política, epoch da política e epoch dos participantes FROST;
- valor, taxa máxima, fee rate, quantidade de inputs e modo de commit;
- evidência de autorização, nonce, sequência e janela de 60 segundos.

Assinatura genérica de mensagens não pertence a este contrato.

## Bytes e assinaturas

Todos os inteiros usam 8 bytes big-endian e cada campo variável recebe prefixo
de tamanho. A assinatura Ed25519 é feita sobre `signingBytes()`/
`signing_bytes()`, com separação de domínio, e nunca sobre JSON arbitrário.
Membros e assinaturas do roster precisam estar estritamente ordenados pelo ID.

`psbt_sha256` é SHA-256 dos bytes exatos da PSBT depois de decodificar o Base64,
antes de parser ou normalização. `authorization_hash` é SHA-256 dos bytes ASCII
exatos do JWS compacto delegado. O hash do descriptor usa a forma canônica com
checksum.

## Anti-replay obrigatório no consumidor

O contrato carrega os dados, mas KFE/Vault devem persistir seu consumo de forma
atômica:

- `(network_id, issuer_workload_id, request_id)` identifica uma tentativa;
- `(network_id, issuer_workload_id, intent_id)` identifica a operação financeira;
- nonce só pode ser consumido uma vez;
- sequence cresce estritamente por
  `(network_id, issuer_workload_id, wallet_id)`;
- repetição byte a byte retorna o resultado já gravado;
- repetição com conteúdo diferente é conflito e falha fechada;
- reserva, assinatura e gravação do resultado precisam sobreviver a restart.

## O que ainda falta para produção

Os contratos não implementam mTLS, emissão SPIRE, verificação Ed25519, banco de
anti-replay, validação independente da PSBT ou transporte de discovery. Cada
serviço precisa consumir esta mesma revisão imutável e provar CA/SAN incorretos,
roster expirado ou forjado, assinatura inválida, replay concorrente e após
restart, PSBT alterada, policy/epoch divergentes e taxas fora dos limites.
