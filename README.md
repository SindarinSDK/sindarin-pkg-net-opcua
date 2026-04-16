# sindarin-pkg-net-opcua

Production-grade OPC UA client for the [Sindarin](https://github.com/SindarinSDK/sindarin-compiler) programming language, backed by [open62541](https://open62541.org/) with OpenSSL crypto. Exposes the full OPC UA security surface — all six security policies, all three message security modes, all three user identity types — plus discovery, attribute services, browse, methods, and subscriptions.

## Installation

Add to your `sn.yaml`:

```yaml
dependencies:
- name: sindarin-pkg-net-opcua
  git: git@github.com:SindarinSDK/sindarin-pkg-net-opcua.git
  branch: main
```

Then `sn --install`.

## Quick start

### Anonymous, unsecured (discovery / dev only)

```sindarin
import "sindarin-pkg-net-opcua/src/opcua"

fn main(): void =>
    var client: OpcUaClient = OpcUaClient.connect("opc.tcp://localhost:4840")
    var v: OpcUaVariant = client.readValue(OpcUaNodeId.numeric(0, 2258))
    print($"Server CurrentTime: {v.asLong()}\n")
    client.disconnect()
```

### Signed and encrypted with username/password

```sindarin
import "sindarin-pkg-net-opcua/src/opcua"

fn main(): void =>
    var trust: OpcUaTrustList = OpcUaTrustList.loadFromDir("pki")

    var config: OpcUaClientConfig = OpcUaClientConfig.defaults()
        .setSecurityPolicy(OpcUaSecurityPolicy.basic256Sha256())
        .setMessageSecurityMode(OpcUaMessageSecurityMode.signAndEncrypt())
        .setUserIdentity(OpcUaUserIdentity.usernamePassword("alice", "secret"))
        .setClientCertificate("pki/client/cert.pem", "pki/client/key.pem")
        .setTrustList(trust)

    var client: OpcUaClient = OpcUaClient.connectWith("opc.tcp://prod:4840", config)
    client.writeValue(OpcUaNodeId.stringId(2, "SetPoint"), OpcUaVariant.fromDouble(42.5))
    client.disconnect()
```

### Discovery (no session)

```sindarin
var endpoints: OpcUaEndpointDescription[] =
    OpcUaClient.getEndpoints("opc.tcp://server:4840")
for ep in endpoints =>
    print($"{ep.endpointUrl()} — policy={ep.securityPolicyUri()} mode={ep.securityMode()}\n")
```

---

## Supported security policies

| Policy | Status | URI suffix |
|---|---|---|
| `OpcUaSecurityPolicy.none()` | None (plaintext) | `#None` |
| `OpcUaSecurityPolicy.basic128Rsa15()` | Deprecated | `#Basic128Rsa15` |
| `OpcUaSecurityPolicy.basic256()` | Deprecated | `#Basic256` |
| `OpcUaSecurityPolicy.basic256Sha256()` | Current baseline | `#Basic256Sha256` |
| `OpcUaSecurityPolicy.aes128Sha256RsaOaep()` | Modern | `#Aes128_Sha256_RsaOaep` |
| `OpcUaSecurityPolicy.aes256Sha256RsaPss()` | Strongest modern | `#Aes256_Sha256_RsaPss` |

Message security modes (orthogonal): `none()`, `sign()`, `signAndEncrypt()`.

User identity tokens: `anonymous()`, `usernamePassword(u, p)`, `certificate(certPath, keyPath)`, `issuedToken(bytes, type)`.

---

## Subscriptions

The client uses a background thread to drive `UA_Client_run_iterate()`. Monitored-item notifications are queued per subscription; drain them with `nextEvent(timeoutMs)`:

```sindarin
var sub: OpcUaSubscription = client.createSubscription(250.0)
var item: OpcUaMonitoredItem = sub.monitor(OpcUaNodeId.stringId(2, "Demo.Counter"))

while true =>
    var ev: OpcUaDataChangeEvent = sub.nextEvent(5000)
    if ev.isEmpty() => break
    print($"item {ev.monitoredItemId()} = {ev.value().toString()}\n")

sub.delete()
```

---

## PKI / trust list

The trust list expects the standard OPC UA PKI directory layout:

```
<pki_root>/
  trusted/
    certs/    *.der or *.pem — server certs to trust
    crl/      *.crl           — revocation lists for trusted certs
  issuers/
    certs/    *.der or *.pem — intermediate CAs
    crl/      *.crl           — revocation lists for issuers
```

Use `OpcUaTrustList.loadFromDir(path)` to populate from disk or `OpcUaTrustList.new().addTrusted(cert).addIssuer(ca).addRevocation(crlBytes)` to build programmatically.

`OpcUaTrustList.noVerification()` disables server certificate validation for test-only use. A warning is emitted at connect time.

---

## Development

```bash
# Install deps + download prebuilt native libs from S3 + generate test PKI
make setup

# Run the test suite
make test

# Build native libs from source via vcpkg (takes minutes; only needed for releases)
make build
```

Tests spin up an in-process open62541 server on `localhost` and require no external services.

### Releases

Pushing a `v0.0.X` tag triggers the shared release pipeline (`sindarin-lib-release.yml`) which builds open62541 for linux-x64/arm64, macos-x64/arm64 and windows-x64 via vcpkg and publishes archives to S3. Normal PRs and pushes to `main` download those archives instead of rebuilding, so CI is fast.

## Dependencies

- [sindarin-pkg-sdk](https://github.com/SindarinSDK/sindarin-pkg-sdk) — stdlib
- [sindarin-pkg-test](https://github.com/SindarinSDK/sindarin-pkg-test) — test runner
- [open62541](https://github.com/open62541/open62541) — statically linked via vcpkg (MPL-2.0)
- [OpenSSL](https://www.openssl.org/) — statically linked via vcpkg (Apache-2.0)

## License

MIT for this package. Linked third-party components are licensed as noted in `LICENSE`.
