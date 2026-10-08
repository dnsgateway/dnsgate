# Onboarding sends the Provider Credential over TLS, not encrypted to the Gateway's key

During Onboarding the CLI sends the Provider Credential and the bootstrap secret in plaintext inside the gRPC request, protected only by the TLS connection to the Gateway. The CLI does not first encrypt the credential to the Gateway's X25519 public encryption key. The Gateway decrypts any such envelope the moment it arrives, so the envelope would protect the credential only on the network path, which TLS already covers. It would add a second key for Administrators to fetch and trust, and a CLI fetching it from the Gateway over the same connection would gain nothing over TLS.

## Considered Options

- Encrypting the credential to the Gateway's public encryption key (a JWE the CLI builds): rejected for v1. It protects the credential only from something that terminates TLS between the CLI and the Gateway, such as a load balancer or ingress. That is covered more simply by requiring TLS to end at the Gateway. To be worth it, the CLI would need the public key from a channel independent of the connection it protects, and keeping that key current would tie Administrators to encryption key rotation.

## Consequences

- TLS must terminate at the Gateway itself. A proxy that terminates TLS in front of the Gateway sees every Provider Credential and the bootstrap secret onboarded through it. The `onboard` help says so.
- The CLI verifies the Gateway's certificate against the system's CA certificates or a CA file given with `--ca-file`, and offers no way to skip verification.
- The credential crosses the wire in plaintext inside TLS only at Onboarding, as before (ADR 0001). Every other request carries it only sealed in a Service Token.
- Credential encryption can be added later without an API break, as a new field of `OnboardRequest` next to the plaintext `credential`.
