# Self-contained Service Tokens carry the Provider Credential and permissions

Every Service Token carries the Provider Credential and the token's permissions inside it. The token is signed and then encrypted by the Gateway (`JWE(JWS(claims))`), and only the Gateway can create or read one. The Gateway stores no Provider Credentials, policies or token records. Its only persistent authorization state is the list of revoked token IDs. We chose this over a Gateway-side secret store with central policy so that compromising the Gateway's database reveals no provider secrets, and the Gateway needs no secret-store infrastructure.

## Consequences

- An Administrator handles the plaintext Provider Credential only once, at Onboarding, which produces a Root Token. Onboarding requires a bootstrap secret configured on the Gateway.
- New tokens are Derived Tokens. They are issued by presenting a Parent Token whose permissions allow issuing, and they must be strictly narrower on every dimension. Their expiry can be no later than the Parent Token's.
- Each token carries the IDs of all its ancestors. Revoking a token revokes all of its descendants without the Gateway keeping a token registry.
- With no token registry, the Gateway cannot tell which tokens descend from which. So any token with permission to revoke tokens can revoke any token ID, including tokens in other chains. Token listing is unavailable until a registry exists.
- Changing permissions or rotating the Provider Credential means issuing new tokens. Rotating the Provider Credential means Onboarding again.
- Rotating the Gateway's encryption key means resealing existing tokens under the new key. Old keys are retired after a set deadline.
- Anyone holding the Gateway's signing and decryption keys can mint tokens and recover every Provider Credential. These keys are the system's most sensitive asset.
