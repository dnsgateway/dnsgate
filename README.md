# DNS API Gateway

DNS Gateway is a security layer between applications and DNS providers. It lets each application manage only the DNS records it is permitted to, without ever handing it the Provider Credential.

## Why it matters

A Provider Credential can give broad access to a DNS account. Sharing it with several applications makes it harder to control access and stop it when needed.

DNS Gateway keeps the Provider Credential out of applications and gives each one limited access. For example, a tool that creates certificates can update its DNS verification records without being able to change other records.

## How it works

An Administrator onboards a Provider Credential into the Gateway, which turns it into a Root Token. From a Service Token whose Permissions allow issuing, the Administrator issues Derived Tokens, one per Service Account.

Applications send DNS requests to the Gateway over gRPC and present their Service Token. The Gateway checks the token and its Permissions, then carries out approved requests against the Provider. Permissions can limit access to specific zones, record name patterns, record types, verbs and Egress.

## Features

- **Limited access:** Each Service Token carries Permissions that grant only the DNS records it needs. A Derived Token never gets more than its Parent Token (Narrowing).
- **Provider Credentials kept out of clients:** The Provider Credential travels sealed inside the Service Token, which only the Gateway can open. Applications never see it in plaintext.
- **Revocation:** Revoking a Service Token invalidates it and every token derived from it, without changing the Provider Credential.
- **Activity history:** The Gateway writes an audit trail of every DNS operation and its result, without recording Provider Credentials or Service Tokens.
- **Agent Egress:** A Provider can be reached from the Gateway (Gateway Egress) or through the application, acting as Egress Agent, so the Provider sees the application's IP address. This helps with Providers that allow access only from certain IP addresses. TLS runs end to end between the Gateway and the Provider.
- **Resealing:** After the Gateway's encryption key is rotated, existing Service Tokens can be Resealed under the new key without changing their identity or Permissions.

The first Provider is Cloudflare, with an API token as the Provider Credential.

## Planned features

- **Workload identity:** Bind a Service Token to a workload's identity, starting with Kubernetes ServiceAccounts, GitHub Actions and GitLab CI ([ADR 0004](docs/adr/0004-identity-binding-in-service-tokens.md)).
- **Certificate automation:** An ACME Endpoint that lets existing ACME clients create DNS verification records within approved domains ([ADR 0003](docs/adr/0003-acme-endpoint.md)).
- **More Providers:** Providers other than Cloudflare, and other kinds of Provider Credential.
- **More Permission constraints:** TTL bounds, record value restrictions, rate limits and source CIDRs.
- **Adapters:** an external-dns webhook provider and Terraform.
- **Scale and key storage:** PostgreSQL, multiple Gateway replicas, KMS for the Gateway's keys, and a token registry with `token list`.
- **Egress Agent hostname allowlist:** A client-side list of Provider hosts the Egress Agent may connect to.

## Who it is for

DNS Gateway is intended for teams that use tools such as `external-dns`, `cert-manager`, Terraform, and certificate automation tools. It could also support automated build and deployment jobs, internal applications, and people who manage DNS records.
