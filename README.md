# DNS API Gateway

DNS Gateway is a proposed security layer between applications and DNS providers. It aims to let applications manage only the DNS records they need, without giving them the provider's main API key.

## Why it matters

DNS provider API keys can give broad access to an account. Sharing these keys with several applications makes it harder to control access and stop it when needed.

DNS Gateway aims to keep provider secrets private and give each application limited access. For example, a tool that creates certificates could update its DNS verification records without being able to change other records.

## How it works

Applications send DNS requests to the gateway. The gateway checks who is making the request and whether they have permission. It then sends approved requests to the DNS provider.

Administrators control which applications can use the gateway and what each application can do. Access can be limited to specific domains, record names, record types, and actions.

## Planned features

- **Limited access:** Give each application permission to manage only the DNS records it needs.
- **Private provider keys:** Use provider credentials without sharing their contents with applications.
- **Access control:** Remove or renew an application's access without changing the provider's main API key.
- **Activity history:** Record DNS operations and their results without recording secrets.
- **Flexible connections:** Connect to providers from the gateway or through an approved client network. This helps with providers that allow access only from certain IP addresses.
- **Workload identity:** Support identity checks for applications, starting with Kubernetes.
- **Certificate automation:** Allow certificate tools to create and remove DNS verification records within approved domains.

## Who it is for

DNS Gateway is intended for teams that use tools such as `external-dns`, `cert-manager`, Terraform, and certificate automation tools. It could also support automated build and deployment jobs, internal applications, and people who manage DNS records.
