# Terraform CLI Configuration

This guide explains how to configure the Terraform CLI to authenticate with and use this registry for **modules**, **providers** (via the network mirror protocol), and the **provider registry protocol**.

## Table of Contents

1. [CLI Config File Location](#cli-config-file-location)
2. [Authentication (credentials block)](#authentication-credentials-block)
3. [Using Modules from This Registry](#using-modules-from-this-registry)
4. [Using Providers via Network Mirror](#using-providers-via-network-mirror)
5. [TLS Trust for Private Deployments](#tls-trust-for-private-deployments)
6. [Verifying the Configuration](#verifying-the-configuration)

---

## CLI Config File Location

Terraform reads CLI configuration from:

| OS | Default path | Override env var |
|---|---|---|
| Windows | `%APPDATA%\terraform.rc` | `TF_CLI_CONFIG_FILE` |
| Linux / macOS | `~/.terraformrc` | `TF_CLI_CONFIG_FILE` |

If `TF_CLI_CONFIG_FILE` is set (e.g. in a CI environment or custom wrapper), that path takes precedence over the default. Ensure your `credentials` and `provider_installation` blocks are in whichever file Terraform is actually reading — check `TF_LOG=DEBUG terraform init` output for the line:

```
[INFO]  Loading CLI configuration from <path>
```

---

## Authentication (credentials block)

Add a `credentials` block for the hostname of your registry. This token is sent as a `Bearer` header to all authenticated registry requests.

```hcl
credentials "registry.example.com" {
  token = "tfr_your_api_key_here"
}
```

Generate an API key from the registry's web UI under **API Keys**, or via the API:

```bash
curl -X POST https://registry.example.com/api/v1/apikeys \
  -H "Authorization: Bearer tfr_admin_key" \
  -H "Content-Type: application/json" \
  -d '{"name": "terraform-cli", "scopes": ["modules:read", "providers:read"]}'
```

The `credentials` block alone is sufficient for **module downloads** — no `provider_installation` block is needed for modules.

---

## Using Modules from This Registry

Reference modules using the registry hostname as the source prefix:

```hcl
module "vpc" {
  source  = "registry.example.com/my-org/vpc/aws"
  version = "1.2.0"
}
```

Terraform's module protocol uses the `credentials` block above for authentication. No additional CLI config is required.

> **Note:** If the module uses `configuration_aliases` in its `required_providers`, you must pass the provider explicitly in the calling module:
>
> ```hcl
> module "vpc" {
>   source  = "registry.example.com/my-org/vpc/aws"
>   version = "1.2.0"
>
>   providers = {
>     aws = aws
>   }
> }
> ```

---

## Using Providers via Network Mirror

This registry implements the [Terraform Network Mirror Protocol](https://developer.hashicorp.com/terraform/internals/provider-network-mirror-protocol), allowing it to serve provider binaries. Providers must first be uploaded to the registry before they can be mirrored.

To route provider downloads through this registry, add a `provider_installation` block to your CLI config:

```hcl
credentials "registry.example.com" {
  token = "tfr_your_api_key_here"
}

provider_installation {
  network_mirror {
    url = "https://registry.example.com/terraform/providers/"
  }
}
```

With this config, `terraform init` will query `https://registry.example.com/terraform/providers/` for **all** providers. If a provider is not present in the registry, the init will fail.

### Falling back to the public registry for unlisted providers

To use the local registry for some providers and fall back to the public Terraform registry for others, use an `include` filter on the mirror and add a direct fallback:

```hcl
provider_installation {
  network_mirror {
    url     = "https://registry.example.com/terraform/providers/"
    include = ["registry.terraform.io/my-org/*"]
  }
  direct {
    exclude = ["registry.terraform.io/my-org/*"]
  }
}
```

### Provider source addresses

Provider `source` addresses in `required_providers` always use the **canonical** address — they do not change when using a network mirror. The mirror is transparent to the Terraform configuration:

```hcl
# This is correct — do NOT change the source to registry.example.com
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"   # canonical: registry.terraform.io/hashicorp/aws
      version = ">= 5.0"
    }
  }
}
```

The `provider_installation` block in the CLI config handles the routing — no changes to `.tf` files are needed.

### Verifying the mirror is active

Run `terraform init` with debug logging and filter for mirror activity:

```bash
TF_LOG=DEBUG terraform init 2>&1 | grep -E "mirror|terraform/providers|Explicit provider"
```

On Windows:

```powershell
$env:TF_LOG="DEBUG"; terraform init 2>&1 | Select-String "mirror|terraform/providers|Explicit provider"
```

Expected output confirms the mirror is active:

```
[DEBUG] Explicit provider installation configuration is set
[DEBUG] Querying available versions of provider registry.terraform.io/hashicorp/aws at network mirror https://registry.example.com/terraform/providers/
[DEBUG] GET https://registry.example.com/terraform/providers/registry.terraform.io/hashicorp/aws/index.json
```

You can also confirm via the registry backend logs — provider mirror requests appear as:

```json
{"method":"GET","path":"/terraform/providers/registry.terraform.io/hashicorp/aws/index.json","status":200}
```

---

## TLS Trust for Private Deployments

If you are running the registry with a self-signed TLS certificate, Terraform will reject the connection with an `x509: certificate signed by unknown authority` error. You must trust the certificate at the OS level.

### Import the certificate

**Windows:**

```powershell
# Export the cert from the running container (if using Docker)
docker exec my-registry-frontend cat /etc/nginx/certs/server.crt | Out-File -Encoding ascii "$env:TEMP\registry.crt"

# Import into the Windows Trusted Root store (requires elevation)
Import-Certificate -FilePath "$env:TEMP\registry.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

**Linux / macOS:**

```bash
# Export cert
docker exec my-registry-frontend cat /etc/nginx/certs/server.crt > /tmp/registry.crt

# Ubuntu/Debian
sudo cp /tmp/registry.crt /usr/local/share/ca-certificates/registry.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/registry.crt
```

### Certificate SAN requirements

The certificate must include a Subject Alternative Name (SAN) matching the hostname you configured in the `credentials` block. A cert with only `CN=localhost` will be rejected when connecting to `registry.example.com`.

If using the registry's built-in Docker image, the SAN is set at build time in the `Dockerfile`:

```dockerfile
openssl req -x509 -newkey rsa:2048 \
  -keyout /etc/nginx/certs/server.key \
  -out /etc/nginx/certs/server.crt \
  -days 365 -nodes \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,DNS:registry.example.com,IP:127.0.0.1'
```

---

## Verifying the Configuration

Run a full `terraform init` from DEBUG mode to confirm all three components work — module download, provider mirror, and authentication:

```bash
TF_LOG=DEBUG terraform init 2>&1 | grep -E "Loading CLI|Explicit provider|registry\.example\.com|Installing"
```

Expected lines:

```
[INFO]  Loading CLI configuration from ~/.terraformrc
[DEBUG] Explicit provider installation configuration is set
[DEBUG] Querying available versions of provider ... at network mirror https://registry.example.com/terraform/providers/
- Installing hashicorp/aws v6.x.x...
- Downloading registry.example.com/my-org/vpc/aws 1.2.0 for mymodule...
```
