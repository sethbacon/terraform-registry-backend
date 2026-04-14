# Getting Started

This tutorial walks you through deploying, configuring, and using the Terraform Registry from scratch. By the end, you will have a running registry with a published module and provider, and your local Terraform CLI configured to use it.

## Table of Contents

1. [Part 1: Deploy](#part-1-deploy)
2. [Part 2: Configure](#part-2-configure)
3. [Part 3: Publish a Module](#part-3-publish-a-module)
4. [Part 4: Consume in Terraform](#part-4-consume-in-terraform)
5. [Part 5: Publish a Provider](#part-5-publish-a-provider)
6. [Part 6: Set Up a Mirror](#part-6-set-up-a-mirror)

---

## Part 1: Deploy

The fastest way to get a running registry is with Docker Compose.

### Prerequisites

- Docker and Docker Compose installed
- `curl` and `jq` available for API interaction

### Start the Registry

```bash
cd deployments/

# Start the backend and PostgreSQL database
docker compose up -d
```

This starts:
- **PostgreSQL 16** on port 5432
- **Backend API** on port 8080 (with Prometheus metrics on port 9090)

Wait for the services to be healthy:

```bash
docker compose ps
```

Verify the backend is running:

```bash
curl -s http://localhost:8080/health | jq .
```

Expected output:

```json
{
  "status": "healthy",
  "database": "connected"
}
```

### Get the Setup Token

On first boot, the backend generates a one-time setup token and prints it to the logs:

```bash
docker compose logs backend | grep "Setup Token"
```

You will see output like:

```
Setup Token: tfr_setup_AbCdEfGh...
```

Save this token -- you will need it in Part 2.

---

## Part 2: Configure

### Option A: Web UI Setup Wizard

If you have the frontend running, navigate to `http://localhost:3000/setup` in your browser and follow the guided wizard.

### Option B: API-Based Setup

#### Step 1: Validate the Setup Token

```bash
export SETUP_TOKEN="tfr_setup_<your-token-here>"

curl -s -X POST http://localhost:8080/api/v1/setup/validate-token \
  -H "Authorization: SetupToken ${SETUP_TOKEN}" | jq .
```

Expected output:

```json
{
  "valid": true,
  "message": "Setup token is valid"
}
```

#### Step 2: Configure Storage

For local development, local storage is already configured. For cloud storage, configure via the setup API:

```bash
curl -s -X POST http://localhost:8080/api/v1/setup/storage \
  -H "Authorization: SetupToken ${SETUP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "backend": "local",
    "local": {
      "base_path": "/app/storage",
      "serve_directly": true
    }
  }' | jq .
```

#### Step 3: Create the Admin User

```bash
curl -s -X POST http://localhost:8080/api/v1/setup/admin \
  -H "Authorization: SetupToken ${SETUP_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "username": "admin"
  }' | jq .
```

The response includes a JWT token for the new admin user.

#### Step 4: Complete Setup

```bash
curl -s -X POST http://localhost:8080/api/v1/setup/complete \
  -H "Authorization: SetupToken ${SETUP_TOKEN}" | jq .
```

### Create an API Key

Using the admin JWT token from step 3:

```bash
export TOKEN="<jwt-token-from-step-3>"

curl -s -X POST http://localhost:8080/api/v1/admin/api-keys \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-api-key",
    "scopes": ["modules:read", "modules:write", "providers:read", "providers:write"]
  }' | jq .
```

Save the `key` value from the response -- this is your API key (it starts with `tfr_`).

```bash
export API_KEY="tfr_<your-key-here>"
```

---

## Part 3: Publish a Module

### Option A: Upload via curl

Create a sample module archive:

```bash
# Create a simple module
mkdir -p /tmp/my-module
cat > /tmp/my-module/main.tf << 'EOF'
variable "name" {
  description = "Name tag for the resource"
  type        = string
  default     = "example"
}

output "greeting" {
  value = "Hello from ${var.name}"
}
EOF

# Package as .tar.gz
cd /tmp && tar czf my-module.tar.gz -C my-module .
```

Upload to the registry:

```bash
curl -s -X POST "http://localhost:8080/api/v1/modules/myorg/my-module/generic/1.0.0/upload" \
  -H "Authorization: Bearer ${API_KEY}" \
  -F "module=@/tmp/my-module.tar.gz" | jq .
```

Expected output:

```json
{
  "namespace": "myorg",
  "name": "my-module",
  "system": "generic",
  "version": "1.0.0",
  "status": "ok"
}
```

### Option B: Publish from GitHub via SCM Integration

1. Configure an SCM provider in the admin UI (Settings > SCM Providers).
2. Link a module to a GitHub repository.
3. Push a tag (e.g., `v1.0.0`) to the repository.
4. The webhook automatically publishes the module version.

### Verify the Module

```bash
# List module versions
curl -s "http://localhost:8080/v1/modules/myorg/my-module/generic/versions" | jq .
```

---

## Part 4: Consume in Terraform

### Configure Terraform Credentials

Create or update `~/.terraformrc` (Linux/macOS) or `%APPDATA%/terraform.rc` (Windows):

```hcl
credentials "localhost" {
  token = "tfr_<your-api-key>"
}
```

See `examples/terraformrc-example` for a full example.

### Write a Terraform Configuration

Create a new directory with a `main.tf` (see `examples/module-consumer/main.tf` for a complete example):

```hcl
terraform {
  required_version = ">= 1.0"
}

module "example" {
  source  = "localhost:8080/myorg/my-module/generic"
  version = "1.0.0"

  name = "world"
}

output "module_output" {
  value = module.example.greeting
}
```

### Initialize and Plan

```bash
terraform init
```

Expected output:

```
Initializing modules...
Downloading localhost:8080/myorg/my-module/generic 1.0.0 for example...

Terraform has been successfully initialized!
```

```bash
terraform plan
```

---

## Part 5: Publish a Provider

### Create a Provider Archive

Provider publishing requires platform-specific binary archives and SHA256SUMS files.

```bash
# Upload a provider binary for linux/amd64
curl -s -X POST "http://localhost:8080/api/v1/providers/myorg/myprovider/1.0.0/linux/amd64/upload" \
  -H "Authorization: Bearer ${API_KEY}" \
  -F "binary=@terraform-provider-myprovider_1.0.0_linux_amd64.zip" \
  -F "shasum=abc123def456..." | jq .
```

### Verify Provider Availability

```bash
# List provider versions
curl -s "http://localhost:8080/v1/providers/myorg/myprovider/versions" | jq .
```

### Use with Terraform

```hcl
terraform {
  required_providers {
    myprovider = {
      source  = "localhost:8080/myorg/myprovider"
      version = "1.0.0"
    }
  }
}
```

Run `terraform init` to download the provider from your private registry.

---

## Part 6: Set Up a Mirror

The provider network mirror caches upstream provider binaries locally, enabling air-gapped deployments and faster downloads.

### Create a Mirror Configuration

```bash
curl -s -X POST "http://localhost:8080/api/v1/admin/mirrors" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "registry.terraform.io",
    "namespace": "hashicorp",
    "type": "aws",
    "sync_enabled": true,
    "sync_interval_mins": 60
  }' | jq .
```

This creates a mirror that syncs the `hashicorp/aws` provider from the public Terraform Registry every 60 minutes.

### Trigger an Initial Sync

```bash
# Get the mirror ID from the creation response, then trigger sync
curl -s -X POST "http://localhost:8080/api/v1/admin/mirrors/<mirror-id>/sync" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

### Configure Terraform to Use the Mirror

Update `~/.terraformrc`:

```hcl
provider_installation {
  network_mirror {
    url = "http://localhost:8080/terraform/providers/"
  }
}
```

### Verify the Mirror

```bash
# Check mirror status
curl -s "http://localhost:8080/terraform/providers/registry.terraform.io/hashicorp/aws/index.json" | jq .
```

Now `terraform init` will download the AWS provider from your local mirror instead of the public registry.

### Verify with Terraform

```bash
mkdir -p /tmp/mirror-test && cd /tmp/mirror-test
cat > main.tf << 'EOF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
EOF

terraform init
```

Terraform will download the AWS provider from your local mirror.

---

## Next Steps

- **Enable security scanning**: Configure a scanner (Trivy, Terrascan, etc.) to automatically scan published modules. See the scanning configuration in `config.example.yaml`.
- **Set up OIDC authentication**: Integrate with your identity provider for SSO. Use the setup wizard or API.
- **Deploy to Kubernetes**: Use the Helm chart in `deployments/helm/` for production deployments. See `values.yaml` for all available options.
- **Enable monitoring**: Set `serviceMonitor.enabled=true` and `grafanaDashboard.enabled=true` in Helm values for Prometheus and Grafana integration.
- **Read the ADRs**: Understand the architectural decisions in `docs/adr/`.
