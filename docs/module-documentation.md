# Module Documentation Extraction

When a module version is uploaded, the registry automatically parses its Terraform source files and extracts structured documentation: input variables, output values, provider requirements, and Terraform version constraints.

No external tool or configuration is required. Extraction runs in-process at upload time using the [hashicorp/terraform-config-inspect](https://github.com/hashicorp/terraform-config-inspect) library.

---

## What Is Extracted

| Field | Source in the module | Notes |
|---|---|---|
| **Inputs** | `variable` blocks | Name, type, description, default value, and whether the variable is required. |
| **Outputs** | `output` blocks | Name, description, and whether the value is marked sensitive. |
| **Providers** | `required_providers` block | Provider name, registry source address, and version constraints. |
| **Terraform version** | `terraform { required_version = "..." }` block | The minimum / constraint on the Terraform CLI version. |

Extraction is **best-effort**: the parser tolerates incomplete modules and missing provider schemas. If a module has no `.tf` files at the root, no documentation is stored and the endpoint returns `404`.

---

## API

Retrieve extracted documentation for a specific version:

```
GET /api/v1/modules/{namespace}/{name}/{system}/versions/{version}/docs
```

No authentication is required.

**Example:**
```bash
curl https://registry.example.com/api/v1/modules/myorg/vpc/aws/versions/1.0.0/docs
```

**Response:**
```json
{
  "inputs": [
    {
      "name": "vpc_cidr",
      "type": "string",
      "description": "CIDR block for the VPC.",
      "default": "10.0.0.0/16",
      "required": false
    },
    {
      "name": "name",
      "type": "string",
      "description": "Name prefix for all resources.",
      "required": true
    }
  ],
  "outputs": [
    {
      "name": "vpc_id",
      "description": "ID of the created VPC.",
      "sensitive": false
    },
    {
      "name": "nat_gateway_ips",
      "description": "Elastic IP addresses of the NAT gateways.",
      "sensitive": false
    }
  ],
  "providers": [
    {
      "name": "aws",
      "source": "hashicorp/aws",
      "version_constraints": ">= 5.0"
    }
  ],
  "requirements": {
    "required_version": ">= 1.3"
  }
}
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `inputs[].name` | string | Variable name as declared. |
| `inputs[].type` | string | Type constraint expression (e.g. `string`, `list(string)`). Empty if not declared. |
| `inputs[].description` | string | Description from the `description` argument. Empty if not set. |
| `inputs[].default` | any | Default value, JSON-decoded. `null` if `required = true`. |
| `inputs[].required` | bool | `true` when no `default` is set and the caller must supply a value. |
| `outputs[].name` | string | Output name as declared. |
| `outputs[].description` | string | Description from the `description` argument. Empty if not set. |
| `outputs[].sensitive` | bool | `true` when the output is marked `sensitive = true`. |
| `providers[].name` | string | Short provider name (the map key in `required_providers`). |
| `providers[].source` | string | Registry source address, e.g. `hashicorp/aws`. Empty if not declared. |
| `providers[].version_constraints` | string | Version constraint string, e.g. `>= 5.0, < 6.0`. Empty if not declared. |
| `requirements.required_version` | string | Terraform version constraint from the `terraform` block. |

---

## Web UI

On any module's detail page, select a version and scroll below the README to the **Module Documentation** section. It shows inputs, outputs, and provider requirements in structured tables, visible to all users. The section is omitted when no documentation was extracted (e.g. modules with no `.tf` files at the archive root).

---

## How It Works

At upload time, the handler:

1. Extracts the `.tar.gz` archive to a temporary directory.
2. Calls `hashicorp/terraform-config-inspect` to parse all `.tf` files in the module root.
3. Stores the extracted inputs, outputs, providers, and requirements in the `module_docs` table.
4. Deletes the temporary directory.

The parser is **tolerant of errors**: if Terraform files are present but reference undeclared providers or have partial syntax issues, extraction still succeeds for the well-formed portions. Parsing diagnostics are logged at `DEBUG` level.

---

## Module Archive Requirements

For documentation to be extracted, the uploaded archive must:

- Be a valid `.tar.gz` file.
- Contain at least one `.tf` file at the **module root**. The root is defined as the top-level directory in the archive, or the first directory containing `.tf` files.

Nested submodules (e.g. `modules/submodule/*.tf`) are not scanned — only the root is analysed.

---

## Configuration

No configuration is required. Extraction is always enabled and runs as part of every module upload. There are no `TFR_*` environment variables or YAML keys to set.

---

## Differences from the `terraform-docs` CLI Tool

The extraction is performed entirely in-process using the official HashiCorp `terraform-config-inspect` library — **the `terraform-docs` CLI binary is not used and does not need to be installed**. The extracted information is a subset of what the `terraform-docs` CLI produces; it covers the most commonly needed fields (variables, outputs, providers, version requirements) without requiring an external process.
