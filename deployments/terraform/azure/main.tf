terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }

  # Uncomment for remote state:
  # backend "azurerm" {
  #   resource_group_name  = "terraform-state-rg"
  #   storage_account_name = "tfstate"
  #   container_name       = "tfstate"
  #   key                  = "terraform-registry.tfstate"
  # }
}

provider "azurerm" {
  features {}
}

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Project     = "terraform-registry"
    ManagedBy   = "terraform"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# Log Analytics
# ---------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.name}-logs"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# ---------------------------------------------------------------------------
# Container Registry
# ---------------------------------------------------------------------------
resource "azurerm_container_registry" "main" {
  name                = replace("${var.name}acr", "-", "")
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = true
}

# ---------------------------------------------------------------------------
# PostgreSQL Flexible Server
# ---------------------------------------------------------------------------
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "${var.name}-db"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "16"
  administrator_login    = "registry"
  administrator_password = var.database_password
  storage_mb             = 32768
  sku_name               = var.db_sku
  zone                   = "1"

  backup_retention_days = 7

  lifecycle {
    ignore_changes = [zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "main" {
  name      = "terraform_registry"
  server_id = azurerm_postgresql_flexible_server.main.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_firewall_rule" "allow_azure" {
  name             = "AllowAzureServices"
  server_id        = azurerm_postgresql_flexible_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# ---------------------------------------------------------------------------
# Storage Account (for module/provider artifacts)
# ---------------------------------------------------------------------------
resource "azurerm_storage_account" "main" {
  name                     = replace("${var.name}storage", "-", "")
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_storage_container" "registry" {
  name                  = "terraform-registry"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "private"
}

# ---------------------------------------------------------------------------
# Key Vault (for secrets)
# ---------------------------------------------------------------------------
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                = "${var.name}-kv"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
  }
}

resource "azurerm_key_vault_secret" "jwt_secret" {
  name         = "jwt-secret"
  value        = var.jwt_secret
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "encryption_key" {
  name         = "encryption-key"
  value        = var.encryption_key
  key_vault_id = azurerm_key_vault.main.id
}

resource "azurerm_key_vault_secret" "db_password" {
  name         = "database-password"
  value        = var.database_password
  key_vault_id = azurerm_key_vault.main.id
}

# ---------------------------------------------------------------------------
# Storage Configuration Locals
# ---------------------------------------------------------------------------
locals {
  storage_env = concat(
    [{ name = "TFR_STORAGE_DEFAULT_BACKEND", value = var.storage_backend }],

    # Azure config (native default)
    var.storage_backend == "azure" ? [
      { name = "TFR_STORAGE_AZURE_ACCOUNT_NAME", value = azurerm_storage_account.main.name },
      { name = "TFR_STORAGE_AZURE_CONTAINER_NAME", value = azurerm_storage_container.registry.name },
    ] : [],
    var.storage_backend == "azure" && var.storage_azure_cdn_url != "" ? [
      { name = "TFR_STORAGE_AZURE_CDN_URL", value = var.storage_azure_cdn_url },
    ] : [],

    # S3 config
    var.storage_backend == "s3" ? [
      { name = "TFR_STORAGE_S3_BUCKET", value = var.storage_s3_bucket },
      { name = "TFR_STORAGE_S3_REGION", value = var.storage_s3_region },
      { name = "TFR_STORAGE_S3_AUTH_METHOD", value = var.storage_s3_auth_method },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_endpoint != "" ? [
      { name = "TFR_STORAGE_S3_ENDPOINT", value = var.storage_s3_endpoint },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_role_arn != "" ? [
      { name = "TFR_STORAGE_S3_ROLE_ARN", value = var.storage_s3_role_arn },
      { name = "TFR_STORAGE_S3_ROLE_SESSION_NAME", value = var.storage_s3_role_session_name },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_external_id != "" ? [
      { name = "TFR_STORAGE_S3_EXTERNAL_ID", value = var.storage_s3_external_id },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_web_identity_token_file != "" ? [
      { name = "TFR_STORAGE_S3_WEB_IDENTITY_TOKEN_FILE", value = var.storage_s3_web_identity_token_file },
    ] : [],

    # GCS config
    var.storage_backend == "gcs" ? [
      { name = "TFR_STORAGE_GCS_BUCKET", value = var.storage_gcs_bucket },
      { name = "TFR_STORAGE_GCS_PROJECT_ID", value = var.storage_gcs_project_id },
      { name = "TFR_STORAGE_GCS_AUTH_METHOD", value = var.storage_gcs_auth_method },
    ] : [],

    # Local config
    var.storage_backend == "local" ? [
      { name = "TFR_STORAGE_LOCAL_BASE_PATH", value = var.storage_local_base_path },
      { name = "TFR_STORAGE_LOCAL_SERVE_DIRECTLY", value = "true" },
    ] : [],
  )

  # Container App secrets for storage credentials
  storage_secrets = concat(
    var.storage_backend == "azure" ? [
      { name = "storage-account-key", value = azurerm_storage_account.main.primary_access_key },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? [
      { name = "s3-access-key", value = var.storage_s3_access_key_id },
      { name = "s3-secret-key", value = var.storage_s3_secret_access_key },
    ] : [],
    var.storage_backend == "gcs" && var.storage_gcs_credentials_json != "" ? [
      { name = "gcs-credentials", value = var.storage_gcs_credentials_json },
    ] : [],
  )

  # Secret env var references (use secret_name instead of value)
  storage_secret_env = concat(
    var.storage_backend == "azure" ? [
      { name = "TFR_STORAGE_AZURE_ACCOUNT_KEY", secret_name = "storage-account-key" },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? [
      { name = "TFR_STORAGE_S3_ACCESS_KEY_ID", secret_name = "s3-access-key" },
      { name = "TFR_STORAGE_S3_SECRET_ACCESS_KEY", secret_name = "s3-secret-key" },
    ] : [],
    var.storage_backend == "gcs" && var.storage_gcs_credentials_json != "" ? [
      { name = "TFR_STORAGE_GCS_CREDENTIALS_JSON", secret_name = "gcs-credentials" },
    ] : [],
  )
}

# ---------------------------------------------------------------------------
# Container Apps Environment
# ---------------------------------------------------------------------------
resource "azurerm_container_app_environment" "main" {
  name                       = "${var.name}-env"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}

# ---------------------------------------------------------------------------
# Backend Container App
# ---------------------------------------------------------------------------
resource "azurerm_container_app" "backend" {
  name                         = "${var.name}-backend"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  secret {
    name  = "database-password"
    value = var.database_password
  }

  secret {
    name  = "jwt-secret"
    value = var.jwt_secret
  }

  secret {
    name  = "encryption-key"
    value = var.encryption_key
  }

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.main.admin_password
  }

  dynamic "secret" {
    for_each = local.storage_secrets
    content {
      name  = secret.value.name
      value = secret.value.value
    }
  }

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "acr-password"
  }

  ingress {
    external_enabled = false
    target_port      = 8080
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    min_replicas = var.backend_min_replicas
    max_replicas = var.backend_max_replicas

    container {
      name   = "backend"
      image  = "${azurerm_container_registry.main.login_server}/${var.name}-backend:${var.image_tag}"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "TFR_SERVER_HOST"
        value = "0.0.0.0"
      }
      env {
        name  = "TFR_SERVER_PORT"
        value = "8080"
      }
      env {
        name  = "TFR_SERVER_BASE_URL"
        value = var.domain != "" ? "https://${var.domain}" : "https://${var.name}-frontend.${azurerm_container_app_environment.main.default_domain}"
      }
      env {
        name  = "TFR_DATABASE_HOST"
        value = azurerm_postgresql_flexible_server.main.fqdn
      }
      env {
        name  = "TFR_DATABASE_PORT"
        value = "5432"
      }
      env {
        name  = "TFR_DATABASE_NAME"
        value = "terraform_registry"
      }
      env {
        name  = "TFR_DATABASE_USER"
        value = "registry"
      }
      env {
        name        = "TFR_DATABASE_PASSWORD"
        secret_name = "database-password"
      }
      env {
        name  = "TFR_DATABASE_SSL_MODE"
        value = "require"
      }
      env {
        name        = "TFR_JWT_SECRET"
        secret_name = "jwt-secret"
      }
      env {
        name        = "ENCRYPTION_KEY"
        secret_name = "encryption-key"
      }
      env {
        name  = "TFR_SECURITY_TLS_ENABLED"
        value = "false"
      }
      env {
        name  = "TFR_AUTH_API_KEYS_ENABLED"
        value = "true"
      }
      env {
        name  = "TFR_LOGGING_LEVEL"
        value = "info"
      }
      env {
        name  = "TFR_LOGGING_FORMAT"
        value = "json"
      }
      env {
        name  = "DEV_MODE"
        value = "false"
      }

      # Storage configuration (value-based env vars)
      dynamic "env" {
        for_each = local.storage_env
        content {
          name  = env.value.name
          value = env.value.value
        }
      }

      # Storage configuration (secret-referenced env vars)
      dynamic "env" {
        for_each = local.storage_secret_env
        content {
          name        = env.value.name
          secret_name = env.value.secret_name
        }
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 8080

        initial_delay    = 10
        interval_seconds = 30
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/ready"
        port      = 8080

        interval_seconds = 10
      }

      startup_probe {
        transport = "HTTP"
        path      = "/health"
        port      = 8080

        interval_seconds        = 5
        failure_count_threshold = 10
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Frontend Container App
# ---------------------------------------------------------------------------
resource "azurerm_container_app" "frontend" {
  name                         = "${var.name}-frontend"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  secret {
    name  = "acr-password"
    value = azurerm_container_registry.main.admin_password
  }

  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "acr-password"
  }

  ingress {
    external_enabled = true
    target_port      = 80
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  template {
    min_replicas = var.frontend_min_replicas
    max_replicas = var.frontend_max_replicas

    container {
      name   = "frontend"
      image  = "${azurerm_container_registry.main.login_server}/${var.name}-frontend:${var.image_tag}"
      cpu    = 0.25
      memory = "0.5Gi"

      liveness_probe {
        transport = "HTTP"
        path      = "/"
        port      = 80

        interval_seconds = 30
      }

      startup_probe {
        transport = "HTTP"
        path      = "/"
        port      = 80

        interval_seconds        = 5
        failure_count_threshold = 6
      }
    }
  }
}
