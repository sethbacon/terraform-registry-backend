// Azure Container Apps deployment for Terraform Registry
// Deploy: az deployment group create -g <rg> -f main.bicep -p parameters.json

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Unique environment name suffix')
param environmentName string = 'terraform-registry'

@description('Backend container image (e.g., myregistry.azurecr.io/terraform-registry-backend:latest)')
param backendImage string

@description('Frontend container image (e.g., myregistry.azurecr.io/terraform-registry-frontend:latest)')
param frontendImage string

@description('PostgreSQL server FQDN')
param databaseHost string

@description('PostgreSQL database name')
param databaseName string = 'terraform_registry'

@description('PostgreSQL user')
param databaseUser string = 'registry'

@secure()
@description('PostgreSQL password')
param databasePassword string

@secure()
@description('JWT signing secret (min 32 chars)')
param jwtSecret string

@secure()
@description('Encryption key for sensitive data (32 bytes)')
param encryptionKey string

@description('Public domain for the registry (e.g., registry.example.com)')
param customDomain string = ''

@description('Backend minimum replicas')
@minValue(1)
param backendMinReplicas int = 1

@description('Backend maximum replicas')
param backendMaxReplicas int = 10

@description('Frontend minimum replicas')
@minValue(1)
param frontendMinReplicas int = 1

@description('Frontend maximum replicas')
param frontendMaxReplicas int = 5

@description('ACR login server (e.g., myregistry.azurecr.io)')
param acrLoginServer string = ''

@secure()
@description('ACR password (if not using managed identity)')
param acrPassword string = ''

@description('ACR username (if not using managed identity)')
param acrUsername string = ''

// ---------------------------------------------------------------------------
// Log Analytics Workspace
// ---------------------------------------------------------------------------
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${environmentName}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// ---------------------------------------------------------------------------
// Container Apps Environment
// ---------------------------------------------------------------------------
resource containerAppEnv 'Microsoft.App/managedEnvironments@2023-05-01' = {
  name: '${environmentName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Backend Container App
// ---------------------------------------------------------------------------
resource backendApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: '${environmentName}-backend'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false
        targetPort: 8080
        transport: 'http'
      }
      secrets: [
        { name: 'database-password', value: databasePassword }
        { name: 'jwt-secret', value: jwtSecret }
        { name: 'encryption-key', value: encryptionKey }
      ]
      registries: !empty(acrLoginServer) ? [
        {
          server: acrLoginServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ] : []
    }
    template: {
      containers: [
        {
          name: 'backend'
          image: backendImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'TFR_SERVER_HOST', value: '0.0.0.0' }
            { name: 'TFR_SERVER_PORT', value: '8080' }
            { name: 'TFR_SERVER_BASE_URL', value: !empty(customDomain) ? 'https://${customDomain}' : 'https://${environmentName}-frontend.${containerAppEnv.properties.defaultDomain}' }
            { name: 'TFR_DATABASE_HOST', value: databaseHost }
            { name: 'TFR_DATABASE_PORT', value: '5432' }
            { name: 'TFR_DATABASE_NAME', value: databaseName }
            { name: 'TFR_DATABASE_USER', value: databaseUser }
            { name: 'TFR_DATABASE_PASSWORD', secretRef: 'database-password' }
            { name: 'TFR_DATABASE_SSL_MODE', value: 'require' }
            { name: 'TFR_JWT_SECRET', secretRef: 'jwt-secret' }
            { name: 'ENCRYPTION_KEY', secretRef: 'encryption-key' }
            { name: 'TFR_SECURITY_TLS_ENABLED', value: 'false' }
            { name: 'TFR_STORAGE_DEFAULT_BACKEND', value: 'azure' }
            { name: 'TFR_AUTH_API_KEYS_ENABLED', value: 'true' }
            { name: 'TFR_LOGGING_LEVEL', value: 'info' }
            { name: 'TFR_LOGGING_FORMAT', value: 'json' }
            { name: 'TFR_TELEMETRY_ENABLED', value: 'true' }
            { name: 'TFR_TELEMETRY_METRICS_ENABLED', value: 'true' }
            { name: 'TFR_TELEMETRY_METRICS_PROMETHEUS_PORT', value: '9090' }
            { name: 'DEV_MODE', value: 'false' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/ready'
                port: 8080
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
            {
              type: 'Startup'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 5
              periodSeconds: 5
              failureThreshold: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: backendMinReplicas
        maxReplicas: backendMaxReplicas
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Frontend Container App
// ---------------------------------------------------------------------------
resource frontendApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: '${environmentName}-frontend'
  location: location
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 80
        transport: 'http'
      }
      registries: !empty(acrLoginServer) ? [
        {
          server: acrLoginServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ] : []
    }
    template: {
      containers: [
        {
          name: 'frontend'
          image: frontendImage
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/'
                port: 80
              }
              periodSeconds: 30
            }
            {
              type: 'Startup'
              httpGet: {
                path: '/'
                port: 80
              }
              initialDelaySeconds: 5
              periodSeconds: 5
              failureThreshold: 6
            }
          ]
        }
      ]
      scale: {
        minReplicas: frontendMinReplicas
        maxReplicas: frontendMaxReplicas
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '100'
              }
            }
          }
        ]
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------
output frontendUrl string = 'https://${frontendApp.properties.configuration.ingress.fqdn}'
output backendInternalUrl string = 'https://${backendApp.properties.configuration.ingress.fqdn}'
output environmentName string = containerAppEnv.name
output logAnalyticsWorkspaceId string = logAnalytics.id
