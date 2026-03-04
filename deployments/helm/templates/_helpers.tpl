{{/*
Chart name
*/}}
{{- define "terraform-registry.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name
*/}}
{{- define "terraform-registry.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label
*/}}
{{- define "terraform-registry.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "terraform-registry.labels" -}}
helm.sh/chart: {{ include "terraform-registry.chart" . }}
{{ include "terraform-registry.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Values.backend.image.tag | default .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "terraform-registry.selectorLabels" -}}
app.kubernetes.io/name: {{ include "terraform-registry.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name
*/}}
{{- define "terraform-registry.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "terraform-registry.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Backend image
*/}}
{{- define "terraform-registry.backendImage" -}}
{{- printf "%s:%s" .Values.backend.image.repository (.Values.backend.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Frontend image
*/}}
{{- define "terraform-registry.frontendImage" -}}
{{- printf "%s:%s" .Values.frontend.image.repository (.Values.frontend.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Secret name for credentials
*/}}
{{- define "terraform-registry.secretName" -}}
{{- if .Values.security.existingSecret }}
{{- .Values.security.existingSecret }}
{{- else }}
{{- include "terraform-registry.fullname" . }}
{{- end }}
{{- end }}

{{/*
Database secret name
*/}}
{{- define "terraform-registry.databaseSecretName" -}}
{{- if .Values.externalDatabase.existingSecret }}
{{- .Values.externalDatabase.existingSecret }}
{{- else }}
{{- include "terraform-registry.fullname" . }}
{{- end }}
{{- end }}

{{/*
Backend service name (for frontend nginx proxy)
*/}}
{{- define "terraform-registry.backendServiceName" -}}
{{- printf "%s-backend" (include "terraform-registry.fullname" .) }}
{{- end }}
