output "frontend_url" {
  description = "Frontend Cloud Run service URL"
  value       = google_cloud_run_v2_service.frontend.uri
}

output "backend_url" {
  description = "Backend Cloud Run service URL"
  value       = google_cloud_run_v2_service.backend.uri
}

output "cloud_sql_connection_name" {
  description = "Cloud SQL instance connection name"
  value       = google_sql_database_instance.main.connection_name
}

output "cloud_sql_private_ip" {
  description = "Cloud SQL private IP address"
  value       = google_sql_database_instance.main.private_ip_address
}

output "gcs_bucket_name" {
  description = "GCS storage bucket name"
  value       = google_storage_bucket.storage.name
}

output "artifact_registry_url" {
  description = "Artifact Registry repository URL"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.main.repository_id}"
}

output "backend_service_account" {
  description = "Backend service account email"
  value       = google_service_account.backend.email
}
