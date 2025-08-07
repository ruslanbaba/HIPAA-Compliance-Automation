# Main Terraform configuration for HIPAA Compliance Automation infrastructure

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
  
  backend "gcs" {
    bucket = "hipaa-terraform-state"
    prefix = "state"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Cloud Function resources
resource "google_storage_bucket" "function_bucket" {
  name     = "${var.project_id}-function"
  location = var.region
  
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }
}

resource "google_service_account" "hipaa_automation" {
  account_id   = "hipaa-automation"
  display_name = "HIPAA Compliance Automation Service Account"
}

resource "google_project_iam_member" "function_roles" {
  for_each = toset([
    "roles/securitycenter.admin",
    "roles/bigquery.dataViewer",
    "roles/monitoring.admin",
    "roles/cloudtrace.admin"
  ])
  
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.hipaa_automation.email}"
}

# Cloud Function
resource "google_cloudfunctions_function" "hipaa_compliance" {
  name        = "hipaa-compliance-automation"
  description = "HIPAA Compliance Automation Function"
  runtime     = "python39"
  
  available_memory_mb   = 1024
  source_archive_bucket = google_storage_bucket.function_bucket.name
  source_archive_object = "function.zip"
  
  entry_point = "process_compliance"
  
  environment_variables = {
    PROJECT_ID = var.project_id
  }
  
  service_account_email = google_service_account.hipaa_automation.email
  
  secret_environment_variables {
    key     = "CONFIG_SECRET"
    secret  = "hipaa-config"
    version = "latest"
  }
}

# Cloud Scheduler
resource "google_cloud_scheduler_job" "hipaa_job" {
  name        = "hipaa-compliance-daily"
  description = "Triggers HIPAA compliance check daily"
  schedule    = "0 0 * * *"
  
  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions_function.hipaa_compliance.https_trigger_url
    
    oidc_token {
      service_account_email = google_service_account.hipaa_automation.email
    }
  }
}

# Monitoring
resource "google_monitoring_dashboard" "hipaa_dashboard" {
  dashboard_json = jsonencode({
    displayName = "HIPAA Compliance Dashboard"
    gridLayout = {
      widgets = [
        {
          title = "Evidence Collection Duration"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/hipaa/evidence_collection_duration\""
                }
              }
            }]
          }
        },
        {
          title = "Compliance Status by Control"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/hipaa/compliance_status\""
                }
              }
            }]
          }
        }
      ]
    }
  })
}

# Cloud Storage for reports
resource "google_storage_bucket" "reports_bucket" {
  name     = "${var.project_id}-hipaa-reports"
  location = var.region
  
  uniform_bucket_level_access = true
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    condition {
      age = 365  # Keep reports for 1 year
    }
    action {
      type = "Delete"
    }
  }
}
