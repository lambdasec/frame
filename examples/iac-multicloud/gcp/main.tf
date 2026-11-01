resource "google_compute_firewall" "admin" {
  name          = "admin"
  network       = "prod"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
}

# A deny ahead of it (a lower priority number) for every instance: RDP is closed on "staging".
resource "google_compute_firewall" "staging_rdp" {
  name          = "staging-rdp"
  network       = "staging"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_compute_firewall" "staging_deny" {
  name          = "staging-deny"
  network       = "staging"
  priority      = 900
  source_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "tcp"
  }
}

resource "google_sql_database_instance" "orders" {
  name             = "orders"
  database_version = "POSTGRES_16"
  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_storage_bucket" "downloads" {
  name     = "acme-downloads"
  location = "EU"
}

resource "google_storage_bucket_iam_member" "downloads_public" {
  bucket = google_storage_bucket.downloads.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# The same grant on a bucket that enforces public access prevention: overridden.
resource "google_storage_bucket" "reports" {
  name                     = "acme-reports"
  location                 = "EU"
  public_access_prevention = "enforced"
}

resource "google_storage_bucket_iam_member" "reports_public" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
