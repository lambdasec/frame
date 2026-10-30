
provider "aws" {
  profile = var.profile
  region  = var.region
}

provider "aws" {
  alias      = "plain_text_access_keys_provider"
  region     = "us-west-1"
  access_key = "PLACEHOLDER_REMOVED_FROM_FIXTURE"
  secret_key = "PLACEHOLDER_REMOVED_FROM_FIXTURE"
}

terraform {
  backend "s3" {
    encrypt = true
  }
}
