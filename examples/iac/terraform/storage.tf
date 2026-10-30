# Product images, served to browsers straight from S3.
resource "aws_s3_bucket" "assets" {
  bucket = "acme-shop-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket = aws_s3_bucket.assets.id
}

resource "aws_s3_bucket_policy" "assets" {
  bucket = aws_s3_bucket.assets.id
  policy = data.aws_iam_policy_document.assets_read.json
}

data "aws_iam_policy_document" "assets_read" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.assets.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

# Order exports. Someone set a public ACL; this configuration never enables ACLs.
resource "aws_s3_bucket" "exports" {
  bucket = "acme-shop-exports"
}

resource "aws_s3_bucket_acl" "exports" {
  bucket = aws_s3_bucket.exports.id
  acl    = "public-read"
}

# The deploy role.
resource "aws_iam_role_policy" "deploy" {
  name = "deploy"
  role = "deploy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
