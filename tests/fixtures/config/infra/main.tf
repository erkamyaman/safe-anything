resource "aws_security_group_rule" "ssh" {
  from_port   = 22
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_s3_bucket_acl" "b" {
  acl = "public-read"
}
resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_s3_account_public_access_block" "account" {
  block_public_policy     = true
  restrict_public_buckets = "false"
}
resource "aws_s3_bucket_public_access_block" "private" {
  bucket                  = aws_s3_bucket.private.id
  block_public_policy     = true
  restrict_public_buckets = true
  # block_public_policy   = false
}
resource "aws_s3_access_point" "reports" {
  bucket = aws_s3_bucket.reports.id
  name   = "reports"
  public_access_block_configuration {
    block_public_policy     = false
    restrict_public_buckets = false
  }
}
resource "aws_db_instance" "d" {
  publicly_accessible = true
  storage_encrypted   = false
}
resource "aws_db_instance" "private" {
  publicly_accessible = false
  storage_encrypted   = true # was = false
  # publicly_accessible = true
}
