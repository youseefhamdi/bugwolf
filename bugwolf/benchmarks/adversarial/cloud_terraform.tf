# bugwolf/benchmarks — adversarial test apps + scoring
# SCHEMA: bugwolf-benchmarks-adversarial-cloud-tf-v1
# ## Source: original work for Phase 4.3
# ## License: BugWolf internal
# ## Capability tier: C0 (passive) only — all benchmarks are local test apps
# Adversarial Terraform fixture — public-read S3 bucket and 0.0.0.0/0 SG.
# This is a TEST FIXTURE. It is NEVER applied. A scanner should flag:
#   * bucket = "public-bucket"
#   * acl    = "public-read"
#   * cidr_blocks = ["0.0.0.0/0"] with ingress on 22
#   * no encryption on the bucket
#   * no versioning on the bucket

terraform {
  required_version = ">= 1.0.0"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "public-bucket"          # BUG: name implies public exposure
  acl    = "public-read"            # BUG: public-read ACL
  # BUG: no server-side encryption block
  # BUG: no versioning block
}

resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Wide-open SSH from the entire internet"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]     # BUG: 0.0.0.0/0 ingress on SSH
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "plaintext_creds" {
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  username             = "admin"
  password             = "password123"   # BUG: weak hardcoded password
  publicly_accessible   = true            # BUG: publicly accessible DB
  skip_final_snapshot  = true
}