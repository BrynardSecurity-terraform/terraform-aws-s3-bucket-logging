resource "aws_s3_bucket" "this" {
  bucket = "${var.name_prefix}-logging${var.name_suffix}"

  tags = var.input_tags
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  dynamic "versioning_configuration" {
    for_each = var.versioning_enabled == true ? [true] : []
    content {
      status = "Enabled"
    }
  }

  dynamic "versioning_configuration" {
    for_each = var.versioning_enabled == true ? [] : [true]
    content {
      status = "Disabled"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count = var.enable_server_side_encryption ? 1 : 0
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count = var.versioning_enabled ? 1 : 0
  bucket = aws_s3_bucket.this.id
  
  rule {
    id = "Logs"

    expiration {
      days = var.transition_expiration
    }

    filter {
      and {
        prefix = "/"
      }
    }

    status = "Enabled"

    transition {
      days = var.transition_IA
      storage_class = "STANDARD_ID"
    }

    transition {
      days = var.transition_glacier
      storage_class = "GLACIER"
    }
  }
}


resource "aws_s3_bucket_replication_configuration" "this" {
  count = var.enable_replication ? 1 : 0
  bucket = aws_s3_bucket.this.id
  role = var.iam_role_s3_replication_arn

  rule {
    id = "${var.name_prefix}-replication${var.name_suffix}"
    status = "Enabled"
    destination {
      bucket = "arn:aws:s3:::${var.s3_destination_bucket_name}"
      storage_class = var.replication_dest_storage_class
      account = var.logging_account_id
      access_control_translation {
        owner = "Destination"
      }
    }
  }
}

resource "aws_s3_bucket_acl" "this" {
  bucket = aws_s3_bucket.this.id
  acl = "log-delivery-write"
}

data "aws_elb_service_account" "elb_account" {}

data "aws_iam_policy_document" "bucket_policy" {

  statement {
    actions = [
      "s3:PutObject"
    ]
    principals {
      identifiers = [
        data.aws_elb_service_account.elb_account.arn
      ]
      type = "AWS"
    }
    resources = [
      "${aws_s3_bucket.this.arn}/elb/*"
    ]
    sid = "EnableELBLogging"
  }

  statement {
    actions = [
      "s3:GetBucketAcl"
    ]
    principals {
      identifiers = [
        "config.amazonaws.com"
      ]
      type = "Service"
    }
    resources = [
      aws_s3_bucket.this.arn
    ]
    sid = "EnableConfigGetACL"
  }

  statement {
    actions = [
      "s3:PutObject"
    ]
    principals {
      identifiers = [
        "config.amazonaws.com"
      ]
      type = "Service"
    }
    resources = [
      "${aws_s3_bucket.this.arn}/aws-config/*",
      "${aws_s3_bucket.this.arn}/config/*"
    ]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values = [
        "bucket-owner-full-control"
      ]
    }
    sid = "EnableConfigLogging"
  }

  statement {
    actions = [
      "s3:*"
    ]
    condition {
      test = "Bool"
      values = [
        "false"
      ]
      variable = "aws:SecureTransport"
    }
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    resources = [
      aws_s3_bucket.this.arn,
      "${aws_s3_bucket.this.arn}/*"
    ]
    sid = "DenyUnsecuredTransport"
  }
}

resource "aws_s3_bucket_policy" "bucket_policy_attachment" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
