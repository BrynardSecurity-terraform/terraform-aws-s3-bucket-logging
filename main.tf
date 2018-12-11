resource "aws_s3_bucket" "bucket" {
  bucket  = "${var.name_prefix}-logging-${random_string.unique_bucket_name.result}"
  acl     = "log-delivery-write"
  lifecycle {
    prevent_destroy = true
  }
  lifecycle_rule {
    id      = "Logs"
    prefix  = "/"
    enabled = true

    transition {
      days = "${var.transition_IA}"
      storage_class = "STANDARD_IA"
    }

    transition {
      days = "${var.transition_glacier}"
      storage_class = "GLACIER"
    }

    expiration {
      days = "${var.transition_expiration}"
    }
  }
  tags = "${var.input_tags}"
}

data "aws_elb_service_account" "elb_account" {}

data "aws_iam_policy_document" "bucket_policy" {

  statement {
    actions   = [
      "s3:PutObject"
    ]
    principals {
      identifiers = [
        "${data.aws_elb_service_account.elb_account.arn}"
      ]
      type = "AWS"
    }
    resources = [
      "${aws_s3_bucket.bucket.arn}/elb/*"
    ]
    sid       = "EnableELBLogging"
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
      "${aws_s3_bucket.bucket.arn}",
      "${aws_s3_bucket.bucket.arn}/*"
    ]
    sid = "DenyUnsecuredTransport"
  }
}

resource "aws_s3_bucket_policy" "bucket_policy_attachment" {
  bucket = "${aws_s3_bucket.bucket.id}"
  policy = "${data.aws_iam_policy_document.bucket_policy.json}"
}
