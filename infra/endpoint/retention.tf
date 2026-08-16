data "aws_caller_identity" "current" {}

locals {
  measurement_data_bucket_name = "${var.resource_name_prefix}-icpr-measurement-${data.aws_caller_identity.current.account_id}-eu-central-1"
  measurement_data_prefix      = "endpoint"
}

resource "aws_s3_bucket" "measurement_data" {
  bucket        = local.measurement_data_bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }

  tags = merge(local.common_tags, {
    Name    = "icpr-measurement-data"
    Purpose = "measurement-evidence-retention"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "measurement_data" {
  bucket = aws_s3_bucket.measurement_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "measurement_data" {
  bucket = aws_s3_bucket.measurement_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "measurement_data" {
  bucket = aws_s3_bucket.measurement_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "measurement_data" {
  bucket = aws_s3_bucket.measurement_data.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "measurement_data_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.measurement_data.arn,
      "${aws_s3_bucket.measurement_data.arn}/*",
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

}

resource "aws_s3_bucket_policy" "measurement_data" {
  bucket = aws_s3_bucket.measurement_data.id
  policy = data.aws_iam_policy_document.measurement_data_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.measurement_data]
}

data "aws_iam_policy_document" "measurement_ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "measurement_upload" {
  name               = "icpr-measurement-upload"
  description        = "Upload-only role for iCPR measurement evidence"
  assume_role_policy = data.aws_iam_policy_document.measurement_ec2_assume_role.json

  tags = merge(local.common_tags, {
    Name = "icpr-measurement-upload"
  })
}

data "aws_iam_policy_document" "measurement_upload" {
  statement {
    sid       = "UploadMeasurementEvidence"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.measurement_data.arn}/${local.measurement_data_prefix}/*"]
  }

  statement {
    sid       = "AbortOwnMultipartUploads"
    effect    = "Allow"
    actions   = ["s3:AbortMultipartUpload"]
    resources = ["${aws_s3_bucket.measurement_data.arn}/${local.measurement_data_prefix}/*"]
  }
}

resource "aws_iam_role_policy" "measurement_upload" {
  name   = "icpr-measurement-upload"
  role   = aws_iam_role.measurement_upload.id
  policy = data.aws_iam_policy_document.measurement_upload.json
}

resource "aws_iam_instance_profile" "measurement" {
  name = "icpr-measurement"
  role = aws_iam_role.measurement_upload.name

  tags = merge(local.common_tags, {
    Name = "icpr-measurement"
  })
}
