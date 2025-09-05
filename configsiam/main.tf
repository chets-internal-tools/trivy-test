resource "aws_iam_role" "test" {
  name = "test-role"
  assume_role_policy = data.aws_iam_policy_document.test.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "test" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
    effect = "Allow"
    sid = ""
  }
}

data "aws_iam_policy_document" "test2" {
  statement {
    sid       = "AllowTestS3"
    actions = [
      "ec2:*",
      "ec2:DeleteVolume",
      "kms:Encrypt",
      "kms:Decrypt",
    ]
    resources = ["*"]
    effect    = "Allow"
  }
}

data "aws_iam_policy_document" "test3" {
  statement {
    sid       = "AllwS3ActionsOnAllResources"
    actions = [
      "s3:*"
    ]
    resources = ["*"]
    effect    = "Allow"
  }
}

# using for initial testing
