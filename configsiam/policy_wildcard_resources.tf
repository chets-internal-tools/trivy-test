resource "aws_iam_policy" "fail_wildcard_resource" {
  name        = "fail-wildcard-resources-policy"
  description = "Policy with wildcard resource to trigger AWS-0057"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WildcardResourceAndAction"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      }
    ]
  })
}
