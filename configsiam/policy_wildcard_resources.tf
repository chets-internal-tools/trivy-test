resource "aws_iam_policy" "fail_wildcard_resources" {
  name        = "fail-wildcard-resources-policy"
  description = "Policy with wildcard resource to trigger AWS-0057"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WildcardResource"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "*"
      }
    ]
  })
}
