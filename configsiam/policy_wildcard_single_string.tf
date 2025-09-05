# Fails: single string wildcard Action and wildcard Resource
resource "aws_iam_policy" "fail_wildcard_single_string" {
  name        = "fail-wildcard-single-string-policy"
  description = "Policy with single string action wildcard and resource *"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
  Sid    = "FailSingleStringWildcard"
        Effect = "Allow"
        Action = "ec2:*"
        Resource = "*"
      }
    ]
  })
}
