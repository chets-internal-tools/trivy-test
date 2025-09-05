# Fails: single string wildcard Action and wildcard Resource
resource "aws_iam_policy" "wildcard_single_string" {
  name        = "wildcard-single-string-policy"
  description = "Policy with single string action wildcard and resource *"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SingleStringWildcard"
        Effect = "Allow"
        Action = "s3:*"
        Resource = "*"
      }
    ]
  })
}
