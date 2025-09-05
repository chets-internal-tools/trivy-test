# Fails: mixed statement with both good and wildcard actions
resource "aws_iam_policy" "fail_mixed_good_bad" {
  name        = "fail-mixed-good-bad-policy"
  description = "Policy containing both precise and wildcard actions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GoodStatement"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::example-bucket/*"
      },
      {
        Sid    = "BadStatement"
        Effect = "Allow"
        Action = ["iam*", "iam:DeleteUser"]
        Resource = "*"
      }
    ]
  })
}
