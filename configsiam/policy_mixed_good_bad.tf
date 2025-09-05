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
        Action = ["ec2:*"]
        Resource = "*"
      }
    ]
  })
}

# Explicit EC2 full access policy (for test of custom rule)
resource "aws_iam_policy" "fail_ec2_full_access_test" {
  name        = "fail-ec2-full-access-test"
  description = "Should be flagged by custom EC2 full access rule"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2FullAccess"
        Effect = "Allow"
        Action = ["ec2:*"]
        Resource = "*"
      }
    ]
  })
}
