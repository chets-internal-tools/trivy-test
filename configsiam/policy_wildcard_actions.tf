resource "aws_iam_policy" "wildcard_actions" {
  name        = "wildcard-actions-policy"
  description = "Policy with wildcard actions to trigger AWS-0057"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WildcardActions"
        Effect   = "Allow"
        Action   = ["s3:*", "ec2:Describe*"]
        Resource = "arn:aws:s3:::example-bucket"
      }
    ]
  })
}
