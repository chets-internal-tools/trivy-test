# Fails: EC2 describe wildcard and resource ARN wildcard suffix
resource "aws_iam_policy" "pass_ec2_prefix_wildcards" {
  name        = "pass-ec2-prefix-wildcards-policy"
  description = "Policy with S3 wildcard actions and resource wildcard suffix"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
  Sid    = "PassEC2PrefixWildcard"
        Effect = "Allow"
        Action = "s3:*"
        Resource = "arn:aws:s3:::example-bucket/*"
      }
    ]
  })
}
