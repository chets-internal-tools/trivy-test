# Fails: EC2 describe wildcard and resource ARN wildcard suffix
resource "aws_iam_policy" "pass_ec2_prefix_wildcards" {
  name        = "pass-ec2-prefix-wildcards-policy"
  description = "Policy with EC2 wildcard actions and resource wildcard suffix"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
  Sid    = "PassEC2PrefixWildcard"
        Effect = "Allow"
        Action = ["ec2:Describe*", "ec2:GetConsole*" ]
        Resource = [
          "arn:aws:ec2:us-east-1:123456789012:instance/*",
          "arn:aws:ec2:us-east-1:123456789012:volume/*"
        ]
      }
    ]
  })
}
