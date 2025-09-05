# Fails: EC2 describe wildcard and resource ARN wildcard suffix
resource "aws_iam_policy" "ec2_resource_wildcards" {
  name        = "ec2-resource-wildcards-policy"
  description = "Policy with EC2 wildcard actions and resource wildcard suffix"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2Wildcard"
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
