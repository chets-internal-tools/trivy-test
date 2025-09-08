resource "aws_iam_policy" "bad_policy" {
    name       = "bad-policy"
    description = "Policy with bad practices to trigger alert"
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect   = "Allow"
                Action   = "*"
                Resource = "*"
            },
            {
                Effect   = "Allow"
                Action   = ["iam:PassRole", "ec2:RunInstances"]
                Resource = "*"
            },
            {
                Effect   = "Allow"
                Action   = ["s3:getObject", "s3:PutObject"]
                Resource = "arn:aws:s3:::example-bucket/*"
            }
        ]
    })
}