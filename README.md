# trivy-test

## Custom IAM Permissions Boundary Policy

This repository includes a custom Trivy (OPA/Rego) policy to ensure every `aws_iam_role` resource defines a required permissions boundary.

Policy location: `trivy/policies/legacy/iam_boundary_check_legacy.rego`

### Local Scan

Install Trivy (Linux/macOS):

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.56.1
```

Run scan (root of repo):

```bash
trivy config \
	--config trivy/policies/trivy.yaml \
	--severity HIGH \
	--format table .
```

Expected finding (since test role lacks a permissions boundary):
`IAM role 'test-role' is missing a permissions boundary.`

### GitHub Actions Workflow

Workflow: `.github/workflows/trivy-cli.yaml` installs Trivy and uploads SARIF results to Code Scanning.

### Adjusting Required Boundary

Change the ARN in `required_boundary` inside the policy file if your boundary differs.
