# trivy-test

This repo runs a scan of custom rego policies using the trivy cli scan on a github action, and outputs the result to the security overview's code scanning page.

### Local Scan

Install Trivy (Linux/macOS):

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.56.1
```

### GitHub Actions Workflow

Workflow: `.github/workflows/trivy-cli.yaml` installs Trivy and uploads SARIF results to Code Scanning.

## Custom S3 Full Access (s3:*) Detection

This repo also includes a simple custom Rego policy to flag IAM policies that grant unrestricted S3 access (`s3:*` with `"*"` resources).

Policy location: `trivy/policies/custom/limit_s3_full_access_custom.rego`

### What it Detects
Flags any `aws_iam_policy` Terraform resource whose JSON (or jsonencoded) policy statements contain:

- An Action exactly `s3:*` (or wildcard ending in `*` starting with `s3:`)
- AND a Resource exactly `*`

### Test Files
Under `configsiam/` the file `policy_s3_fails.tf` contains a policy intentionally granting full S3 access and should be flagged.

```

Typical output snippet:

```
policy_s3_fails.tf (terraform)
HIGH: IAM policy 'fail-wildcard-actions-policy' allows unrestricted S3 access with action 's3:*' on resource '*'
```

### CI Integration
The existing GitHub Actions workflow already loads the custom directory through `trivy/policies/trivy.yaml`, so the S3 rule runs automatically in Code Scanning.

### Tuning / Extending
To extend detection (e.g. flag `s3:Get*` + `*`), modify the helper `wildcard_action` in the policy:

```rego
wildcard_action(a) { a == "s3:*" } else { endswith(a, "*") }
```

Change logic or add additional deny rules as needed.

