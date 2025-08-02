# GitHub Actions Configuration Guide

This guide explains how to configure GitHub Actions for cross-account CI/CD deployment.

## Overview

The GitHub Actions workflow uses OpenID Connect (OIDC) to securely authenticate with AWS without storing long-lived credentials. The workflow assumes IAM roles in each target AWS account to perform deployments.

## Workflow Architecture

```
GitHub Actions → OIDC Authentication → Assume AWS IAM Role → Deploy to Account
```

## Configuration Steps

### 1. Set Up GitHub Repository Secrets

After deploying the infrastructure, you need to configure GitHub repository secrets with the IAM role ARNs:

```bash
# Automated setup
npm run setup:github-secrets

# Or manually set secrets
gh secret set AWS_ROLE_ARN_DEV --body "arn:aws:iam::111111111111:role/GitHubActionsDevelopment"
gh secret set AWS_ROLE_ARN_STAGING --body "arn:aws:iam::222222222222:role/GitHubActionsStaging"  
gh secret set AWS_ROLE_ARN_PROD --body "arn:aws:iam::333333333333:role/GitHubActionsProduction"
```

### 2. Configure GitHub Environments

Set up deployment environments in your GitHub repository:

1. Go to **Settings → Environments** in your GitHub repository
2. Create environments: `development`, `staging`, `production`
3. Configure environment protection rules:
   - **Development**: No restrictions
   - **Staging**: Require reviews from 1 person
   - **Production**: Require reviews from 2 people, restrict to main branch

### 3. Workflow Configuration

The main workflow file `.github/workflows/deploy.yml` orchestrates deployments across all environments:

- **Triggers**: Push to main branch, pull requests
- **Permissions**: `id-token: write` for OIDC authentication
- **Environment Gates**: Staging waits for dev, production waits for staging

## Workflow Files

### Main Deployment Workflow

**`.github/workflows/deploy.yml`**

Key features:
- Sequential deployment: dev → staging → production
- Environment-specific role assumption
- Conditional deployment based on branch and approval
- Integration with composite actions for reusability

### Composite Action

**`.github/actions/deploy-to-account/action.yml`**

Reusable deployment logic:
- AWS credential configuration via OIDC
- Role assumption verification
- Node.js setup and dependency installation
- CDK deployment execution
- Post-deployment verification

## Security Features

### OIDC Authentication

- **No Long-lived Credentials**: Uses temporary tokens
- **Repository Scoped**: Tokens are tied to specific repository
- **Branch Restrictions**: Can limit to specific branches
- **Short-lived**: Tokens expire after workflow completion

### IAM Role Trust Policies

Each deployment role trusts only:
- GitHub's OIDC provider
- Your specific repository
- Specific conditions (audience, subject claims)

Example trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
        },
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

## Deployment Flow

### Pull Request Flow

1. **Trigger**: Pull request opened/updated
2. **Deploy to Dev**: Automatic deployment to development environment
3. **Run Tests**: Execute integration and validation tests
4. **Report Results**: Comment on PR with deployment status

### Main Branch Flow

1. **Trigger**: Push to main branch
2. **Deploy to Dev**: Automatic deployment
3. **Deploy to Staging**: Requires dev deployment success
4. **Deploy to Production**: Requires staging success + manual approval

## Environment Variables

The workflows use these environment variables:

- `AWS_REGION`: Target AWS region (default: us-east-1)
- `NODE_VERSION`: Node.js version for builds (default: 18)
- `CDK_VERSION`: CDK CLI version compatibility

## Monitoring and Alerts

### Workflow Notifications

Configure workflow notifications:

1. **Slack Integration**: Use GitHub Actions Slack app
2. **Email Notifications**: Configure in repository settings
3. **Custom Webhooks**: Send to monitoring systems

### Deployment Metrics

The workflow automatically records:
- Deployment duration
- Success/failure rates
- Deployed services count
- Environment-specific metrics

## Troubleshooting

### Common Issues

1. **OIDC Authentication Failures**
   ```
   Error: Could not assume role with OIDC
   ```
   **Solutions**:
   - Verify OIDC provider exists in target account
   - Check role trust policy allows your repository
   - Ensure `id-token: write` permission is set

2. **Permission Denied**
   ```
   Error: User is not authorized to perform action
   ```
   **Solutions**:
   - Verify IAM role has necessary permissions
   - Check policy attachments and inline policies
   - Review CloudFormation capabilities

3. **Stack Update Failures**
   ```
   Error: No updates are to be performed
   ```
   **Solutions**:
   - This is informational, not an error
   - Consider using `--force` flag for testing
   - Check if parameters or template changed

### Debugging Workflows

Enable debug logging:
```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

View detailed logs:
1. Go to Actions tab in GitHub repository
2. Select the failed workflow run
3. Expand log sections to see detailed output
4. Check AWS CloudTrail for API call details

## Best Practices

### Security

- **Least Privilege**: IAM roles have minimal required permissions
- **Environment Isolation**: Each environment uses separate AWS accounts
- **Branch Protection**: Require reviews for production deployments
- **Secret Rotation**: Regularly rotate any remaining secrets

### Reliability

- **Retry Logic**: Implement retries for transient failures
- **Rollback Strategy**: Define rollback procedures for failures
- **Health Checks**: Verify deployments before proceeding
- **Monitoring**: Set up alerts for deployment failures

### Performance

- **Parallel Jobs**: Run independent jobs in parallel where possible
- **Caching**: Cache dependencies and build artifacts
- **Incremental Deploys**: Only deploy changed components
- **Artifact Reuse**: Share built artifacts between environments

## Integration with Other Tools

### External Systems

- **Monitoring**: Send metrics to DataDog, New Relic, etc.
- **Communication**: Integrate with Slack, Teams, or email
- **Ticketing**: Update Jira, ServiceNow tickets on deployment
- **Documentation**: Auto-update deployment documentation

### Testing Integration

- **Unit Tests**: Run before deployment
- **Integration Tests**: Execute after deployment
- **Security Scans**: Include SAST/DAST in pipeline  
- **Performance Tests**: Load test after staging deployment

## Maintenance

### Regular Tasks

- Review and update IAM permissions quarterly
- Test rollback procedures monthly
- Update Node.js and CDK versions regularly
- Monitor workflow performance and optimize bottlenecks

### Security Reviews

- Audit GitHub repository access permissions
- Review environment protection rules
- Validate OIDC trust relationships
- Monitor CloudTrail logs for unauthorized access
