# Infrastructure Setup Guide

This guide walks you through deploying the AWS CDK infrastructure for the cross-account CI/CD solution.

## Prerequisites

- AWS CLI installed and configured
- AWS CDK CLI installed (`npm install -g aws-cdk`)
- Node.js 18+ and npm
- Access to multiple AWS accounts with appropriate permissions

## Account Setup

1. **Configure AWS Profiles**
   
   Set up AWS CLI profiles for each environment:
   ```bash
   # Development account
   aws configure --profile development
   # Enter your dev account credentials
   
   # Staging account  
   aws configure --profile staging
   # Enter your staging account credentials
   
   # Production account
   aws configure --profile production
   # Enter your production account credentials
   ```

2. **Update Configuration**
   
   Copy the example configuration and update with your account details:
   ```bash
   cp config/accounts.example.json config/accounts.json
   # Edit config/accounts.json with your AWS account IDs and GitHub repository
   ```

## Deployment Steps

### 1. Bootstrap CDK (One-time per account)

Bootstrap CDK in each target account:

```bash
# Development account
cdk bootstrap --profile development

# Staging account
cdk bootstrap --profile staging  

# Production account
cdk bootstrap --profile production
```

### 2. Deploy Infrastructure Stacks

Deploy the infrastructure to each environment:

```bash
# Deploy to development
npm run deploy:dev

# Deploy to staging
npm run deploy:staging

# Deploy to production
npm run deploy:prod
```

### 3. Verify Deployment

Check that all stacks deployed successfully:

```bash
# List stacks in development account
aws cloudformation list-stacks --profile development --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE

# Repeat for other accounts
aws cloudformation list-stacks --profile staging --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE
aws cloudformation list-stacks --profile production --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE
```

## Stack Components

### GitHubActionsRoleStack

Creates the IAM role that GitHub Actions will assume for deployments:

- **OIDC Provider**: Configures GitHub as a trusted identity provider
- **Deployment Role**: IAM role with necessary permissions for deployment
- **Trust Policy**: Allows GitHub Actions from your repository to assume the role

Key outputs:
- `DeploymentRoleArn`: ARN of the role for GitHub Actions configuration
- `OIDCProviderArn`: ARN of the OIDC provider

### ApplicationStack

Deploys the sample application infrastructure:

- **Lambda Function**: Sample function demonstrating cross-account deployment
- **S3 Bucket**: Application data storage
- **Secrets Manager**: Configuration and secrets storage
- **IAM Roles**: Execution roles with least privilege access

Key outputs:
- `ApplicationBucketName`: Name of the S3 bucket
- `SampleLambdaArn`: ARN of the sample Lambda function
- `ApplicationSecretsArn`: ARN of the secrets in Secrets Manager

### MonitoringStack

Sets up monitoring and alerting:

- **CloudWatch Dashboard**: Deployment and application metrics
- **SNS Topic**: Alert notifications
- **CloudWatch Alarms**: Automated failure detection

Key outputs:
- `AlertTopicArn`: ARN of the SNS topic for alerts
- `DashboardUrl`: URL to the CloudWatch dashboard

## Permissions Required

The deployment requires the following permissions in each target account:

### Administrative Permissions (Initial Setup)
- `AdministratorAccess` or equivalent for initial deployment
- Permissions to create IAM roles, OIDC providers, and CloudFormation stacks

### GitHub Actions Role Permissions (Runtime)
- CloudFormation stack management
- Lambda function deployment and management
- S3 bucket operations for CDK assets
- Secrets Manager read access
- CloudWatch metrics publishing

## Troubleshooting

### Common Issues

1. **CDK Bootstrap Required**
   ```
   Error: Need to perform AWS CDK bootstrap
   ```
   **Solution**: Run `cdk bootstrap --profile <environment>` for the target account

2. **Insufficient Permissions**
   ```
   Error: User is not authorized to perform: action
   ```
   **Solution**: Ensure your AWS profile has sufficient permissions for deployment

3. **OIDC Provider Already Exists**
   ```
   Error: EntityAlreadyExistsException: Provider with this name already exists
   ```
   **Solution**: This is expected if deploying multiple stacks to the same account. The stack will use the existing provider.

4. **Stack Already Exists**
   ```
   Error: Stack already exists
   ```
   **Solution**: Use `cdk deploy --context environment=<env>` to update the existing stack

### Validation

Run the validation script to check your setup:
```bash
npm run validate:setup
```

This will verify:
- AWS CLI installation and configuration
- CDK CLI availability
- Configuration files
- AWS profile access to target accounts

## Security Considerations

- **Least Privilege**: IAM roles are configured with minimal required permissions
- **Time-Limited Access**: GitHub Actions uses temporary credentials via OIDC
- **Environment Isolation**: Each environment uses separate AWS accounts
- **Audit Trail**: All actions are logged via CloudTrail

## Next Steps

After successful infrastructure deployment:

1. Configure GitHub repository secrets using `npm run setup:github-secrets`
2. Update email addresses in the monitoring configuration  
3. Test the deployment pipeline by pushing code changes
4. Review CloudWatch dashboards and set up additional monitoring as needed
