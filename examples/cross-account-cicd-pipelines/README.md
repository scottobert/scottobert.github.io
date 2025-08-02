# Cross-Account CI/CD Pipeline Solution

This is a complete, deployable implementation of the cross-account CI/CD patterns described in the blog post "Implementing Cross-Account CI/CD Pipelines: DevOps Patterns for Multi-Account AWS Architectures".

## Architecture Overview

This solution demonstrates how to implement secure CI/CD pipelines that deploy across multiple AWS accounts using:

- **GitHub Actions** with OIDC authentication
- **AWS CDK** for infrastructure as code
- **Cross-account IAM roles** with least privilege access
- **AWS Secrets Manager** for secure configuration management
- **Blue-Green deployment** patterns
- **Comprehensive monitoring** and audit logging

## Project Structure

```
├── infrastructure/          # AWS CDK infrastructure code
│   ├── lib/                # CDK stack definitions
│   ├── bin/                # CDK app entry point
│   └── cdk.json           # CDK configuration
├── src/                    # Application and utility code
│   ├── deployment/         # Deployment utilities
│   ├── monitoring/         # Monitoring and audit logging
│   └── secrets/           # Secrets management
├── .github/               # GitHub Actions workflows
│   ├── workflows/         # Deployment workflows
│   └── actions/          # Reusable composite actions
├── tests/                 # Integration and unit tests
├── config/               # Environment-specific configuration
└── scripts/              # Deployment and setup scripts
```

## Prerequisites

- AWS CLI configured with appropriate permissions
- Node.js 18+ and npm
- AWS CDK CLI (`npm install -g aws-cdk`)
- Access to multiple AWS accounts (dev, staging, production)
- GitHub repository with Actions enabled

## Quick Start

1. **Clone and Setup**
   ```bash
   git clone <this-repo>
   cd cross-account-cicd-solution
   npm install
   ```

2. **Configure Accounts**
   ```bash
   # Update config files with your account IDs
   cp config/accounts.example.json config/accounts.json
   # Edit config/accounts.json with your AWS account IDs
   ```

3. **Deploy Infrastructure**
   ```bash
   # Deploy to each account
   npm run deploy:dev
   npm run deploy:staging
   npm run deploy:prod
   ```

4. **Configure GitHub Secrets**
   ```bash
   # Set up GitHub repository secrets
   npm run setup:github-secrets
   ```

5. **Test Deployment**
   ```bash
   # Trigger a test deployment
   git push origin main
   ```

## Detailed Setup Instructions

See the individual README files in each directory for detailed setup instructions:

- [Infrastructure Setup](./infrastructure/README.md)
- [GitHub Actions Configuration](./.github/README.md)
- [Application Deployment](./src/README.md)
- [Testing Guide](./tests/README.md)

## Security Considerations

- All cross-account access uses temporary credentials via OIDC
- IAM roles follow principle of least privilege
- Secrets are managed through AWS Secrets Manager
- All deployment activities are logged and monitored
- Blue-green deployments minimize risk

## Troubleshooting

Common issues and solutions:

1. **Permission Denied**: Verify IAM roles and trust relationships
2. **Secret Access Failures**: Check Secrets Manager permissions
3. **Deployment Timeouts**: Review CloudFormation stack complexity
4. **OIDC Authentication Issues**: Verify GitHub OIDC provider configuration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details
