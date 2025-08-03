---
title: "Implementing Cross-Account CI/CD Pipelines: DevOps Patterns for Multi-Account AWS Architectures"
date: 2025-08-06T09:00:00-07:00
draft: false
categories: ["Cloud Computing", "DevOps"]
tags:
- AWS
- CI/CD
- Cross-Account
- GitHub Actions
- IAM
- DevOps
- Security
- CodePipeline
series: AWS Cross-Account Patterns
---

Here's a scene that plays out daily in engineering teams worldwide: you're a senior engineer at a growing SaaS company. Your team has maturely segmented production, staging, and development environments into separate AWS accounts for security and compliance reasons. However, your deployment process has become a manual nightmare of shared credentials, context switching between accounts, and error-prone coordination steps. Each release requires logging into multiple AWS consoles, remembering different IAM roles, and manually orchestrating deployments—a process that takes hours and keeps everyone on edge.

If this resonates with your experience, you're not alone. Most organizations that adopt multi-account AWS architectures initially underestimate the complexity of maintaining efficient deployment workflows across account boundaries.

{{< image src="/posts/2025/08/06/cross-account-cicd-pipelines.png" alt="Overview of cross-account CI/CD pipeline architecture showing GitHub Actions orchestrating deployments across multiple AWS accounts with secure role assumption" caption="Cross-Account CI/CD Pipeline Architecture Diagram" width="400" >}}

This is exactly why cross-account CI/CD pipelines have become essential for modern enterprise development. These patterns enable you to build once and deploy consistently across multiple AWS accounts—from development through staging to production—while maintaining strict security controls and comprehensive audit trails. More importantly, they eliminate the manual toil and security risks associated with credential sharing and manual deployments.

Modern enterprise applications increasingly rely on multi-account AWS architectures to maintain security boundaries, isolate environments, and support organizational requirements. However, implementing effective CI/CD pipelines across these account boundaries presents unique challenges that require sophisticated approaches to authentication, authorization, and secure deployment orchestration. The patterns we'll explore solve these challenges while providing the automation and reliability that development teams need to ship software confidently.


## Architecture Overview

Cross-account CI/CD architecture involves orchestrating deployments from a central CI/CD system into multiple target AWS accounts. **GitHub Actions** serves as the orchestration platform, utilizing AWS IAM roles with cross-account trust relationships to securely assume deployment permissions in target accounts. **AWS Secrets Manager** and **GitHub Secrets** provide secure credential management, while **assume-role patterns** enable temporary, scoped access for deployment operations.

{{< plantuml id="cross-account-cicd-architecture" >}}
@startuml
!theme aws-orange
title Cross-Account CI/CD Pipeline Architecture

cloud "GitHub" as GitHub {
  rectangle "GitHub Actions\nWorkflow" as Actions
  rectangle "GitHub Secrets" as Secrets
}

cloud "Development Account (111111111111)" as DevAccount {
  rectangle "Deployment Role\n(GitHubActionsDev)" as DevRole
  rectangle "Application Stack" as DevStack
  rectangle "AWS Secrets Manager" as DevSecrets
}

cloud "Staging Account (222222222222)" as StagingAccount {
  rectangle "Deployment Role\n(GitHubActionsStaging)" as StagingRole
  rectangle "Application Stack" as StagingStack
  rectangle "AWS Secrets Manager" as StagingSecrets
}

cloud "Production Account (333333333333)" as ProdAccount {
  rectangle "Deployment Role\n(GitHubActionsProd)" as ProdRole
  rectangle "Application Stack" as ProdStack
  rectangle "AWS Secrets Manager" as ProdSecrets
}

Actions --> DevRole : "Assume Role\n(OIDC)"
Actions --> StagingRole : "Assume Role\n(OIDC)"
Actions --> ProdRole : "Assume Role\n(OIDC)"

DevRole --> DevStack : "Deploy"
StagingRole --> StagingStack : "Deploy"
ProdRole --> ProdStack : "Deploy"

DevRole --> DevSecrets : "Access"
StagingRole --> StagingSecrets : "Access"
ProdRole --> ProdSecrets : "Access"

Secrets --> Actions : "Configuration"

note right of Actions
  Uses OpenID Connect (OIDC)
  for secure authentication
  without long-lived credentials
end note

@enduml
{{< /plantuml >}}

## Step 1: Setting Up Cross-Account IAM Roles

The foundation of secure cross-account CI/CD lies in properly configured IAM roles that GitHub Actions can assume in each target account. These roles must trust the GitHub OIDC provider and include only the minimum permissions necessary for deployment operations.

Create deployment roles in each target account with appropriate trust policies for GitHub Actions:

```typescript
// deployment-role-trust-policy.json - Trust policy for GitHub Actions OIDC
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
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

Define deployment permissions that follow the principle of least privilege while enabling necessary CI/CD operations:

```typescript
// deployment-permissions-policy.json - Deployment permissions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:UpdateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStackResources",
        "cloudformation:ListStackResources",
        "cloudformation:GetTemplate"
      ],
      "Resource": [
        "arn:aws:cloudformation:*:*:stack/your-app-*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "lambda:DeleteFunction",
        "lambda:GetFunction",
        "lambda:ListFunctions",
        "lambda:TagResource",
        "lambda:UntagResource"
      ],
      "Resource": [
        "arn:aws:lambda:*:*:function:your-app-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:TagRole",
        "iam:UntagRole"
      ],
      "Resource": [
        "arn:aws:iam::*:role/your-app-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:*:secret:your-app/*"
      ]
    }
  ]
}
```

Create the roles using AWS CDK for better maintainability and consistency:

```typescript
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class GitHubActionsRoleStack extends cdk.Stack {
  public readonly deploymentRole: iam.Role;

  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    githubRepository: string;
    environment: string;
  }) {
    super(scope, id, props);

    // Create OIDC provider for GitHub Actions (only needed once per account)
    const oidcProvider = new iam.OpenIdConnectProvider(this, 'GitHubOidcProvider', {
      url: 'https://token.actions.githubusercontent.com',
      clientIds: ['sts.amazonaws.com'],
      thumbprints: ['6938fd4d98bab03faadb97b34396831e3780aea1']
    });

    // Create deployment role with GitHub Actions trust policy
    this.deploymentRole = new iam.Role(this, 'GitHubActionsDeploymentRole', {
      roleName: `GitHubActions${props?.environment || 'Dev'}`,
      description: `Deployment role for GitHub Actions in ${props?.environment || 'development'} environment`,
      assumedBy: new iam.WebIdentityPrincipal(
        oidcProvider.openIdConnectProviderArn,
        {
          'StringLike': {
            'token.actions.githubusercontent.com:sub': `repo:${props?.githubRepository}:*`
          },
          'StringEquals': {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'
          }
        }
      ),
      inlinePolicies: {
        DeploymentPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'cloudformation:CreateStack',
                'cloudformation:UpdateStack',
                'cloudformation:DeleteStack',
                'cloudformation:DescribeStacks',
                'cloudformation:DescribeStackEvents',
                'cloudformation:DescribeStackResources',
                'cloudformation:ListStackResources',
                'cloudformation:GetTemplate'
              ],
              resources: [`arn:aws:cloudformation:*:${this.account}:stack/your-app-*/*`]
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'lambda:CreateFunction',
                'lambda:UpdateFunctionCode',
                'lambda:UpdateFunctionConfiguration',
                'lambda:DeleteFunction',
                'lambda:GetFunction',
                'lambda:ListFunctions',
                'lambda:TagResource',
                'lambda:UntagResource'
              ],
              resources: [`arn:aws:lambda:*:${this.account}:function:your-app-*`]
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'iam:CreateRole',
                'iam:DeleteRole',
                'iam:GetRole',
                'iam:PassRole',
                'iam:AttachRolePolicy',
                'iam:DetachRolePolicy',
                'iam:PutRolePolicy',
                'iam:DeleteRolePolicy',
                'iam:TagRole',
                'iam:UntagRole'
              ],
              resources: [`arn:aws:iam::${this.account}:role/your-app-*`]
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'secretsmanager:GetSecretValue',
                'secretsmanager:DescribeSecret'
              ],
              resources: [`arn:aws:secretsmanager:*:${this.account}:secret:your-app/*`]
            })
          ]
        })
      }
    });

    // Output role ARN for use in GitHub Actions workflow
    new cdk.CfnOutput(this, 'DeploymentRoleArn', {
      value: this.deploymentRole.roleArn,
      description: `GitHub Actions deployment role ARN for ${props?.environment || 'development'} environment`
    });
  }
}
```

## Step 2: Configuring GitHub Actions with OIDC Authentication

GitHub Actions supports OpenID Connect (OIDC) authentication, eliminating the need for long-lived AWS credentials while providing secure, temporary access to AWS resources. Configure your workflow to use OIDC for each target account.

Create a reusable workflow that can deploy to multiple accounts:

```yaml
# .github/workflows/deploy.yml - Multi-account deployment workflow
name: Cross-Account Deployment

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy-dev:
    name: Deploy to Development
    runs-on: ubuntu-latest
    environment: development
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials for Development
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_DEV }}
          role-session-name: GitHubActions-Dev-${{ github.run_id }}
          aws-region: us-east-1

      - name: Deploy to Development Account
        run: |
          aws sts get-caller-identity
          # Deploy using AWS CDK, CloudFormation, or other tools
          npm run deploy:dev

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    environment: staging
    needs: deploy-dev
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials for Staging
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_STAGING }}
          role-session-name: GitHubActions-Staging-${{ github.run_id }}
          aws-region: us-east-1

      - name: Deploy to Staging Account
        run: |
          aws sts get-caller-identity
          npm run deploy:staging

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    environment: production
    needs: deploy-staging
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials for Production
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN_PROD }}
          role-session-name: GitHubActions-Prod-${{ github.run_id }}
          aws-region: us-east-1

      - name: Deploy to Production Account
        run: |
          aws sts get-caller-identity
          npm run deploy:prod
```

Configure GitHub repository secrets for each environment's role ARN:

```bash
# GitHub CLI commands to set up secrets
gh secret set AWS_ROLE_ARN_DEV --body "arn:aws:iam::111111111111:role/GitHubActionsDev"
gh secret set AWS_ROLE_ARN_STAGING --body "arn:aws:iam::222222222222:role/GitHubActionsStaging"  
gh secret set AWS_ROLE_ARN_PROD --body "arn:aws:iam::333333333333:role/GitHubActionsProd"
```

## Step 3: Secure Secrets Management

Effective secrets management across multiple accounts requires a layered approach combining GitHub Secrets for workflow configuration and AWS Secrets Manager for application secrets. This pattern ensures that sensitive configuration data remains secure while being accessible to deployment processes.

Store account-specific configuration in AWS Secrets Manager:

```typescript
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

interface ApplicationSecrets {
  databaseUrl: string;
  apiKeys: Record<string, string>;
  externalServiceUrls: Record<string, string>;
}

export class SecretsManager {
  private readonly client: SecretsManagerClient;

  constructor(region: string = 'us-east-1') {
    this.client = new SecretsManagerClient({ region });
  }

  async getApplicationSecrets(environment: string): Promise<ApplicationSecrets> {
    try {
      const command = new GetSecretValueCommand({
        SecretId: `your-app/${environment}/config`
      });

      const response = await this.client.send(command);
      
      if (!response.SecretString) {
        throw new Error(`Secret not found for environment: ${environment}`);
      }

      return JSON.parse(response.SecretString) as ApplicationSecrets;
    } catch (error) {
      console.error(`Failed to retrieve secrets for environment ${environment}:`, error);
      throw error;
    }
  }

  async createOrUpdateSecret(
    environment: string, 
    secrets: ApplicationSecrets
  ): Promise<void> {
    try {
      const { PutSecretValueCommand } = await import('@aws-sdk/client-secrets-manager');
      
      const command = new PutSecretValueCommand({
        SecretId: `your-app/${environment}/config`,
        SecretString: JSON.stringify(secrets, null, 2)
      });

      await this.client.send(command);
      console.log(`Successfully updated secrets for environment: ${environment}`);
    } catch (error) {
      console.error(`Failed to update secrets for environment ${environment}:`, error);
      throw error;
    }
  }
}
```

Create a deployment utility that retrieves secrets during the deployment process:

```typescript
// deploy-utils.ts - Deployment utilities with secrets management
import { SecretsManager } from './secrets-manager';
import { CloudFormationClient, DescribeStacksCommand, UpdateStackCommand } from '@aws-sdk/client-cloudformation';

export interface DeploymentConfig {
  stackName: string;
  templateUrl: string;
  environment: string;
  region: string;
}

export class CrossAccountDeployer {
  private readonly secretsManager: SecretsManager;
  private readonly cloudFormation: CloudFormationClient;

  constructor(region: string = 'us-east-1') {
    this.secretsManager = new SecretsManager(region);
    this.cloudFormation = new CloudFormationClient({ region });
  }

  async deployStack(config: DeploymentConfig): Promise<void> {
    console.log(`Starting deployment to ${config.environment} environment`);

    try {
      // Retrieve application secrets for this environment
      const secrets = await this.secretsManager.getApplicationSecrets(config.environment);

      // Prepare CloudFormation parameters
      const parameters = [
        {
          ParameterKey: 'Environment',
          ParameterValue: config.environment
        },
        {
          ParameterKey: 'DatabaseUrl',
          ParameterValue: secrets.databaseUrl
        }
      ];

      // Add additional parameters from secrets
      Object.entries(secrets.apiKeys).forEach(([key, value]) => {
        parameters.push({
          ParameterKey: `ApiKey${this.capitalizeFirst(key)}`,
          ParameterValue: value
        });
      });

      // Check if stack exists
      const stackExists = await this.stackExists(config.stackName);

      if (stackExists) {
        await this.updateStack(config, parameters);
      } else {
        await this.createStack(config, parameters);
      }

      console.log(`Successfully deployed ${config.stackName} to ${config.environment}`);
    } catch (error) {
      console.error(`Deployment failed for ${config.environment}:`, error);
      throw error;
    }
  }

  private async stackExists(stackName: string): Promise<boolean> {
    try {
      const command = new DescribeStacksCommand({ StackName: stackName });
      await this.cloudFormation.send(command);
      return true;
    } catch (error) {
      return false;
    }
  }

  private async updateStack(
    config: DeploymentConfig, 
    parameters: Array<{ ParameterKey: string; ParameterValue: string }>
  ): Promise<void> {
    const command = new UpdateStackCommand({
      StackName: config.stackName,
      TemplateURL: config.templateUrl,
      Parameters: parameters,
      Capabilities: ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
    });

    await this.cloudFormation.send(command);
  }

  private async createStack(
    config: DeploymentConfig, 
    parameters: Array<{ ParameterKey: string; ParameterValue: string }>
  ): Promise<void> {
    const { CreateStackCommand } = await import('@aws-sdk/client-cloudformation');
    
    const command = new CreateStackCommand({
      StackName: config.stackName,
      TemplateURL: config.templateUrl,
      Parameters: parameters,
      Capabilities: ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
    });

    await this.cloudFormation.send(command);
  }

  private capitalizeFirst(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
}
```

## Step 4: Implementing Role Assumption in Build Steps

GitHub Actions workflows must assume the appropriate IAM role for each target account during deployment. This pattern ensures that each deployment operation has only the necessary permissions for its specific target environment.

Create a composite action for role assumption and deployment:

```yaml
# .github/actions/deploy-to-account/action.yml - Reusable deployment action
name: 'Deploy to AWS Account'
description: 'Deploy application to a specific AWS account using role assumption'
inputs:
  role-arn:
    description: 'AWS IAM Role ARN to assume'
    required: true
  environment:
    description: 'Target environment (dev, staging, prod)'
    required: true
  stack-name:
    description: 'CloudFormation stack name'
    required: true
  template-path:
    description: 'Path to CloudFormation template'
    required: true
  aws-region:
    description: 'AWS region for deployment'
    required: false
    default: 'us-east-1'

runs:
  using: 'composite'
  steps:
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: ${{ inputs.role-arn }}
        role-session-name: GitHubActions-${{ inputs.environment }}-${{ github.run_id }}
        aws-region: ${{ inputs.aws-region }}

    - name: Verify assumed role
      shell: bash
      run: |
        echo "Assumed role identity:"
        aws sts get-caller-identity
        echo "Available permissions test:"
        aws iam list-attached-role-policies --role-name $(aws sts get-caller-identity --query Arn --output text | cut -d'/' -f2) || echo "Limited permissions - this is expected"

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      shell: bash
      run: npm ci

    - name: Build application
      shell: bash
      run: npm run build

    - name: Deploy CloudFormation stack
      shell: bash
      run: |
        npm run deploy -- \
          --environment ${{ inputs.environment }} \
          --stack-name ${{ inputs.stack-name }} \
          --template-path ${{ inputs.template-path }} \
          --region ${{ inputs.aws-region }}

    - name: Verify deployment
      shell: bash
      run: |
        aws cloudformation describe-stacks \
          --stack-name ${{ inputs.stack-name }} \
          --query 'Stacks[0].StackStatus' \
          --output text
```

Update the main workflow to use the composite action:

```yaml
# .github/workflows/deploy.yml - Updated workflow using composite action
name: Cross-Account Deployment

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  id-token: write
  contents: read

jobs:
  deploy-dev:
    name: Deploy to Development
    runs-on: ubuntu-latest
    environment: development
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Deploy to Development Account
        uses: ./.github/actions/deploy-to-account
        with:
          role-arn: ${{ secrets.AWS_ROLE_ARN_DEV }}
          environment: development
          stack-name: your-app-dev
          template-path: ./infrastructure/template.yml

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    environment: staging
    needs: deploy-dev
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Deploy to Staging Account
        uses: ./.github/actions/deploy-to-account
        with:
          role-arn: ${{ secrets.AWS_ROLE_ARN_STAGING }}
          environment: staging
          stack-name: your-app-staging
          template-path: ./infrastructure/template.yml

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    environment: production
    needs: deploy-staging
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Deploy to Production Account
        uses: ./.github/actions/deploy-to-account
        with:
          role-arn: ${{ secrets.AWS_ROLE_ARN_PROD }}
          environment: production
          stack-name: your-app-prod
          template-path: ./infrastructure/template.yml
```

## Step 5: Advanced Deployment Patterns

Complex cross-account deployments often require sophisticated patterns for handling database migrations, feature flags, and rollback scenarios. These patterns ensure reliable deployments while maintaining system stability across multiple environments.

Implement blue-green deployment across accounts:

```typescript
// blue-green-deployer.ts - Blue-green deployment implementation
import { CloudFormationClient, DescribeStacksCommand, UpdateStackCommand } from '@aws-sdk/client-cloudformation';
import { Route53Client, ChangeResourceRecordSetsCommand } from '@aws-sdk/client-route-53';
import { SecretsManager } from './secrets-manager';

export interface BlueGreenConfig {
  environment: string;
  region: string;
  stackName: string;
  domainName: string;
  hostedZoneId: string;
}

export class BlueGreenDeployer {
  private readonly cloudFormation: CloudFormationClient;
  private readonly route53: Route53Client;
  private readonly secretsManager: SecretsManager;

  constructor(region: string = 'us-east-1') {
    this.cloudFormation = new CloudFormationClient({ region });
    this.route53 = new Route53Client({ region });
    this.secretsManager = new SecretsManager(region);
  }

  async deployBlueGreen(config: BlueGreenConfig): Promise<void> {
    console.log(`Starting blue-green deployment for ${config.environment}`);

    try {
      // Determine current active environment (blue or green)
      const currentEnvironment = await this.getCurrentActiveEnvironment(config);
      const newEnvironment = currentEnvironment === 'blue' ? 'green' : 'blue';

      console.log(`Current environment: ${currentEnvironment}, deploying to: ${newEnvironment}`);

      // Deploy to inactive environment
      await this.deployToEnvironment(config, newEnvironment);

      // Run health checks on new environment
      await this.runHealthChecks(config, newEnvironment);

      // Switch traffic to new environment
      await this.switchTraffic(config, newEnvironment);

      // Verify traffic switch was successful
      await this.verifyTrafficSwitch(config, newEnvironment);

      console.log(`Blue-green deployment completed successfully for ${config.environment}`);
    } catch (error) {
      console.error(`Blue-green deployment failed for ${config.environment}:`, error);
      throw error;
    }
  }

  private async getCurrentActiveEnvironment(config: BlueGreenConfig): Promise<'blue' | 'green'> {
    try {
      const command = new DescribeStacksCommand({
        StackName: `${config.stackName}-traffic`
      });

      const response = await this.cloudFormation.send(command);
      const stack = response.Stacks?.[0];
      
      if (!stack?.Parameters) {
        return 'blue'; // Default to blue if no traffic stack exists
      }

      const activeParam = stack.Parameters.find(p => p.ParameterKey === 'ActiveEnvironment');
      return (activeParam?.ParameterValue as 'blue' | 'green') || 'blue';
    } catch (error) {
      console.log('Traffic stack not found, defaulting to blue environment');
      return 'blue';
    }
  }

  private async deployToEnvironment(config: BlueGreenConfig, environment: 'blue' | 'green'): Promise<void> {
    const secrets = await this.secretsManager.getApplicationSecrets(config.environment);
    
    const parameters = [
      {
        ParameterKey: 'Environment',
        ParameterValue: `${config.environment}-${environment}`
      },
      {
        ParameterKey: 'DatabaseUrl',
        ParameterValue: secrets.databaseUrl
      }
    ];

    const command = new UpdateStackCommand({
      StackName: `${config.stackName}-${environment}`,
      TemplateURL: `https://your-templates-bucket.s3.amazonaws.com/app-template.yml`,
      Parameters: parameters,
      Capabilities: ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
    });

    await this.cloudFormation.send(command);
    
    // Wait for deployment to complete
    await this.waitForStackUpdate(`${config.stackName}-${environment}`);
  }

  private async runHealthChecks(config: BlueGreenConfig, environment: 'blue' | 'green'): Promise<void> {
    // Get the load balancer URL for the new environment
    const stackName = `${config.stackName}-${environment}`;
    const command = new DescribeStacksCommand({ StackName: stackName });
    const response = await this.cloudFormation.send(command);
    
    const outputs = response.Stacks?.[0]?.Outputs;
    const loadBalancerUrl = outputs?.find(o => o.OutputKey === 'LoadBalancerUrl')?.OutputValue;

    if (!loadBalancerUrl) {
      throw new Error(`LoadBalancer URL not found in stack outputs for ${stackName}`);
    }

    // Perform health checks
    const healthCheckUrl = `${loadBalancerUrl}/health`;
    const maxRetries = 10;
    const retryDelay = 30000; // 30 seconds

    for (let i = 0; i < maxRetries; i++) {
      try {
        const response = await fetch(healthCheckUrl);
        if (response.ok) {
          console.log(`Health check passed for ${environment} environment`);
          return;
        }
      } catch (error) {
        console.log(`Health check attempt ${i + 1} failed, retrying...`);
      }

      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }

    throw new Error(`Health checks failed for ${environment} environment after ${maxRetries} attempts`);
  }

  private async switchTraffic(config: BlueGreenConfig, newEnvironment: 'blue' | 'green'): Promise<void> {
    // Get the new environment's load balancer DNS name
    const stackName = `${config.stackName}-${newEnvironment}`;
    const command = new DescribeStacksCommand({ StackName: stackName });
    const response = await this.cloudFormation.send(command);
    
    const outputs = response.Stacks?.[0]?.Outputs;
    const loadBalancerDns = outputs?.find(o => o.OutputKey === 'LoadBalancerDns')?.OutputValue;

    if (!loadBalancerDns) {
      throw new Error(`LoadBalancer DNS not found for ${newEnvironment} environment`);
    }

    // Update Route 53 record to point to new environment
    const changeCommand = new ChangeResourceRecordSetsCommand({
      HostedZoneId: config.hostedZoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: config.domainName,
              Type: 'CNAME',
              TTL: 60,
              ResourceRecords: [{ Value: loadBalancerDns }]
            }
          }
        ]
      }
    });

    await this.route53.send(changeCommand);
    console.log(`Traffic switched to ${newEnvironment} environment`);
  }

  private async verifyTrafficSwitch(config: BlueGreenConfig, newEnvironment: 'blue' | 'green'): Promise<void> {
    // Wait for DNS propagation and verify the switch
    const maxRetries = 5;
    const retryDelay = 60000; // 1 minute

    for (let i = 0; i < maxRetries; i++) {
      try {
        const response = await fetch(`https://${config.domainName}/health`);
        if (response.ok) {
          console.log(`Traffic switch verified for ${newEnvironment} environment`);
          return;
        }
      } catch (error) {
        console.log(`Traffic verification attempt ${i + 1} failed, retrying...`);
      }

      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }

    throw new Error(`Traffic switch verification failed after ${maxRetries} attempts`);
  }

  private async waitForStackUpdate(stackName: string): Promise<void> {
    const maxWaitTime = 30 * 60 * 1000; // 30 minutes
    const pollInterval = 30 * 1000; // 30 seconds
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const command = new DescribeStacksCommand({ StackName: stackName });
      const response = await this.cloudFormation.send(command);
      const status = response.Stacks?.[0]?.StackStatus;

      if (status?.includes('COMPLETE')) {
        console.log(`Stack ${stackName} update completed with status: ${status}`);
        return;
      }

      if (status?.includes('FAILED') || status?.includes('ROLLBACK')) {
        throw new Error(`Stack ${stackName} update failed with status: ${status}`);
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Stack ${stackName} update timed out after 30 minutes`);
  }
}
```

## Step 6: Security Best Practices and Monitoring

Implementing comprehensive security monitoring and audit trails for cross-account CI/CD pipelines ensures that deployment activities are tracked, authorized, and compliant with organizational security policies.

Set up CloudTrail logging for deployment activities:

```typescript
// audit-logger.ts - Deployment audit logging
import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

export interface AuditEvent {
  timestamp: Date;
  user: string;
  action: string;
  resource: string;
  sourceAccount: string;
  targetAccount: string;
  result: 'SUCCESS' | 'FAILURE';
  details?: Record<string, any>;
}

export class DeploymentAuditor {
  private readonly cloudTrail: CloudTrailClient;
  private readonly sns: SNSClient;

  constructor(
    private readonly notificationTopicArn: string,
    region: string = 'us-east-1'
  ) {
    this.cloudTrail = new CloudTrailClient({ region });
    this.sns = new SNSClient({ region });
  }

  async logDeploymentEvent(event: AuditEvent): Promise<void> {
    console.log('Deployment audit event:', JSON.stringify(event, null, 2));

    // Send notification for high-risk events
    if (this.isHighRiskEvent(event)) {
      await this.sendSecurityNotification(event);
    }

    // Store in audit trail (implementation depends on your requirements)
    await this.storeAuditEvent(event);
  }

  async getRecentDeploymentEvents(
    startTime: Date,
    endTime: Date,
    targetAccount?: string
  ): Promise<AuditEvent[]> {
    const command = new LookupEventsCommand({
      StartTime: startTime,
      EndTime: endTime,
      LookupAttributes: [
        {
          AttributeKey: 'EventName',
          AttributeValue: 'AssumeRoleWithWebIdentity'
        }
      ]
    });

    const response = await this.cloudTrail.send(command);
    const events: AuditEvent[] = [];

    for (const event of response.Events || []) {
      if (this.isDeploymentEvent(event) && 
          (!targetAccount || event.Username?.includes(targetAccount))) {
        events.push({
          timestamp: event.EventTime || new Date(),
          user: event.Username || 'Unknown',
          action: event.EventName || 'Unknown',
          resource: event.Resources?.[0]?.ResourceName || 'Unknown',
          sourceAccount: event.CloudTrailEvent ? 
            JSON.parse(event.CloudTrailEvent).recipientAccountId : 'Unknown',
          targetAccount: this.extractTargetAccount(event),
          result: event.ErrorCode ? 'FAILURE' : 'SUCCESS',
          details: event.CloudTrailEvent ? JSON.parse(event.CloudTrailEvent) : undefined
        });
      }
    }

    return events;
  }

  private isHighRiskEvent(event: AuditEvent): boolean {
    // Define criteria for high-risk events
    return event.targetAccount.includes('prod') || 
           event.action.includes('Delete') ||
           event.result === 'FAILURE';
  }

  private async sendSecurityNotification(event: AuditEvent): Promise<void> {
    const message = {
      alert: 'High-Risk Deployment Event',
      timestamp: event.timestamp.toISOString(),
      user: event.user,
      action: event.action,
      targetAccount: event.targetAccount,
      result: event.result,
      details: event.details
    };

    const command = new PublishCommand({
      TopicArn: this.notificationTopicArn,
      Subject: `Security Alert: ${event.action} in ${event.targetAccount}`,
      Message: JSON.stringify(message, null, 2)
    });

    await this.sns.send(command);
  }

  private async storeAuditEvent(event: AuditEvent): Promise<void> {
    // Implementation depends on your audit storage requirements
    // Could be DynamoDB, S3, CloudWatch Logs, or external SIEM
    console.log('Storing audit event:', event);
  }

  private isDeploymentEvent(event: any): boolean {
    // Logic to identify deployment-related CloudTrail events
    return event.EventName === 'AssumeRoleWithWebIdentity' &&
           event.Username?.includes('GitHubActions');
  }

  private extractTargetAccount(event: any): string {
    // Extract target account from CloudTrail event
    if (event.CloudTrailEvent) {
      const parsedEvent = JSON.parse(event.CloudTrailEvent);
      return parsedEvent.recipientAccountId || 'Unknown';
    }
    return 'Unknown';
  }
}
```

Create monitoring and alerting for deployment failures:

```typescript
// deployment-monitor.ts - Deployment monitoring and alerting
import { CloudWatchClient, PutMetricDataCommand, GetMetricStatisticsCommand } from '@aws-sdk/client-cloudwatch';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

export interface DeploymentMetrics {
  environment: string;
  duration: number;
  success: boolean;
  failureReason?: string;
  deployedServices: string[];
}

export class DeploymentMonitor {
  private readonly cloudWatch: CloudWatchClient;
  private readonly sns: SNSClient;

  constructor(
    private readonly alertTopicArn: string,
    region: string = 'us-east-1'
  ) {
    this.cloudWatch = new CloudWatchClient({ region });
    this.sns = new SNSClient({ region });
  }

  async recordDeploymentMetrics(metrics: DeploymentMetrics): Promise<void> {
    const metricData = [
      {
        MetricName: 'DeploymentDuration',
        Dimensions: [
          { Name: 'Environment', Value: metrics.environment }
        ],
        Value: metrics.duration,
        Unit: 'Seconds',
        Timestamp: new Date()
      },
      {
        MetricName: 'DeploymentSuccess',
        Dimensions: [
          { Name: 'Environment', Value: metrics.environment }
        ],
        Value: metrics.success ? 1 : 0,
        Unit: 'Count',
        Timestamp: new Date()
      },
      {
        MetricName: 'DeployedServices',
        Dimensions: [
          { Name: 'Environment', Value: metrics.environment }
        ],
        Value: metrics.deployedServices.length,
        Unit: 'Count',
        Timestamp: new Date()
      }
    ];

    const command = new PutMetricDataCommand({
      Namespace: 'CrossAccount/Deployment',
      MetricData: metricData
    });

    await this.cloudWatch.send(command);

    // Send alert if deployment failed
    if (!metrics.success) {
      await this.sendFailureAlert(metrics);
    }
  }

  async getDeploymentSuccessRate(
    environment: string,
    hours: number = 24
  ): Promise<number> {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - (hours * 60 * 60 * 1000));

    const command = new GetMetricStatisticsCommand({
      Namespace: 'CrossAccount/Deployment',
      MetricName: 'DeploymentSuccess',
      Dimensions: [
        { Name: 'Environment', Value: environment }
      ],
      StartTime: startTime,
      EndTime: endTime,
      Period: 3600, // 1 hour periods
      Statistics: ['Average']
    });

    const response = await this.cloudWatch.send(command);
    const datapoints = response.Datapoints || [];

    if (datapoints.length === 0) {
      return 1.0; // No deployments = 100% success rate
    }

    const totalSuccessRate = datapoints.reduce((sum, dp) => sum + (dp.Average || 0), 0);
    return totalSuccessRate / datapoints.length;
  }

  private async sendFailureAlert(metrics: DeploymentMetrics): Promise<void> {
    const message = {
      alert: 'Deployment Failure',
      environment: metrics.environment,
      duration: metrics.duration,
      failureReason: metrics.failureReason,
      deployedServices: metrics.deployedServices,
      timestamp: new Date().toISOString()
    };

    const command = new PublishCommand({
      TopicArn: this.alertTopicArn,
      Subject: `Deployment Failed: ${metrics.environment}`,
      Message: JSON.stringify(message, null, 2)
    });

    await this.sns.send(command);
  }
}
```

## Testing and Validation

Comprehensive testing ensures that cross-account CI/CD pipelines work reliably across all target environments. Implement automated testing that validates both the deployment process and the deployed applications.

Create integration tests for the deployment process:

```typescript
// deployment.test.ts - Integration tests for cross-account deployment
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { CrossAccountDeployer } from '../src/deploy-utils';
import { DeploymentAuditor } from '../src/audit-logger';
import { SecretsManager } from '../src/secrets-manager';

describe('Cross-Account Deployment Integration Tests', () => {
  let deployer: CrossAccountDeployer;
  let auditor: DeploymentAuditor;
  let secretsManager: SecretsManager;

  beforeAll(() => {
    deployer = new CrossAccountDeployer('us-east-1');
    auditor = new DeploymentAuditor('arn:aws:sns:us-east-1:123456789012:deployment-alerts');
    secretsManager = new SecretsManager('us-east-1');
  });

  it('should successfully assume role in development account', async () => {
    // This test requires proper AWS credentials and permissions
    const roleArn = process.env.AWS_ROLE_ARN_DEV;
    expect(roleArn).toBeDefined();

    // Test role assumption by making a simple AWS API call
    // Implementation would depend on your specific testing setup
  });

  it('should retrieve secrets from development account', async () => {
    const secrets = await secretsManager.getApplicationSecrets('development');
    
    expect(secrets).toBeDefined();
    expect(secrets.databaseUrl).toBeDefined();
    expect(secrets.apiKeys).toBeDefined();
  });

  it('should deploy stack to development account', async () => {
    const config = {
      stackName: 'test-stack-dev',
      templateUrl: 'https://test-bucket.s3.amazonaws.com/test-template.yml',
      environment: 'development',
      region: 'us-east-1'
    };

    await expect(deployer.deployStack(config)).resolves.not.toThrow();
  });

  it('should record deployment audit events', async () => {
    const auditEvent = {
      timestamp: new Date(),
      user: 'github-actions-test',
      action: 'DeployStack',
      resource: 'test-stack-dev',
      sourceAccount: '000000000000',
      targetAccount: '111111111111',
      result: 'SUCCESS' as const
    };

    await expect(auditor.logDeploymentEvent(auditEvent)).resolves.not.toThrow();
  });

  afterAll(async () => {
    // Cleanup any test resources
    // Implementation depends on your specific test setup
  });
});
```

## Troubleshooting Common Issues

Cross-account CI/CD implementations can encounter various issues related to permissions, network connectivity, and configuration. Understanding common problems and their solutions helps maintain reliable deployment pipelines.

**Permission Denied Errors** often occur when IAM roles lack necessary permissions or trust relationships are misconfigured. Verify that the GitHub OIDC provider is correctly configured in each target account and that role trust policies allow the expected repository and branches.

**Secret Retrieval Failures** can happen when AWS Secrets Manager permissions are insufficient or when secrets don't exist in the target account. Implement proper error handling and ensure that deployment roles have `secretsmanager:GetSecretValue` permissions for the required secret ARNs.

**Stack Deployment Timeouts** may occur when CloudFormation operations take longer than expected. Implement proper wait conditions and consider breaking large deployments into smaller, more manageable stacks.

**Network Connectivity Issues** between GitHub Actions and AWS services are rare but can happen. Ensure that your workflows don't have network restrictions that prevent communication with AWS APIs.

Cross-account CI/CD pipelines enable organizations to maintain consistent deployment processes across multiple AWS accounts while preserving security boundaries and organizational isolation. By implementing proper IAM roles, OIDC authentication, secure secrets management, and comprehensive monitoring, teams can build reliable deployment pipelines that scale with their multi-account architectures.

## Key Takeaways

The implementation of cross-account CI/CD delivers significant benefits that extend beyond simple automation. **Security isolation** remains intact while enabling seamless deployments, ensuring that production environments stay protected even as development velocity increases. **Operational efficiency** improves dramatically through eliminated manual processes and reduced deployment times. **Audit compliance** becomes effortless with comprehensive logging and role-based access controls that satisfy enterprise governance requirements.

The patterns demonstrated in this guide provide a foundation for implementing sophisticated DevOps workflows in enterprise environments. Start with basic cross-account deployments using GitHub Actions and OIDC authentication, then gradually introduce advanced features like blue-green deployments, comprehensive monitoring, and automated testing as your requirements evolve.

Remember that successful cross-account CI/CD is as much about organizational process as it is about technical implementation. Establish clear responsibility boundaries between teams, implement proper change management procedures, and maintain documentation that keeps everyone aligned on deployment processes and emergency procedures.

## Next Steps

Begin your cross-account CI/CD journey by implementing the foundational IAM roles and OIDC authentication patterns outlined in this post. Focus on getting basic deployments working reliably before adding complexity. Once you have a solid foundation, consider exploring **AWS CodePipeline integration** for more complex orchestration needs, **AWS Systems Manager Parameter Store** for additional configuration management, and **AWS CloudTrail integration** for enhanced audit capabilities.

In our next post in the AWS Cross-Account Patterns series, we'll dive into cross-account monitoring and observability strategies, showing how to maintain visibility into your distributed applications across account boundaries while preserving security isolation.
