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
series: "AWS Cross-Account Patterns"
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

Create deployment roles in each target account with appropriate trust policies for GitHub Actions.

**The `sub` condition is the entire security boundary of this design, so get it right before anything else.** A trust policy that ends in `:*` is the most common and most dangerous mistake in GitHub Actions OIDC setups:

```json
// DO NOT DO THIS -- any workflow in the repo can assume this role
"StringLike": {
  "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
}
```

That wildcard matches every `sub` GitHub can mint for the repository: every branch, every tag, every pull request, every environment. Anyone who can get a workflow to run — a contributor pushing a branch, a pull request that touches the workflow file — can assume your **production** deployment role. The blast radius of a wildcard here is the whole target account.

Scope each role to the exact context that is allowed to assume it. For production, bind it to a GitHub Environment and use `StringEquals`, not `StringLike`:

```json
// deployment-role-trust-policy.json - production role, scoped to an environment
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::333333333333:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub":
            "repo:your-org/your-repo:environment:production"
        }
      }
    }
  ]
}
```

Note the `Federated` principal names the OIDC provider in **the account the role lives in** — `333333333333` for the production role. Each target account needs its own OIDC provider resource; there is no shared one.

The `sub` value to use depends on what triggers the deployment:

| Deployment trigger | `sub` claim to require |
| --- | --- |
| A GitHub Environment (recommended for staging/prod) | `repo:org/repo:environment:production` |
| Pushes to the default branch only | `repo:org/repo:ref:refs/heads/main` |
| Tag-triggered releases | `repo:org/repo:ref:refs/tags/v*` (with `StringLike`) |
| Pull request validation (dev account only) | `repo:org/repo:pull_request` |

Pairing the environment-scoped `sub` with a GitHub Environment that has required reviewers is what actually gates production: GitHub only issues a token with `environment:production` in the `sub` after the reviewers approve, so the approval requirement is enforced by the token itself rather than by workflow logic that a workflow edit could bypass.

Define deployment permissions that follow the principle of least privilege while enabling necessary CI/CD operations. Two details worth calling out: pin the account ID rather than using `arn:aws:iam::*:role/...` (a wildcard account in a resource ARN is meaningless at best and misleading at worst), and constrain `iam:PassRole` with an `iam:PassedToService` condition. An unconstrained `iam:PassRole` combined with `iam:CreateRole` is a privilege-escalation path: the pipeline can create a role with any permissions and pass it to a service it controls.

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
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:TagRole",
        "iam:UntagRole"
      ],
      "Resource": [
        "arn:aws:iam::333333333333:role/your-app-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::333333333333:role/your-app-*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": [
            "lambda.amazonaws.com",
            "cloudformation.amazonaws.com"
          ]
        }
      }
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

    // Create OIDC provider for GitHub Actions (only needed once per account).
    // Do not pin a thumbprint. IAM no longer relies on the thumbprint for
    // token.actions.githubusercontent.com -- it validates against the trusted
    // root CAs instead -- and hardcoded thumbprints broke deployments
    // everywhere the last time GitHub rotated its certificate.
    const oidcProvider = new iam.OpenIdConnectProvider(this, 'GitHubOidcProvider', {
      url: 'https://token.actions.githubusercontent.com',
      clientIds: ['sts.amazonaws.com']
    });

    // Create deployment role with GitHub Actions trust policy
    this.deploymentRole = new iam.Role(this, 'GitHubActionsDeploymentRole', {
      roleName: `GitHubActions${props?.environment || 'Dev'}`,
      description: `Deployment role for GitHub Actions in ${props?.environment || 'development'} environment`,
      // Scope to this environment's GitHub Environment, not `:*`.
      assumedBy: new iam.WebIdentityPrincipal(
        oidcProvider.openIdConnectProviderArn,
        {
          'StringEquals': {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
            'token.actions.githubusercontent.com:sub':
              `repo:${props?.githubRepository}:environment:${props?.environment}`
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
              actions: ['iam:PassRole'],
              resources: [`arn:aws:iam::${this.account}:role/your-app-*`],
              conditions: {
                StringEquals: {
                  'iam:PassedToService': [
                    'lambda.amazonaws.com',
                    'cloudformation.amazonaws.com'
                  ]
                }
              }
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

# `id-token: write` is what lets a job request an OIDC token, so grant it at
# the job level rather than the workflow level -- a build or lint job has no
# business being able to mint AWS credentials.
permissions:
  contents: read

# Never let two deployments to the same environment run concurrently. Without
# this, two merges in quick succession race each other through CloudFormation
# and one of them fails mid-update.
concurrency:
  group: deploy-${{ github.ref }}
  cancel-in-progress: false

jobs:
  deploy-dev:
    name: Deploy to Development
    runs-on: ubuntu-latest
    environment: development
    # Pull requests validate; they do not deploy. Without this guard, opening a
    # PR deploys to the dev account -- and combined with a wildcard `sub` claim
    # that is a straightforward path to using your account as someone else's
    # compute.
    if: github.event_name == 'push'
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials for Development
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN_DEV }}
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
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials for Staging
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN_STAGING }}
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
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Configure AWS credentials for Production
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN_PROD }}
          role-session-name: GitHubActions-Prod-${{ github.run_id }}
          aws-region: us-east-1

      - name: Deploy to Production Account
        run: |
          aws sts get-caller-identity
          npm run deploy:prod
```

Configure the role ARNs for each environment. Use **variables**, not secrets: a role ARN is not sensitive (it grants nothing without a matching trust policy), and storing it as a secret means GitHub masks it in every log line, which makes debugging a failed `AssumeRoleWithWebIdentity` needlessly painful.

```bash
# Scope each variable to its GitHub Environment so a job can only ever see
# the ARN for the environment it is deploying to.
gh variable set AWS_ROLE_ARN_DEV     --env development \
  --body "arn:aws:iam::111111111111:role/GitHubActionsDev"
gh variable set AWS_ROLE_ARN_STAGING --env staging \
  --body "arn:aws:iam::222222222222:role/GitHubActionsStaging"
gh variable set AWS_ROLE_ARN_PROD    --env production \
  --body "arn:aws:iam::333333333333:role/GitHubActionsProd"
```

Then configure the **production** environment in repository settings with required reviewers. That, combined with the `environment:production` scoped `sub` claim from Step 1, is what makes production deployments genuinely gated.

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
      // Confirm the secret exists and is readable before touching the stack,
      // so a missing secret fails fast instead of mid-deploy.
      await this.secretsManager.getApplicationSecrets(config.environment);

      // Pass only non-sensitive values as CloudFormation parameters. Parameter
      // values are returned in plaintext by DescribeStacks to anyone holding
      // `cloudformation:DescribeStacks`, and they persist in the stack's
      // history, so a database URL or API key passed this way is effectively
      // published to every reader of the account.
      const parameters = [
        {
          ParameterKey: 'Environment',
          ParameterValue: config.environment
        },
        // The secret's *name*, not its value. The template resolves it at
        // deploy time with a dynamic reference:
        //   DatabaseUrl: '{{resolve:secretsmanager:your-app/prod/config:SecretString:databaseUrl}}'
        // CloudFormation never stores the resolved value.
        {
          ParameterKey: 'ConfigSecretName',
          ParameterValue: `your-app/${config.environment}/config`
        }
      ];

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
      await this.cloudFormation.send(
        new DescribeStacksCommand({ StackName: stackName })
      );
      return true;
    } catch (error) {
      // Only "does not exist" means the stack is absent. Catching everything
      // and returning false turns a throttle or an AccessDenied into a
      // CreateStack attempt against a stack that already exists, which then
      // fails with a confusing AlreadyExistsException.
      if (
        error instanceof Error &&
        error.name === 'ValidationError' &&
        /does not exist/.test(error.message)
      ) {
        return false;
      }
      throw error;
    }
  }

  private async updateStack(
    config: DeploymentConfig,
    parameters: Array<{ ParameterKey: string; ParameterValue: string }>
  ): Promise<void> {
    try {
      await this.cloudFormation.send(new UpdateStackCommand({
        StackName: config.stackName,
        TemplateURL: config.templateUrl,
        Parameters: parameters,
        Capabilities: ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
      }));
    } catch (error) {
      // Redeploying an unchanged template throws ValidationError with this
      // message. It means "already up to date", not "failed" -- treating it as
      // an error is a classic red build for a successful no-op deploy.
      if (
        error instanceof Error &&
        /No updates are to be performed/.test(error.message)
      ) {
        console.log(`Stack ${config.stackName} is already up to date`);
        return;
      }
      throw error;
    }
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

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '22'
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

Implement blue-green deployment across accounts. Before the code, two caveats about the DNS-based approach shown here, because they determine whether it is appropriate for your workload:

- **DNS cutover is not a fast rollback.** Resolvers and JVM/client-side caches routinely ignore a 60-second TTL, so some traffic keeps hitting the old environment for minutes after the record changes. If you need a cutover you can reverse in seconds, shift traffic at the load balancer instead — weighted target groups on a single ALB listener, or CodeDeploy's built-in blue/green for ECS and Lambda.
- **The active-environment marker has to be durable.** The implementation below reads which colour is live from a CloudFormation stack parameter, so whatever performs the cutover must also write that marker back. If it does not, the next deployment reads a stale value, picks the colour that is currently serving traffic, and deploys straight over production.



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
    // Route 53 is a global service with a single endpoint in us-east-1;
    // passing the deployment region here does not do what it looks like.
    this.route53 = new Route53Client({ region: 'us-east-1' });
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

      try {
        // Verify traffic switch was successful
        await this.verifyTrafficSwitch(config, newEnvironment);
      } catch (verificationError) {
        // Roll the record back before rethrowing. Without this the deployment
        // fails *after* traffic has already moved to an environment that just
        // failed verification -- the worst of both states.
        console.error('Verification failed after cutover, rolling traffic back');
        await this.switchTraffic(config, currentEnvironment);
        throw verificationError;
      }

      // Persist which colour is now live, so the next deployment picks the
      // other one. Skipping this makes the next deploy overwrite production.
      await this.recordActiveEnvironment(config, newEnvironment);

      console.log(`Blue-green deployment completed successfully for ${config.environment}`);
    } catch (error) {
      console.error(`Blue-green deployment failed for ${config.environment}:`, error);
      throw error;
    }
  }

  private async recordActiveEnvironment(
    config: BlueGreenConfig,
    activeEnvironment: 'blue' | 'green'
  ): Promise<void> {
    await this.cloudFormation.send(new UpdateStackCommand({
      StackName: `${config.stackName}-traffic`,
      UsePreviousTemplate: true,
      Parameters: [
        { ParameterKey: 'ActiveEnvironment', ParameterValue: activeEnvironment }
      ]
    }));

    await this.waitForStackUpdate(`${config.stackName}-traffic`);
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
    // Every ALB exposes its canonical hosted zone ID; export it from the
    // application stack alongside the DNS name.
    const albHostedZoneId = outputs?.find(o => o.OutputKey === 'LoadBalancerHostedZoneId')?.OutputValue;

    if (!loadBalancerDns || !albHostedZoneId) {
      throw new Error(`LoadBalancer DNS/zone not found for ${newEnvironment} environment`);
    }

    // Use an ALIAS record, not a CNAME. DNS forbids a CNAME at a zone apex
    // (`example.com`), so a CNAME here works for `app.example.com` and fails
    // outright for the bare domain. An A-record alias to the ALB works for
    // both, costs nothing to resolve, and needs no TTL management.
    const changeCommand = new ChangeResourceRecordSetsCommand({
      HostedZoneId: config.hostedZoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: config.domainName,
              Type: 'A',
              AliasTarget: {
                DNSName: loadBalancerDns,
                HostedZoneId: albHostedZoneId,   // the ALB's zone ID, not yours
                EvaluateTargetHealth: true
              }
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
    // Prefer the SDK's own waiter over a hand-rolled poll loop -- it already
    // handles backoff and the full set of terminal states:
    //
    //   import { waitUntilStackUpdateComplete } from '@aws-sdk/client-cloudformation';
    //   await waitUntilStackUpdateComplete(
    //     { client: this.cloudFormation, maxWaitTime: 1800 },
    //     { StackName: stackName }
    //   );
    //
    // If you do write it by hand, match statuses exactly. A substring test for
    // 'COMPLETE' also matches UPDATE_ROLLBACK_COMPLETE and ROLLBACK_COMPLETE,
    // so a deployment that failed and rolled back gets reported as a success
    // and the pipeline goes green on a stack that never changed.
    const SUCCESS = new Set(['UPDATE_COMPLETE', 'CREATE_COMPLETE']);
    const FAILURE = new Set([
      'UPDATE_FAILED',
      'UPDATE_ROLLBACK_COMPLETE',
      'UPDATE_ROLLBACK_FAILED',
      'ROLLBACK_COMPLETE',
      'ROLLBACK_FAILED',
      'CREATE_FAILED',
      'DELETE_FAILED'
    ]);

    const maxWaitTime = 30 * 60 * 1000; // 30 minutes
    const pollInterval = 30 * 1000;     // 30 seconds
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const response = await this.cloudFormation.send(
        new DescribeStacksCommand({ StackName: stackName })
      );
      const status = response.Stacks?.[0]?.StackStatus ?? '';

      if (SUCCESS.has(status)) {
        console.log(`Stack ${stackName} update completed with status: ${status}`);
        return;
      }

      if (FAILURE.has(status)) {
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

  // A note on `LookupEvents`: it only reaches back 90 days, it is throttled to
  // roughly two requests per second, and it is not paginated below. It is fine
  // for ad-hoc investigation but it is not an audit trail. For retention and
  // querying, send an organization trail to S3 and query it with Athena.
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

  // `targetAccount` is a 12-digit account ID (see extractTargetAccount), so
  // testing it for the substring 'prod' never matches and every production
  // deployment is silently classified as low risk. Compare against the actual
  // account IDs instead.
  private static readonly PRODUCTION_ACCOUNT_IDS = new Set(['333333333333']);

  private isHighRiskEvent(event: AuditEvent): boolean {
    return DeploymentAuditor.PRODUCTION_ACCOUNT_IDS.has(event.targetAccount) ||
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

In our next post in the AWS Cross-Account Patterns series, we'll dive into [cross-account monitoring and observability strategies](/posts/cross-account-monitoring-observability/), showing how to maintain visibility into your distributed applications across account boundaries while preserving security isolation.

## More in This Series

This is post 3 of 5 in the **AWS Cross-Account Patterns** series:

1. [Cross-Account Lambda Access to S3](/posts/cross-account-lambda-s3-access/)
2. [Cross-Account EventBridge Integration](/posts/2025/07/30/cross-account-eventbridge-integration/)
3. **Implementing Cross-Account CI/CD Pipelines** (this post)
4. [Cross-Account Monitoring and Observability](/posts/cross-account-monitoring-observability/)
5. [Simplified Cross-Account Backup and Disaster Recovery](/posts/2025/08/20/simplified-aws-backup-cross-account/)
