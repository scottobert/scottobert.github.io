import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface GitHubActionsRoleStackProps extends cdk.StackProps {
  githubRepository: string;
  environment: string;
}

export class GitHubActionsRoleStack extends cdk.Stack {
  public readonly deploymentRole: iam.Role;
  public readonly oidcProvider: iam.OpenIdConnectProvider;

  constructor(scope: Construct, id: string, props: GitHubActionsRoleStackProps) {
    super(scope, id, props);

    // Create OIDC provider for GitHub Actions (only needed once per account)
    this.oidcProvider = new iam.OpenIdConnectProvider(this, 'GitHubOidcProvider', {
      url: 'https://token.actions.githubusercontent.com',
      clientIds: ['sts.amazonaws.com'],
      thumbprints: ['6938fd4d98bab03faadb97b34396831e3780aea1'],
      tags: {
        Name: `GitHub-OIDC-Provider-${props.environment}`,
        Environment: props.environment
      }
    });

    // Create deployment role with GitHub Actions trust policy
    this.deploymentRole = new iam.Role(this, 'GitHubActionsDeploymentRole', {
      roleName: `GitHubActions${this.capitalizeFirst(props.environment)}`,
      description: `Deployment role for GitHub Actions in ${props.environment} environment`,
      assumedBy: new iam.WebIdentityPrincipal(
        this.oidcProvider.openIdConnectProviderArn,
        {
          'StringLike': {
            'token.actions.githubusercontent.com:sub': `repo:${props.githubRepository}:*`
          },
          'StringEquals': {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'
          }
        }
      ),
      maxSessionDuration: cdk.Duration.hours(1),
      inlinePolicies: {
        DeploymentPolicy: this.createDeploymentPolicy(),
        SecretsManagerPolicy: this.createSecretsManagerPolicy(),
        MonitoringPolicy: this.createMonitoringPolicy()
      },
      tags: {
        Name: `GitHubActions-${props.environment}`,
        Environment: props.environment,
        Purpose: 'CI/CD Deployment'
      }
    });

    // Output role ARN for use in GitHub Actions workflow
    new cdk.CfnOutput(this, 'DeploymentRoleArn', {
      value: this.deploymentRole.roleArn,
      description: `GitHub Actions deployment role ARN for ${props.environment} environment`,
      exportName: `GitHubActionsRoleArn-${props.environment}`
    });

    new cdk.CfnOutput(this, 'OIDCProviderArn', {
      value: this.oidcProvider.openIdConnectProviderArn,
      description: `GitHub OIDC provider ARN for ${props.environment} environment`,
      exportName: `GitHubOIDCProviderArn-${props.environment}`
    });
  }

  private createDeploymentPolicy(): iam.PolicyDocument {
    return new iam.PolicyDocument({
      statements: [
        // CloudFormation permissions
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
            'cloudformation:GetTemplate',
            'cloudformation:ListStacks',
            'cloudformation:DescribeStackResource'
          ],
          resources: [
            `arn:aws:cloudformation:*:${this.account}:stack/Application-*/*`,
            `arn:aws:cloudformation:*:${this.account}:stack/Monitoring-*/*`
          ]
        }),
        // Lambda permissions
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
            'lambda:UntagResource',
            'lambda:PublishVersion',
            'lambda:CreateAlias',
            'lambda:UpdateAlias',
            'lambda:DeleteAlias'
          ],
          resources: [`arn:aws:lambda:*:${this.account}:function:cross-account-*`]
        }),
        // IAM permissions for deployment
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
            'iam:UntagRole',
            'iam:ListAttachedRolePolicies',
            'iam:ListRolePolicies'
          ],
          resources: [`arn:aws:iam::${this.account}:role/cross-account-*`]
        }),
        // S3 permissions for deployment artifacts
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            's3:GetObject',
            's3:PutObject',
            's3:DeleteObject',
            's3:ListBucket'
          ],
          resources: [
            `arn:aws:s3:::cdk-*-${this.account}-*`,
            `arn:aws:s3:::cdk-*-${this.account}-*/*`
          ]
        })
      ]
    });
  }

  private createSecretsManagerPolicy(): iam.PolicyDocument {
    return new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'secretsmanager:GetSecretValue',
            'secretsmanager:DescribeSecret',
            'secretsmanager:CreateSecret',
            'secretsmanager:UpdateSecret',
            'secretsmanager:PutSecretValue',
            'secretsmanager:TagResource'
          ],
          resources: [`arn:aws:secretsmanager:*:${this.account}:secret:cross-account/*`]
        })
      ]
    });
  }

  private createMonitoringPolicy(): iam.PolicyDocument {
    return new iam.PolicyDocument({
      statements: [
        // CloudWatch permissions
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'cloudwatch:PutMetricData',
            'cloudwatch:GetMetricStatistics',
            'cloudwatch:ListMetrics'
          ],
          resources: ['*']
        }),
        // SNS permissions for alerts
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'sns:Publish',
            'sns:CreateTopic',
            'sns:Subscribe',
            'sns:Unsubscribe',
            'sns:ListTopics',
            'sns:GetTopicAttributes'
          ],
          resources: [`arn:aws:sns:*:${this.account}:cross-account-*`]
        })
      ]
    });
  }

  private capitalizeFirst(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }
}
