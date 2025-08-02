#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { GitHubActionsRoleStack } from '../lib/github-actions-role-stack';
import { ApplicationStack } from '../lib/application-stack';
import { MonitoringStack } from '../lib/monitoring-stack';
import { accountConfig } from '../../config/accounts';

const app = new cdk.App();

// Get environment from context
const environment = app.node.tryGetContext('environment') || 'development';
const account = accountConfig[environment];

if (!account) {
  throw new Error(`Invalid environment: ${environment}. Must be one of: ${Object.keys(accountConfig).join(', ')}`);
}

const env = {
  account: account.accountId,
  region: account.region || 'us-east-1'
};

// Create GitHub Actions role stack
const githubRoleStack = new GitHubActionsRoleStack(app, `GitHubActionsRole-${environment}`, {
  env,
  githubRepository: account.githubRepository,
  environment,
  description: `GitHub Actions deployment role for ${environment} environment`
});

// Create application stack
const applicationStack = new ApplicationStack(app, `Application-${environment}`, {
  env,
  environment,
  deploymentRole: githubRoleStack.deploymentRole,
  description: `Application infrastructure for ${environment} environment`
});

// Create monitoring stack
const monitoringStack = new MonitoringStack(app, `Monitoring-${environment}`, {
  env,
  environment,
  applicationStack,
  description: `Monitoring and alerting for ${environment} environment`
});

// Add dependencies
applicationStack.addDependency(githubRoleStack);
monitoringStack.addDependency(applicationStack);

// Add tags
const tags = {
  Environment: environment,
  Project: 'cross-account-cicd',
  ManagedBy: 'CDK'
};

Object.entries(tags).forEach(([key, value]) => {
  cdk.Tags.of(app).add(key, value);
});
