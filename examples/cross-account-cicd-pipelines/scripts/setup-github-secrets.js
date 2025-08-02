#!/usr/bin/env node

/**
 * Script to set up GitHub repository secrets for cross-account CI/CD
 * Requires GitHub CLI (gh) to be installed and authenticated
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function main() {
  console.log('Setting up GitHub secrets for cross-account CI/CD...');

  // Check if GitHub CLI is installed
  try {
    execSync('gh --version', { stdio: 'pipe' });
  } catch (error) {
    console.error('GitHub CLI (gh) is not installed. Please install it first: https://cli.github.com/');
    process.exit(1);
  }

  // Load account configuration
  const configPath = path.join(__dirname, '..', 'config', 'accounts.json');
  
  if (!fs.existsSync(configPath)) {
    console.error('accounts.json not found. Please copy accounts.example.json to accounts.json and update with your account IDs.');
    process.exit(1);
  }

  const accounts = JSON.parse(fs.readFileSync(configPath, 'utf8'));

  // Set secrets for each environment
  for (const [environment, config] of Object.entries(accounts)) {
    const roleArn = `arn:aws:iam::${config.accountId}:role/GitHubActions${capitalizeFirst(environment)}`;
    const secretName = `AWS_ROLE_ARN_${environment.toUpperCase()}`;

    try {
      console.log(`Setting secret ${secretName}...`);
      execSync(`gh secret set ${secretName} --body "${roleArn}"`, { stdio: 'inherit' });
      console.log(`✓ Secret ${secretName} set successfully`);
    } catch (error) {
      console.error(`✗ Failed to set secret ${secretName}:`, error.message);
    }
  }

  console.log('\nGitHub secrets setup completed!');
  console.log('\nNext steps:');
  console.log('1. Deploy the infrastructure to each AWS account');
  console.log('2. Update the email addresses in the monitoring stack configuration');
  console.log('3. Test the deployment pipeline by pushing to the main branch');
}

function capitalizeFirst(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

if (require.main === module) {
  main();
}
