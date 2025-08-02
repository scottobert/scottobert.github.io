#!/usr/bin/env node

/**
 * Script to validate the cross-account deployment setup
 * Checks AWS credentials, IAM roles, and GitHub configuration
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function main() {
  console.log('Validating cross-account deployment setup...\n');

  let hasErrors = false;

  // Check AWS CLI
  if (!checkAwsCli()) {
    hasErrors = true;
  }

  // Check CDK CLI
  if (!checkCdkCli()) {
    hasErrors = true;
  }

  // Check GitHub CLI
  if (!checkGitHubCli()) {
    hasErrors = true;
  }

  // Check configuration files
  if (!checkConfigFiles()) {
    hasErrors = true;
  }

  // Check AWS profiles
  if (!checkAwsProfiles()) {
    hasErrors = true;
  }

  if (hasErrors) {
    console.log('\n❌ Setup validation failed. Please address the issues above.');
    process.exit(1);
  } else {
    console.log('\n✅ Setup validation passed! You\'re ready to deploy.');
  }
}

function checkAwsCli() {
  try {
    const version = execSync('aws --version', { encoding: 'utf8' });
    console.log('✓ AWS CLI installed:', version.trim());
    return true;
  } catch (error) {
    console.log('✗ AWS CLI not found. Please install the AWS CLI.');
    return false;
  }
}

function checkCdkCli() {
  try {
    const version = execSync('cdk --version', { encoding: 'utf8' });
    console.log('✓ AWS CDK installed:', version.trim());
    return true;
  } catch (error) {
    console.log('✗ AWS CDK not found. Please install: npm install -g aws-cdk');
    return false;
  }
}

function checkGitHubCli() {
  try {
    const version = execSync('gh --version', { encoding: 'utf8' });
    console.log('✓ GitHub CLI installed:', version.split('\n')[0]);
    return true;
  } catch (error) {
    console.log('✗ GitHub CLI not found. Please install: https://cli.github.com/');
    return false;
  }
}

function checkConfigFiles() {
  const configPath = path.join(__dirname, '..', 'config', 'accounts.json');
  
  if (!fs.existsSync(configPath)) {
    console.log('✗ accounts.json not found. Copy accounts.example.json to accounts.json and update with your account IDs.');
    return false;
  }

  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    const environments = Object.keys(config);
    
    if (environments.length === 0) {
      console.log('✗ No environments configured in accounts.json');
      return false;
    }

    console.log('✓ Configuration file found with environments:', environments.join(', '));
    
    // Validate configuration structure
    for (const [env, envConfig] of Object.entries(config)) {
      if (!envConfig.accountId || !envConfig.region || !envConfig.githubRepository) {
        console.log(`✗ Invalid configuration for environment ${env}. Missing required fields.`);
        return false;
      }
    }

    return true;
  } catch (error) {
    console.log('✗ Invalid accounts.json format:', error.message);
    return false;
  }
}

function checkAwsProfiles() {
  try {
    const configPath = path.join(__dirname, '..', 'config', 'accounts.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    
    let allProfilesValid = true;

    for (const [environment, envConfig] of Object.entries(config)) {
      try {
        // Try to get caller identity with the profile
        const identity = execSync(`aws sts get-caller-identity --profile ${environment}`, { 
          encoding: 'utf8',
          stdio: 'pipe'
        });
        
        const identityData = JSON.parse(identity);
        
        if (identityData.Account === envConfig.accountId) {
          console.log(`✓ AWS profile '${environment}' configured correctly for account ${envConfig.accountId}`);
        } else {
          console.log(`✗ AWS profile '${environment}' is configured for account ${identityData.Account}, but expected ${envConfig.accountId}`);
          allProfilesValid = false;
        }
      } catch (error) {
        console.log(`✗ AWS profile '${environment}' not configured or accessible`);
        allProfilesValid = false;
      }
    }

    return allProfilesValid;
  } catch (error) {
    console.log('✗ Error checking AWS profiles:', error.message);
    return false;
  }
}

if (require.main === module) {
  main();
}
