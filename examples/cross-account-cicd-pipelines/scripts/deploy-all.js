#!/usr/bin/env node

/**
 * Comprehensive deployment script for cross-account CI/CD solution
 * This script orchestrates the complete setup process
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class DeploymentOrchestrator {
  constructor() {
    this.environments = ['development', 'staging', 'production'];
    this.configPath = path.join(__dirname, '..', 'config', 'accounts.json');
  }

  async deploy() {
    console.log('🚀 Starting Cross-Account CI/CD Solution Deployment\n');

    try {
      // Step 1: Validate prerequisites
      await this.validatePrerequisites();

      // Step 2: Install dependencies
      await this.installDependencies();

      // Step 3: Validate configuration
      await this.validateConfiguration();

      // Step 4: Bootstrap CDK in all accounts
      await this.bootstrapCdk();

      // Step 5: Deploy infrastructure
      await this.deployInfrastructure();

      // Step 6: Set up GitHub secrets
      await this.setupGitHubSecrets();

      // Step 7: Validate deployment
      await this.validateDeployment();

      console.log('\n✅ Deployment completed successfully!');
      this.printNextSteps();

    } catch (error) {
      console.error('\n❌ Deployment failed:', error.message);
      process.exit(1);
    }
  }

  async validatePrerequisites() {
    console.log('📋 Validating prerequisites...');

    const requirements = [
      { cmd: 'node --version', name: 'Node.js' },
      { cmd: 'npm --version', name: 'npm' },
      { cmd: 'aws --version', name: 'AWS CLI' },
      { cmd: 'cdk --version', name: 'AWS CDK' },
      { cmd: 'gh --version', name: 'GitHub CLI' }
    ];

    for (const req of requirements) {
      try {
        const version = execSync(req.cmd, { encoding: 'utf8', stdio: 'pipe' });
        console.log(`  ✓ ${req.name}: ${version.trim().split('\n')[0]}`);
      } catch (error) {
        throw new Error(`${req.name} is not installed or not in PATH`);
      }
    }
  }

  async installDependencies() {
    console.log('\n📦 Installing dependencies...');
    
    execSync('npm ci', { stdio: 'inherit' });
    console.log('  ✓ Dependencies installed');
  }

  async validateConfiguration() {
    console.log('\n⚙️ Validating configuration...');

    if (!fs.existsSync(this.configPath)) {
      throw new Error('accounts.json not found. Please copy accounts.example.json to accounts.json and update with your values');
    }

    const config = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
    
    for (const env of this.environments) {
      if (!config[env]) {
        throw new Error(`Configuration missing for environment: ${env}`);
      }

      const envConfig = config[env];
      if (!envConfig.accountId || !envConfig.region || !envConfig.githubRepository) {
        throw new Error(`Incomplete configuration for environment: ${env}`);
      }

      // Validate AWS profile access
      try {
        const identity = execSync(`aws sts get-caller-identity --profile ${env}`, {
          encoding: 'utf8',
          stdio: 'pipe'
        });
        
        const identityData = JSON.parse(identity);
        if (identityData.Account !== envConfig.accountId) {
          throw new Error(`AWS profile '${env}' account mismatch: expected ${envConfig.accountId}, got ${identityData.Account}`);
        }
        
        console.log(`  ✓ ${env}: Profile configured for account ${envConfig.accountId}`);
      } catch (error) {
        throw new Error(`AWS profile '${env}' not configured or accessible: ${error.message}`);
      }
    }
  }

  async bootstrapCdk() {
    console.log('\n🏗️ Bootstrapping CDK...');

    for (const env of this.environments) {
      try {
        console.log(`  Bootstrapping ${env}...`);
        execSync(`cdk bootstrap --profile ${env}`, { stdio: 'pipe' });
        console.log(`  ✓ ${env}: CDK bootstrapped`);
      } catch (error) {
        // CDK bootstrap might already exist, check if it's actually an error
        if (error.message.includes('already bootstrapped')) {
          console.log(`  ✓ ${env}: Already bootstrapped`);
        } else {
          throw new Error(`CDK bootstrap failed for ${env}: ${error.message}`);
        }
      }
    }
  }

  async deployInfrastructure() {
    console.log('\n🚀 Deploying infrastructure...');

    for (const env of this.environments) {
      console.log(`  Deploying to ${env}...`);
      
      try {
        execSync(`npm run deploy:${env}`, { stdio: 'inherit' });
        console.log(`  ✓ ${env}: Infrastructure deployed`);
      } catch (error) {
        throw new Error(`Infrastructure deployment failed for ${env}: ${error.message}`);
      }
    }
  }

  async setupGitHubSecrets() {
    console.log('\n🔐 Setting up GitHub secrets...');

    try {
      // Check if we're in a git repository
      execSync('git rev-parse --git-dir', { stdio: 'pipe' });
      
      // Check if GitHub CLI is authenticated
      execSync('gh auth status', { stdio: 'pipe' });
      
      execSync('node scripts/setup-github-secrets.js', { stdio: 'inherit' });
      console.log('  ✓ GitHub secrets configured');
    } catch (error) {
      console.log('  ⚠️ GitHub secrets setup skipped (not in git repo or not authenticated)');
      console.log('    Run "npm run setup:github-secrets" manually after setting up your repository');
    }
  }

  async validateDeployment() {
    console.log('\n🔍 Validating deployment...');

    const config = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));

    for (const env of this.environments) {
      const { accountId } = config[env];
      
      try {
        // Check if stacks exist
        const stacks = execSync(
          `aws cloudformation list-stacks --profile ${env} --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[?contains(StackName, \`${env}\`)].StackName' --output text`,
          { encoding: 'utf8', stdio: 'pipe' }
        );

        const stackCount = stacks.trim().split('\n').filter(s => s.trim()).length;
        if (stackCount >= 3) { // Expect at least 3 stacks per environment
          console.log(`  ✓ ${env}: ${stackCount} stacks deployed successfully`);
        } else {
          console.log(`  ⚠️ ${env}: Only ${stackCount} stacks found (expected 3+)`);
        }
      } catch (error) {
        console.log(`  ⚠️ ${env}: Could not validate stacks: ${error.message}`);
      }
    }
  }

  printNextSteps() {
    console.log('\n📋 Next Steps:');
    console.log('');
    console.log('1. 🔗 Set up your GitHub repository:');
    console.log('   - Push this code to your GitHub repository');
    console.log('   - Configure branch protection rules');
    console.log('   - Set up environment protection rules');
    console.log('');
    console.log('2. 📧 Update monitoring configuration:');
    console.log('   - Edit infrastructure/lib/monitoring-stack.ts');
    console.log('   - Replace "your-email@example.com" with your actual email');
    console.log('   - Redeploy: npm run deploy:dev && npm run deploy:staging && npm run deploy:prod');
    console.log('');
    console.log('3. 🧪 Test the pipeline:');
    console.log('   - Make a small change to the code');
    console.log('   - Commit and push to trigger the workflow');
    console.log('   - Monitor the GitHub Actions deployment');
    console.log('');
    console.log('4. 📊 Monitor deployments:');
    console.log('   - Check CloudWatch dashboards in each account');
    console.log('   - Subscribe to SNS notifications');
    console.log('   - Review deployment metrics and logs');
    console.log('');
    console.log('🔗 Useful Links:');
    console.log('   - Documentation: ./README.md');
    console.log('   - Infrastructure Guide: ./infrastructure/README.md');
    console.log('   - GitHub Actions Guide: ./.github/README.md');
    console.log('   - Testing Guide: ./tests/README.md');
  }
}

// Run the deployment orchestrator
if (require.main === module) {
  const orchestrator = new DeploymentOrchestrator();
  orchestrator.deploy().catch(error => {
    console.error('Deployment orchestrator failed:', error);
    process.exit(1);
  });
}
