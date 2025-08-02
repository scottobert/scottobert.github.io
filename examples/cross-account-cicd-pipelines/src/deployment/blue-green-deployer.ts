import { CloudFormationClient, DescribeStacksCommand, UpdateStackCommand } from '@aws-sdk/client-cloudformation';
import { Route53Client, ChangeResourceRecordSetsCommand } from '@aws-sdk/client-route-53';
import { SecretsManager } from '../secrets/secrets-manager';

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
