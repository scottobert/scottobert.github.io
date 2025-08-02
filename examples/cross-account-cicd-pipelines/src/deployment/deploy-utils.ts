import { SecretsManager } from '../secrets/secrets-manager';
import { CloudFormationClient, DescribeStacksCommand, UpdateStackCommand, CreateStackCommand } from '@aws-sdk/client-cloudformation';

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
