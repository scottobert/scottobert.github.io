import { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } from '@aws-sdk/client-secrets-manager';

export interface ApplicationSecrets {
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
        SecretId: `cross-account/${environment}/config`
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
      const command = new PutSecretValueCommand({
        SecretId: `cross-account/${environment}/config`,
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
