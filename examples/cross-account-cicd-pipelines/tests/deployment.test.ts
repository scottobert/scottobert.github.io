import { describe, it, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { CrossAccountDeployer } from '../src/deployment/deploy-utils';
import { DeploymentAuditor } from '../src/monitoring/audit-logger';
import { SecretsManager } from '../src/secrets/secrets-manager';

// Mock AWS SDK clients
jest.mock('@aws-sdk/client-cloudformation');
jest.mock('@aws-sdk/client-secrets-manager');
jest.mock('@aws-sdk/client-cloudtrail');
jest.mock('@aws-sdk/client-sns');

describe('Cross-Account Deployment Integration Tests', () => {
  let deployer: CrossAccountDeployer;
  let auditor: DeploymentAuditor;
  let secretsManager: SecretsManager;

  beforeAll(() => {
    deployer = new CrossAccountDeployer('us-east-1');
    auditor = new DeploymentAuditor('arn:aws:sns:us-east-1:123456789012:deployment-alerts');
    secretsManager = new SecretsManager('us-east-1');
  });

  describe('SecretsManager', () => {
    it('should retrieve application secrets', async () => {
      const mockSecrets = {
        databaseUrl: 'postgresql://localhost:5432/myapp_dev',
        apiKeys: {
          paymentService: 'test-api-key'
        },
        externalServiceUrls: {
          paymentService: 'https://payment-dev.example.com'
        }
      };

      // Mock the secrets manager response
      const mockSecretsManagerClient = {
        send: jest.fn().mockResolvedValue({
          SecretString: JSON.stringify(mockSecrets)
        })
      };

      // Replace the client instance
      (secretsManager as any).client = mockSecretsManagerClient;

      const secrets = await secretsManager.getApplicationSecrets('development');
      
      expect(secrets).toEqual(mockSecrets);
      expect(mockSecretsManagerClient.send).toHaveBeenCalledTimes(1);
    });

    it('should handle missing secrets gracefully', async () => {
      const mockSecretsManagerClient = {
        send: jest.fn().mockRejectedValue(new Error('Secret not found'))
      };

      (secretsManager as any).client = mockSecretsManagerClient;

      await expect(secretsManager.getApplicationSecrets('nonexistent'))
        .rejects.toThrow('Secret not found');
    });
  });

  describe('CrossAccountDeployer', () => {
    it('should deploy stack successfully', async () => {
      const mockCloudFormationClient = {
        send: jest.fn()
          .mockResolvedValueOnce({}) // DescribeStacks call (stack doesn't exist)
          .mockResolvedValueOnce({}) // CreateStack call
      };

      const mockSecretsManagerClient = {
        send: jest.fn().mockResolvedValue({
          SecretString: JSON.stringify({
            databaseUrl: 'postgresql://localhost:5432/myapp_dev',
            apiKeys: { test: 'key' },
            externalServiceUrls: {}
          })
        })
      };

      // Mock the first DescribeStacks call to throw (stack doesn't exist)
      mockCloudFormationClient.send
        .mockRejectedValueOnce(new Error('Stack not found'))
        .mockResolvedValueOnce({}); // CreateStack succeeds

      (deployer as any).cloudFormation = mockCloudFormationClient;
      (deployer as any).secretsManager.client = mockSecretsManagerClient;

      const config = {
        stackName: 'test-stack-dev',
        templateUrl: 'https://test-bucket.s3.amazonaws.com/test-template.yml',
        environment: 'development',
        region: 'us-east-1'
      };

      await expect(deployer.deployStack(config)).resolves.not.toThrow();
      
      // Verify CreateStack was called
      expect(mockCloudFormationClient.send).toHaveBeenCalledTimes(2);
    });
  });

  describe('DeploymentAuditor', () => {
    it('should log deployment events', async () => {
      const mockSNSClient = {
        send: jest.fn().mockResolvedValue({})
      };

      (auditor as any).sns = mockSNSClient;

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

    it('should send alerts for high-risk events', async () => {
      const mockSNSClient = {
        send: jest.fn().mockResolvedValue({})
      };

      (auditor as any).sns = mockSNSClient;

      const highRiskEvent = {
        timestamp: new Date(),
        user: 'github-actions-test',
        action: 'DeleteStack',
        resource: 'test-stack-prod',
        sourceAccount: '000000000000',
        targetAccount: '333333333333', // Production account
        result: 'SUCCESS' as const
      };

      await auditor.logDeploymentEvent(highRiskEvent);

      // Verify SNS publish was called for high-risk event
      expect(mockSNSClient.send).toHaveBeenCalled();
    });
  });

  afterAll(async () => {
    // Cleanup any test resources
    jest.restoreAllMocks();
  });
});
