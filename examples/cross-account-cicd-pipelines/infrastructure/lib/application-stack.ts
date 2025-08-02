import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface ApplicationStackProps extends cdk.StackProps {
  environment: string;
  deploymentRole: iam.Role;
}

export class ApplicationStack extends cdk.Stack {
  public readonly applicationBucket: s3.Bucket;
  public readonly sampleLambda: lambda.Function;
  public readonly applicationSecrets: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: ApplicationStackProps) {
    super(scope, id, props);

    // Create secrets for application configuration
    this.applicationSecrets = new secretsmanager.Secret(this, 'ApplicationSecrets', {
      secretName: `cross-account/${props.environment}/config`,
      description: `Application configuration for ${props.environment} environment`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          databaseUrl: `postgresql://localhost:5432/myapp_${props.environment}`,
          externalServiceUrls: {
            paymentService: `https://payment-${props.environment}.example.com`,
            notificationService: `https://notifications-${props.environment}.example.com`
          }
        }),
        generateStringKey: 'apiKey',
        includeSpace: false,
        excludeCharacters: '"@/\\'
      }
    });

    // Create S3 bucket for application data
    this.applicationBucket = new s3.Bucket(this, 'ApplicationBucket', {
      bucketName: `cross-account-app-${props.environment}-${cdk.Aws.ACCOUNT_ID}`,
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      lifecycleRules: [
        {
          id: 'DeleteOldVersions',
          enabled: true,
          noncurrentVersionExpiration: cdk.Duration.days(90)
        }
      ],
      removalPolicy: props.environment === 'production' 
        ? cdk.RemovalPolicy.RETAIN 
        : cdk.RemovalPolicy.DESTROY
    });

    // Create execution role for Lambda
    const lambdaRole = new iam.Role(this, 'LambdaExecutionRole', {
      roleName: `cross-account-lambda-${props.environment}`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
      ],
      inlinePolicies: {
        SecretsAccess: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'secretsmanager:GetSecretValue',
                'secretsmanager:DescribeSecret'
              ],
              resources: [this.applicationSecrets.secretArn]
            })
          ]
        }),
        S3Access: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                's3:GetObject',
                's3:PutObject',
                's3:DeleteObject',
                's3:ListBucket'
              ],
              resources: [
                this.applicationBucket.bucketArn,
                `${this.applicationBucket.bucketArn}/*`
              ]
            })
          ]
        })
      }
    });

    // Create sample Lambda function
    this.sampleLambda = new lambda.Function(this, 'SampleFunction', {
      functionName: `cross-account-sample-${props.environment}`,
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      role: lambdaRole,
      environment: {
        ENVIRONMENT: props.environment,
        SECRETS_NAME: this.applicationSecrets.secretName,
        BUCKET_NAME: this.applicationBucket.bucketName
      },
      code: lambda.Code.fromInline(`
const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const secretsClient = new SecretsManagerClient();
const s3Client = new S3Client();

exports.handler = async (event) => {
  console.log('Event:', JSON.stringify(event, null, 2));
  
  try {
    // Get secrets
    const secretsResponse = await secretsClient.send(new GetSecretValueCommand({
      SecretId: process.env.SECRETS_NAME
    }));
    
    const secrets = JSON.parse(secretsResponse.SecretString);
    console.log('Successfully retrieved secrets');
    
    // Write a test file to S3
    const testData = {
      timestamp: new Date().toISOString(),
      environment: process.env.ENVIRONMENT,
      message: 'Hello from cross-account deployment!',
      secrets: Object.keys(secrets) // Don't log actual secret values
    };
    
    await s3Client.send(new PutObjectCommand({
      Bucket: process.env.BUCKET_NAME,
      Key: \`test-data/\${Date.now()}.json\`,
      Body: JSON.stringify(testData, null, 2),
      ContentType: 'application/json'
    }));
    
    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Success',
        environment: process.env.ENVIRONMENT,
        timestamp: new Date().toISOString()
      })
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        message: 'Error',
        error: error.message
      })
    };
  }
};
      `),
      timeout: cdk.Duration.seconds(30),
      memorySize: 256
    });

    // Outputs
    new cdk.CfnOutput(this, 'ApplicationBucketName', {
      value: this.applicationBucket.bucketName,
      description: `Application S3 bucket for ${props.environment} environment`,
      exportName: `ApplicationBucketName-${props.environment}`
    });

    new cdk.CfnOutput(this, 'SampleLambdaArn', {
      value: this.sampleLambda.functionArn,
      description: `Sample Lambda function ARN for ${props.environment} environment`,
      exportName: `SampleLambdaArn-${props.environment}`
    });

    new cdk.CfnOutput(this, 'ApplicationSecretsArn', {
      value: this.applicationSecrets.secretArn,
      description: `Application secrets ARN for ${props.environment} environment`,
      exportName: `ApplicationSecretsArn-${props.environment}`
    });
  }
}
