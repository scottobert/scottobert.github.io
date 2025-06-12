---
title: "AWS CDK Infrastructure as Code with TypeScript"
date: 2023-07-23T10:00:00-07:00
draft: false
categories: ["Cloud Computing", "Infrastructure as Code"]
tags:
- AWS
- TypeScript
- CDK
- Infrastructure
- DevOps
- Serverless
series: "AWS and Typescript"
---

Managing cloud infrastructure through code brings numerous advantages over manual configuration, including version control, reproducibility, and automated deployment pipelines. In this post, we'll explore how to use AWS CDK (Cloud Development Kit) with TypeScript to create, manage, and deploy serverless applications with infrastructure that's as maintainable and type-safe as your application code.

## Why CDK with TypeScript?

AWS CDK offers a compelling alternative to traditional infrastructure tools by allowing you to define cloud resources using familiar programming languages. When combined with TypeScript, CDK provides compile-time type checking, intelligent code completion, and the ability to create reusable, composable infrastructure components.

The key advantages of this approach include:

- **Type Safety**: Catch configuration errors at compile time rather than deployment time
- **Code Reuse**: Create modular constructs that can be shared across projects and teams
- **Developer Experience**: Leverage familiar IDE features like autocomplete and refactoring
- **Testing**: Apply unit testing practices to your infrastructure code
- **Maintainability**: Use object-oriented patterns and abstractions to manage complexity

Let's examine the architecture we'll be building throughout this post:

{{< plantuml id="cdk-architecture" >}}
@startuml
!theme aws-orange
title AWS Serverless Application Architecture with CDK

package "API Layer" {
  [API Gateway] as api
  [Lambda Authorizer] as auth
}

package "Application Layer" {
  [Create User Lambda] as createUser
  [Get User Lambda] as getUser
  [Update User Lambda] as updateUser
  [Delete User Lambda] as deleteUser
}

package "Data Layer" {
  [DynamoDB Table] as db
  [DynamoDB Streams] as streams
}

package "Monitoring" {
  [CloudWatch Logs] as logs
  [CloudWatch Metrics] as metrics
  [CloudWatch Alarms] as alarms
}

api --> createUser
api --> getUser
api --> updateUser
api --> deleteUser

createUser --> db
getUser --> db
updateUser --> db
deleteUser --> db

db --> streams

createUser --> logs
getUser --> logs
updateUser --> logs
deleteUser --> logs

logs --> metrics
metrics --> alarms

auth --> api

@enduml
{{< /plantuml >}}

This architecture demonstrates how CDK helps us manage complex infrastructure dependencies while maintaining clear separation of concerns between different layers of our application.

## Prerequisites

Before diving into CDK development, ensure you have the necessary tools and knowledge. You'll need Node.js (v18 or later) and the AWS CDK CLI installed globally via `npm install -g aws-cdk`. The AWS CLI should be configured with appropriate credentials and permissions for resource creation. Familiarity with our previous posts on Lambda, DynamoDB, and API Gateway will provide helpful context for understanding the infrastructure patterns we'll implement.

## Project Structure and Setup

A well-organized CDK project structure is crucial for maintainability and scalability. Here's how we'll organize our serverless application:

{{< plantuml id="project-structure" >}}
@startuml
!theme plain

folder "aws-serverless-app-cdk" {
  folder "lib" {
    folder "constructs" {
      file "lambda-api-construct.ts"
      file "dynamodb-construct.ts"
      file "api-gateway-construct.ts"
    }
    folder "types" {
      file "stack-config.ts"
    }
    file "serverless-app-stack.ts"
  }
  folder "config" {
    file "dev.ts"
    file "staging.ts"
    file "prod.ts"
  }
  folder "test" {
    file "constructs.test.ts"
  }
  file "bin/app.ts"
  file "cdk.json"
  file "package.json"
}
@enduml
{{< /plantuml >}}

Let's start by setting up the project and defining our configuration types. The beauty of CDK is that we can use familiar TypeScript patterns to define our infrastructure configuration, making it both type-safe and environment-aware.

First, initialize your CDK project and install the necessary dependencies:

```bash
mkdir aws-serverless-app-cdk && cd aws-serverless-app-cdk
cdk init app --language typescript
npm install @aws-cdk/aws-apigatewayv2-alpha @aws-cdk/aws-apigatewayv2-integrations-alpha
```

The foundation of any scalable CDK project is a well-defined configuration interface. This interface acts as a contract between different environments and ensures consistency across deployments:

```typescript
// lib/types/stack-config.ts
export interface StackConfig {
  app: {
    environment: 'dev' | 'staging' | 'prod';
    region: string;
    domainName?: string;
    enableXRay: boolean;
    corsOrigins: string[];
  };
  database: {
    billingMode: 'PAY_PER_REQUEST' | 'PROVISIONED';
    pointInTimeRecovery: boolean;
    enableStreams: boolean;
  };
  lambda: {
    memorySize: number;
    timeout: number;
    reservedConcurrency?: number;
    environment: Record<string, string>;
  };
  monitoring: {
    enableDetailedMetrics: boolean;
    alarmEmail?: string;
    errorThreshold: number;
    latencyThreshold: number;
  };
}
```

This configuration-driven approach provides several critical advantages. First, it enables type safety - TypeScript will catch missing or incorrect configuration values at compile time. Second, it promotes consistency across environments by ensuring the same configuration structure is used everywhere. Finally, it makes infrastructure changes more predictable and reviewable, as modifications to configuration are explicit and tracked in version control.

## Reusable Constructs

The true power of CDK lies in creating reusable constructs that encapsulate infrastructure best practices. Think of constructs as Lego blocks for cloud infrastructure - they can be assembled into complex architectures while hiding implementation details and promoting consistency.

### Lambda Function Construct

Lambda functions form the core of our serverless application. Rather than configuring each function individually, we'll create a construct that encapsulates all the best practices: proper logging, X-Ray tracing, optimized bundling, and standardized permissions.

```typescript
// lib/constructs/lambda-api-construct.ts
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as nodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface LambdaApiProps {
  functionName: string;
  entry: string;
  environment: Record<string, string>;
  timeout: cdk.Duration;
  memorySize: number;
  enableXRay?: boolean;
}

export class LambdaApiConstruct extends Construct {
  public readonly function: nodejs.NodejsFunction;

  constructor(scope: Construct, id: string, props: LambdaApiProps) {
    super(scope, id);

    // Create optimized Lambda function with best practices built-in
    this.function = new nodejs.NodejsFunction(this, props.functionName, {
      functionName: props.functionName,
      entry: props.entry,
      runtime: lambda.Runtime.NODEJS_18_X,
      timeout: props.timeout,
      memorySize: props.memorySize,
      environment: {
        NODE_OPTIONS: '--enable-source-maps',
        ...props.environment,
      },
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'es2022',
        format: nodejs.OutputFormat.ESM,
      },
      tracing: props.enableXRay ? lambda.Tracing.ACTIVE : lambda.Tracing.DISABLED,
    });

    // Standardized tags for resource management
    cdk.Tags.of(this.function).add('Component', 'Lambda');
  }

  // Helper method for DynamoDB permissions
  public grantDynamoDbAccess(tableArn: string): void {
    this.function.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:Query', 'dynamodb:Scan'],
      resources: [tableArn, `${tableArn}/index/*`],
    }));
  }
}
```

This construct approach brings several benefits to your infrastructure. **Consistency** is automatically enforced - every Lambda function follows the same configuration patterns without manual setup. **Best practices** are built-in by default, including source maps for debugging, optimized bundling for performance, and proper tracing configuration. Most importantly, **maintainability** is dramatically improved since changes to Lambda configuration can be made in one place and propagated to all functions.

### DynamoDB Construct

DynamoDB often requires complex configuration for Global Secondary Indexes, encryption, backup policies, and stream configuration. Our construct simplifies this complexity while ensuring production-ready defaults:

```typescript
// lib/constructs/dynamodb-construct.ts
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';

export interface DynamoDbTableProps {
  tableName: string;
  partitionKey: { name: string; type: dynamodb.AttributeType };
  sortKey?: { name: string; type: dynamodb.AttributeType };
  globalSecondaryIndexes?: Array<{
    indexName: string;
    partitionKey: { name: string; type: dynamodb.AttributeType };
    sortKey?: { name: string; type: dynamodb.AttributeType };
  }>;
  pointInTimeRecovery: boolean;
  enableStreams: boolean;
}

export class DynamoDbConstruct extends Construct {
  public readonly table: dynamodb.Table;

  constructor(scope: Construct, id: string, props: DynamoDbTableProps) {
    super(scope, id);

    this.table = new dynamodb.Table(this, props.tableName, {
      tableName: props.tableName,
      partitionKey: props.partitionKey,
      sortKey: props.sortKey,
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: props.pointInTimeRecovery,
      stream: props.enableStreams ? dynamodb.StreamViewType.NEW_AND_OLD_IMAGES : undefined,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // Use RETAIN for production
    });

    // Add Global Secondary Indexes with proper configuration
    props.globalSecondaryIndexes?.forEach(gsi => {
      this.table.addGlobalSecondaryIndex({
        indexName: gsi.indexName,
        partitionKey: gsi.partitionKey,
        sortKey: gsi.sortKey,
        projectionType: dynamodb.ProjectionType.ALL,
      });
    });

    cdk.Tags.of(this.table).add('Component', 'Database');
  }
}
```

This construct demonstrates several important design principles. **Flexible configuration** allows for various table designs while maintaining type safety through TypeScript interfaces. **Production-ready defaults** ensure that encryption, billing mode, and backup configurations follow AWS best practices. The construct is also **extensible** - new features like TTL (Time To Live) or additional indexes can be easily added without breaking existing implementations.

### API Gateway Construct

API Gateway configuration can be complex, involving CORS settings, logging, authentication, and domain management. Our construct abstracts this complexity behind a clean interface:

```typescript
// lib/constructs/api-gateway-construct.ts
import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface ApiGatewayProps {
  apiName: string;
  description: string;
  corsOptions?: {
    allowOrigins: string[];
    allowMethods: string[];
    allowHeaders: string[];
  };
  enableAccessLogging?: boolean;
  enableXRayTracing?: boolean;
}

export class ApiGatewayConstruct extends Construct {
  public readonly api: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: ApiGatewayProps) {
    super(scope, id);

    // Create access log group for monitoring
    const accessLogGroup = props.enableAccessLogging ? new logs.LogGroup(this, 'ApiAccessLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    }) : undefined;

    // Create REST API with production-ready defaults
    this.api = new apigateway.RestApi(this, props.apiName, {
      restApiName: props.apiName,
      description: props.description,
      deployOptions: {
        stageName: 'api',
        accessLogDestination: accessLogGroup ? new apigateway.LogGroupLogDestination(accessLogGroup) : undefined,
        tracingEnabled: props.enableXRayTracing,
      },
      defaultCorsPreflightOptions: props.corsOptions ? {
        allowOrigins: props.corsOptions.allowOrigins,
        allowMethods: props.corsOptions.allowMethods,
        allowHeaders: props.corsOptions.allowHeaders,
      } : undefined,
    });

    cdk.Tags.of(this.api).add('Component', 'API');
  }

  public addLambdaIntegration(path: string, method: string, lambdaFunction: lambda.Function): void {
    const resource = this.getOrCreateResource(path);
    resource.addMethod(method, new apigateway.LambdaIntegration(lambdaFunction, { proxy: true }));
  }

  private getOrCreateResource(path: string): apigateway.Resource {
    const pathParts = path.split('/').filter(part => part !== '');
    let resource = this.api.root;

    for (const pathPart of pathParts) {
      const existingResource = resource.getResource(pathPart);
      resource = existingResource || resource.addResource(pathPart);
    }

    return resource;
  }
}
```

This construct illustrates how CDK can **simplify complex configurations** by providing sensible defaults while maintaining flexibility. The **addLambdaIntegration** method demonstrates the power of higher-level abstractions - adding a new API endpoint becomes a single method call rather than manually configuring resources, methods, and integrations. The construct also **enables growth** by handling nested resource paths automatically, making it easy to create hierarchical API structures.

## Main Stack Implementation

Now that we have our reusable constructs, we can create the main stack that orchestrates all components. This is where CDK truly shines - complex infrastructure becomes readable, maintainable code that clearly expresses the relationships between resources.

{{< plantuml id="stack-deployment" >}}
@startuml
!theme aws-orange
title CDK Stack Deployment Flow

participant "Developer" as dev
participant "CDK CLI" as cdk
participant "CloudFormation" as cf
participant "AWS Services" as aws

dev -> cdk: cdk deploy
cdk -> cdk: Synthesize TypeScript to CloudFormation
cdk -> cf: Deploy CloudFormation template
cf -> aws: Create DynamoDB table
cf -> aws: Create Lambda functions
cf -> aws: Create API Gateway
cf -> aws: Configure IAM roles & policies
cf -> aws: Set up monitoring & logging
aws -> cf: Return resource ARNs
cf -> cdk: Deployment complete
cdk -> dev: Stack outputs

@enduml
{{< /plantuml >}}

The deployment flow above illustrates how CDK transforms your TypeScript code into CloudFormation templates, which AWS then uses to provision resources. The beauty is that you get all the benefits of CloudFormation (rollback capabilities, change sets, dependency management) while writing in a familiar programming language.

Here's our main stack that brings everything together:

```typescript
// lib/serverless-app-stack.ts
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';
import { LambdaApiConstruct } from './constructs/lambda-api-construct';
import { DynamoDbConstruct } from './constructs/dynamodb-construct';
import { ApiGatewayConstruct } from './constructs/api-gateway-construct';
import { StackConfig } from './types/stack-config';

export interface ServerlessAppStackProps extends cdk.StackProps {
  config: StackConfig;
}

export class ServerlessAppStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ServerlessAppStackProps) {
    super(scope, id, props);

    const { config } = props;

    // Create DynamoDB table using single-table design pattern
    const database = new DynamoDbConstruct(this, 'AppDatabase', {
      tableName: `app-table-${config.app.environment}`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      globalSecondaryIndexes: [{
        indexName: 'GSI1',
        partitionKey: { name: 'gsi1pk', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'gsi1sk', type: dynamodb.AttributeType.STRING },
      }],
      pointInTimeRecovery: config.database.pointInTimeRecovery,
      enableStreams: config.database.enableStreams,
    });

    // Create API Gateway with CORS and logging configuration
    const api = new ApiGatewayConstruct(this, 'AppApi', {
      apiName: `app-api-${config.app.environment}`,
      description: `Application API for ${config.app.environment} environment`,
      corsOptions: {
        allowOrigins: config.app.corsOrigins,
        allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization'],
      },
      enableAccessLogging: true,
      enableXRayTracing: config.app.enableXRay,
    });

    // Create Lambda functions with shared environment configuration
    const commonEnvironment = {
      TABLE_NAME: database.table.tableName,
      ENVIRONMENT: config.app.environment,
      REGION: config.app.region,
      ...config.lambda.environment,
    };

    const createUserFunction = new LambdaApiConstruct(this, 'CreateUserFunction', {
      functionName: `create-user-${config.app.environment}`,
      entry: 'src/handlers/users/create.ts',
      environment: commonEnvironment,
      timeout: cdk.Duration.seconds(config.lambda.timeout),
      memorySize: config.lambda.memorySize,
      enableXRay: config.app.enableXRay,
    });

    const getUserFunction = new LambdaApiConstruct(this, 'GetUserFunction', {
      functionName: `get-user-${config.app.environment}`,
      entry: 'src/handlers/users/get.ts',
      environment: commonEnvironment,
      timeout: cdk.Duration.seconds(config.lambda.timeout),
      memorySize: config.lambda.memorySize,
      enableXRay: config.app.enableXRay,
    });

    // Grant DynamoDB permissions to all functions
    [createUserFunction, getUserFunction].forEach(fn => {
      fn.grantDynamoDbAccess(database.table.tableArn);
    });

    // Set up API routes
    api.addLambdaIntegration('users', 'POST', createUserFunction.function);
    api.addLambdaIntegration('users/{id}', 'GET', getUserFunction.function);

    // Export important values for other stacks or applications
    new cdk.CfnOutput(this, 'ApiUrl', {
      value: api.api.url,
      description: 'API Gateway URL',
      exportName: `${id}-ApiUrl`,
    });

    new cdk.CfnOutput(this, 'TableName', {
      value: database.table.tableName,
      description: 'DynamoDB Table Name',
      exportName: `${id}-TableName`,
    });
  }
}
```

This stack implementation demonstrates several key architectural patterns. **Composition over inheritance** is evident in how we combine multiple constructs to create a complete application. **Configuration-driven deployment** ensures that environment-specific settings drive all resource creation. Most importantly, **resource relationships** are automatically managed by CDK - IAM permissions, environment variables, and API integrations are all handled seamlessly.

## Environment-Specific Configuration

One of CDK's greatest strengths is its ability to handle multiple environments through configuration-driven deployment. Instead of maintaining separate infrastructure templates for each environment, we define environment-specific settings as TypeScript objects, ensuring type safety and consistency.

This approach offers several advantages over traditional infrastructure management. **Type safety** ensures that all required configuration values are provided and correctly typed. **Environment consistency** is maintained because the same infrastructure code deploys to all environments, with only the configuration values changing. **Change visibility** is improved since environment differences are explicit and version-controlled.

Here are examples of environment-specific configurations:

```typescript
// config/dev.ts - Development environment optimized for cost and experimentation
export const devConfig: StackConfig = {
  app: {
    environment: 'dev',
    region: 'us-east-1',
    enableXRay: false, // Disabled to reduce costs
    corsOrigins: ['http://localhost:3000'],
  },
  database: {
    billingMode: 'PAY_PER_REQUEST',
    pointInTimeRecovery: false, // Not critical for dev
    enableStreams: false,
  },
  lambda: {
    memorySize: 256, // Lower memory for cost optimization
    timeout: 30,
    environment: { LOG_LEVEL: 'DEBUG' },
  },
  monitoring: {
    enableDetailedMetrics: true,
    errorThreshold: 5, // Higher tolerance for experimentation
    latencyThreshold: 5000,
  },
};

// config/prod.ts - Production environment optimized for reliability and performance
export const prodConfig: StackConfig = {
  app: {
    environment: 'prod',
    region: 'us-east-1',
    domainName: 'api.example.com',
    enableXRay: true, // Full observability in production
    corsOrigins: ['https://example.com'],
  },
  database: {
    billingMode: 'PAY_PER_REQUEST',
    pointInTimeRecovery: true, // Essential for production data protection
    enableStreams: true, // Enables event-driven patterns
  },
  lambda: {
    memorySize: 512, // Higher memory for better performance
    timeout: 30,
    reservedConcurrency: 100, // Protect against runaway executions
    environment: { LOG_LEVEL: 'INFO' },
  },
  monitoring: {
    enableDetailedMetrics: true,
    alarmEmail: 'alerts@example.com',
    errorThreshold: 1, // Zero tolerance for production errors
    latencyThreshold: 2000, // Strict performance requirements
  },
};
```

Notice how the configurations clearly show the trade-offs between environments. Development prioritizes cost optimization and debugging capabilities, while production emphasizes reliability, performance, and comprehensive monitoring.

## Deployment and Testing

CDK provides sophisticated tooling for deployment automation and infrastructure testing. Establishing a robust development workflow is crucial for maintaining infrastructure quality and enabling confident deployments across environments.

### Deployment Automation

The deployment process begins with a simple application entry point that selects the appropriate configuration based on context:

```typescript
// bin/app.ts
#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { ServerlessAppStack } from '../lib/serverless-app-stack';
import { devConfig } from '../config/dev';
import { prodConfig } from '../config/prod';

const app = new cdk.App();
const environment = app.node.tryGetContext('environment') || 'dev';
const config = environment === 'prod' ? prodConfig : devConfig;

new ServerlessAppStack(app, `ServerlessApp-${config.app.environment}`, {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: config.app.region,
  },
  config,
  tags: {
    Environment: config.app.environment,
    Project: 'ServerlessApp',
    ManagedBy: 'CDK',
  },
});
```

This approach provides **context-aware deployment** where the same code can deploy different configurations based on the environment parameter. **Consistent tagging** ensures all resources are properly labeled for cost tracking and resource management.

### Essential NPM Scripts

Streamline your development workflow with these essential package.json scripts:

```json
{
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "synth:dev": "cdk synth -c environment=dev",
    "synth:prod": "cdk synth -c environment=prod",
    "deploy:dev": "cdk deploy -c environment=dev --require-approval never",
    "deploy:prod": "cdk deploy -c environment=prod",
    "diff:dev": "cdk diff -c environment=dev",
    "destroy:dev": "cdk destroy -c environment=dev"
  }
}
```

These scripts enable **safe development** with automatic approval for dev deployments while requiring manual approval for production. The **diff commands** let you preview changes before deployment, preventing unintended modifications.

### Infrastructure Testing

Testing infrastructure code is essential for maintaining reliability. CDK's testing framework allows you to verify that your constructs generate the expected CloudFormation resources:

```typescript
// test/constructs/lambda-api-construct.test.ts
import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { LambdaApiConstruct } from '../../lib/constructs/lambda-api-construct';

describe('LambdaApiConstruct', () => {
  test('creates Lambda function with correct configuration', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'TestStack');

    new LambdaApiConstruct(stack, 'TestFunction', {
      functionName: 'test-function',
      entry: 'src/handlers/test.ts',
      environment: { NODE_ENV: 'test' },
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      enableXRay: true,
    });

    const template = Template.fromStack(stack);
    
    // Verify Lambda function properties
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'test-function',
      Runtime: 'nodejs18.x',
      MemorySize: 256,
      Timeout: 30,
      TracingConfig: { Mode: 'Active' },
    });
  });

  test('grants DynamoDB permissions correctly', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'TestStack');
    
    const construct = new LambdaApiConstruct(stack, 'TestFunction', {
      functionName: 'test-function',
      entry: 'src/handlers/test.ts',
      environment: {},
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
    });

    construct.grantDynamoDbAccess('arn:aws:dynamodb:us-east-1:123456789012:table/test-table');

    const template = Template.fromStack(stack);
    
    // Verify IAM policy is created with correct permissions
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: {
        Statement: [{
          Effect: 'Allow',
          Action: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:DeleteItem', 'dynamodb:Query', 'dynamodb:Scan'],
          Resource: [
            'arn:aws:dynamodb:us-east-1:123456789012:table/test-table',
            'arn:aws:dynamodb:us-east-1:123456789012:table/test-table/index/*',
          ],
        }],
      },
    });
  });
});
```

This testing strategy provides multiple benefits. **Resource validation** ensures that infrastructure resources are created with the correct properties and configurations. **Permission testing** verifies that IAM policies grant the appropriate access without being overly permissive. **Regression prevention** catches breaking changes before they reach production. Perhaps most importantly, **living documentation** is created since tests serve as executable specifications of how the infrastructure should behave.

## Conclusion

AWS CDK with TypeScript represents a paradigm shift in infrastructure management, bringing the same development practices, tooling, and type safety that modern applications enjoy to cloud infrastructure. Throughout this exploration, we've seen how CDK transforms infrastructure from static configuration files into living, testable, and maintainable code.

The patterns demonstrated here scale remarkably well. **Reusable constructs** allow teams to encapsulate best practices and share them across projects, reducing duplication and ensuring consistency. **Configuration-driven deployment** enables the same infrastructure code to work seamlessly across environments while maintaining clear visibility into environment-specific differences. **Comprehensive testing** provides confidence in infrastructure changes, preventing the "it works on my machine" problems that plague traditional infrastructure management.

Perhaps most importantly, CDK enables **infrastructure evolution**. As your application requirements change, your infrastructure can adapt alongside it. New Lambda functions become simple construct instantiations. API endpoints require just method calls. Complex monitoring and alerting can be abstracted into reusable patterns that work across your entire organization.

The type safety and developer experience that TypeScript provides transforms infrastructure development from an error-prone, trial-and-error process into a predictable, IDE-assisted workflow. IntelliSense, refactoring tools, and compile-time validation catch issues before deployment, dramatically reducing the feedback loop for infrastructure changes.

This approach scales from simple applications to complex, multi-service architectures while maintaining consistency and reliability. Whether you're building a single serverless function or orchestrating dozens of microservices, CDK provides the foundation for infrastructure that's as maintainable and robust as your application code.

In our next post, we'll explore building real-time applications with AWS WebSockets and TypeScript, completing our comprehensive tour of serverless development patterns with AWS and TypeScript.
