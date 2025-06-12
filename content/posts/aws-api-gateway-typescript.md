---
title: "Building Type-Safe APIs with AWS API Gateway and TypeScript"
date: 2023-06-11T10:00:00-07:00
draft: false
categories: ["Cloud Computing", "API Development"]
tags:
- AWS
- TypeScript
- API Gateway
- Serverless
- Development
- REST API
series: "AWS and Typescript"
---

Building robust APIs requires more than just handling HTTP requests—it demands type safety, proper validation, and clear documentation. In this post, we'll explore how to build production-ready APIs using AWS API Gateway with TypeScript, ensuring type safety from request to response while maintaining excellent developer experience.

{{< plantuml id="api-gateway-architecture" >}}
@startuml API Gateway Architecture
!define RECTANGLE class

cloud "Client Applications" as clients
package "AWS Cloud" {
  rectangle "API Gateway" as apigw {
    rectangle "REST API" as restapi
    rectangle "Request Validation" as validation
    rectangle "CORS" as cors
  }
  
  package "Lambda Functions" {
    rectangle "Create User" as create
    rectangle "Get User" as get
    rectangle "Update User" as update
    rectangle "Delete User" as delete
  }
  
  database "DynamoDB" as dynamo {
    rectangle "Users Table" as table
  }
}

clients --> restapi : HTTPS Requests
restapi --> validation : Validate Schema
validation --> cors : Apply CORS
cors --> create : POST /users
cors --> get : GET /users/{id}
cors --> update : PUT /users/{id}
cors --> delete : DELETE /users/{id}

create --> table : Store User
get --> table : Retrieve User
update --> table : Update User
delete --> table : Remove User

note right of validation
  • Request validation
  • Type checking
  • Schema enforcement
end note

note right of table
  • Primary Key: id
  • Attributes: name, email,
    department, timestamps
end note
@enduml
{{< /plantuml >}}

## Why Type-Safe APIs Matter

Type safety in API development provides several critical advantages:

- **Compile-time Error Detection**: Catch issues before deployment rather than in production
- **Enhanced Developer Experience**: IntelliSense, autocomplete, and refactoring support
- **Self-Documenting Code**: Types serve as living documentation that stays current
- **Team Collaboration**: Clear contracts between frontend and backend developers
- **Reduced Integration Issues**: Consistent interfaces prevent miscommunication

## Project Structure Overview

{{< plantuml id="project-structure" >}}
@startuml Project Structure
!define FOLDER folder
!define FILE rectangle

FOLDER "src/" {
  FOLDER "types/" {
    FILE "api.ts" as types
  }
  FOLDER "handlers/" {
    FILE "users.ts" as handlers
  }
  FOLDER "utils/" {
    FILE "validation.ts" as validation
    FILE "response.ts" as response
  }
}

FOLDER "tests/" {
  FILE "api.test.ts" as tests
}

FILE "template.yaml" as sam
FILE "package.json" as pkg
FILE "tsconfig.json" as ts

note right of types
  Interface definitions
  Request/Response types
  API contracts
end note

note right of handlers
  Lambda function implementations
  Business logic
  Error handling
end note

note right of validation
  Type guards
  Schema validation
  Input sanitization
end note
@enduml
{{< /plantuml >}}

## Prerequisites

Ensure you have these essentials:

- **AWS SDK v3** packages for API Gateway and DynamoDB
- **TypeScript** environment with strict type checking
- **AWS SAM CLI** for local development and deployment
- **Jest** for testing framework

## Type Definitions and Contracts

Start with clear, comprehensive type definitions that serve as your API contract:

```typescript
// src/types/api.ts
export interface CreateUserRequest {
  name: string;
  email: string;
  department?: string;
}

export interface UserResponse {
  id: string;
  name: string;
  email: string;
  department?: string;
  createdAt: string;
  updatedAt: string;
}

export interface UpdateUserRequest {
  name?: string;
  email?: string;
  department?: string;
}

export interface ApiResponse<T = any> {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

export interface ErrorResponse {
  error: string;
  message: string;
  statusCode: number;
}
```

These interfaces establish clear contracts for your API endpoints, ensuring consistency across your application and providing excellent TypeScript support.

## Request Validation with Type Guards

Implement robust validation using TypeScript type guards for runtime type safety:

```typescript
// src/utils/validation.ts
import { CreateUserRequest, UpdateUserRequest } from '../types/api';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const validateCreateUser = (body: unknown): body is CreateUserRequest => {
  if (!body || typeof body !== 'object') return false;
  
  const req = body as Record<string, unknown>;
  return !!(
    req.name && typeof req.name === 'string' && req.name.trim() &&
    req.email && typeof req.email === 'string' && EMAIL_REGEX.test(req.email) &&
    (req.department === undefined || typeof req.department === 'string')
  );
};

export const validateUpdateUser = (body: unknown): body is UpdateUserRequest => {
  if (!body || typeof body !== 'object') return false;
  
  const req = body as Record<string, unknown>;
  const hasValidName = !req.name || (typeof req.name === 'string' && req.name.trim());
  const hasValidEmail = !req.email || (typeof req.email === 'string' && EMAIL_REGEX.test(req.email));
  const hasValidDept = req.department === undefined || typeof req.department === 'string';
  
  return hasValidName && hasValidEmail && hasValidDept && 
         (req.name !== undefined || req.email !== undefined || req.department !== undefined);
};

export class ValidationError extends Error {
  constructor(message: string, public field?: string) {
    super(message);
    this.name = 'ValidationError';
  }
}
```

## Response Utilities

Create consistent response formatting:

```typescript
// src/utils/response.ts
import { ApiResponse, ErrorResponse } from '../types/api';

const CORS_HEADERS = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization'
} as const;

export const createResponse = <T>(statusCode: number, body: T): ApiResponse<T> => ({
  statusCode,
  headers: CORS_HEADERS,
  body: JSON.stringify(body)
});

export const createErrorResponse = (
  statusCode: number, 
  error: string, 
  message: string
): ApiResponse<ErrorResponse> => 
  createResponse(statusCode, { error, message, statusCode });
```

## Lambda Handler Implementation

Build type-safe Lambda functions with comprehensive error handling:

```typescript
// src/handlers/users.ts
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand, GetCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';
import { v4 as uuidv4 } from 'uuid';
import { UserResponse, CreateUserRequest, UpdateUserRequest } from '../types/api';
import { validateCreateUser, validateUpdateUser, ValidationError } from '../utils/validation';
import { createResponse, createErrorResponse } from '../utils/response';

const docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE_NAME = process.env.USERS_TABLE_NAME!;

export const createUser = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    if (!event.body) {
      return createErrorResponse(400, 'Bad Request', 'Request body required');
    }

    const body = JSON.parse(event.body);
    if (!validateCreateUser(body)) {
      return createErrorResponse(400, 'Validation Error', 'Invalid request format');
    }

    const userId = uuidv4();
    const timestamp = new Date().toISOString();
    
    const user: UserResponse = {
      id: userId,
      name: body.name.trim(),
      email: body.email.toLowerCase(),
      department: body.department?.trim(),
      createdAt: timestamp,
      updatedAt: timestamp
    };

    await docClient.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: user,
      ConditionExpression: 'attribute_not_exists(id)'
    }));

    return createResponse(201, user);
  } catch (error) {
    if (error instanceof ValidationError) {
      return createErrorResponse(400, 'Validation Error', error.message);
    }
    
    if (error.name === 'ConditionalCheckFailedException') {
      return createErrorResponse(409, 'Conflict', 'User already exists');
    }
    
    console.error('Create user error:', error);
    return createErrorResponse(500, 'Internal Server Error', 'Failed to create user');
  }
};

export const getUser = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const userId = event.pathParameters?.id;
    if (!userId) {
      return createErrorResponse(400, 'Bad Request', 'User ID required');
    }

    const { Item } = await docClient.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: { id: userId }
    }));

    if (!Item) {
      return createErrorResponse(404, 'Not Found', 'User not found');
    }

    return createResponse(200, Item as UserResponse);
  } catch (error) {
    console.error('Get user error:', error);
    return createErrorResponse(500, 'Internal Server Error', 'Failed to retrieve user');
  }
};

export const updateUser = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const userId = event.pathParameters?.id;
    if (!userId || !event.body) {
      return createErrorResponse(400, 'Bad Request', 'User ID and body required');
    }

    const body = JSON.parse(event.body);
    if (!validateUpdateUser(body)) {
      return createErrorResponse(400, 'Validation Error', 'Invalid update format');
    }

    const updateExpression: string[] = [];
    const attributeNames: Record<string, string> = {};
    const attributeValues: Record<string, any> = {};

    if (body.name) {
      updateExpression.push('#name = :name');
      attributeNames['#name'] = 'name';
      attributeValues[':name'] = body.name.trim();
    }

    if (body.email) {
      updateExpression.push('#email = :email');
      attributeNames['#email'] = 'email';
      attributeValues[':email'] = body.email.toLowerCase();
    }

    if (body.department !== undefined) {
      updateExpression.push('#dept = :dept');
      attributeNames['#dept'] = 'department';
      attributeValues[':dept'] = body.department.trim();
    }

    updateExpression.push('#updated = :updated');
    attributeNames['#updated'] = 'updatedAt';
    attributeValues[':updated'] = new Date().toISOString();

    const { Attributes } = await docClient.send(new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { id: userId },
      UpdateExpression: `SET ${updateExpression.join(', ')}`,
      ExpressionAttributeNames: attributeNames,
      ExpressionAttributeValues: attributeValues,
      ConditionExpression: 'attribute_exists(id)',
      ReturnValues: 'ALL_NEW'
    }));

    return createResponse(200, Attributes as UserResponse);
  } catch (error) {
    if (error.name === 'ConditionalCheckFailedException') {
      return createErrorResponse(404, 'Not Found', 'User not found');
    }
    
    console.error('Update user error:', error);
    return createErrorResponse(500, 'Internal Server Error', 'Failed to update user');
  }
};

export const deleteUser = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const userId = event.pathParameters?.id;
    if (!userId) {
      return createErrorResponse(400, 'Bad Request', 'User ID required');
    }

    await docClient.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: { id: userId },
      ConditionExpression: 'attribute_exists(id)'
    }));

    return createResponse(204, {});
  } catch (error) {
    if (error.name === 'ConditionalCheckFailedException') {
      return createErrorResponse(404, 'Not Found', 'User not found');
    }
    
    console.error('Delete user error:', error);
    return createErrorResponse(500, 'Internal Server Error', 'Failed to delete user');
  }
};
```

## Infrastructure as Code with SAM

Define your API Gateway and Lambda infrastructure using a concise SAM template:

```yaml
# template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  Stage:
    Type: String
    Default: dev
    AllowedValues: [dev, staging, prod]

Globals:
  Function:
    Runtime: nodejs18.x
    CodeUri: dist/
    Timeout: 30
    Environment:
      Variables:
        USERS_TABLE_NAME: !Ref UsersTable

Resources:
  # API Gateway with OpenAPI specification
  UsersApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: !Ref Stage
      Cors:
        AllowMethods: "'*'"
        AllowHeaders: "'*'"
        AllowOrigin: "'*'"
      DefinitionBody:
        openapi: 3.0.1
        info:
          title: !Sub "${AWS::StackName}-users-api"
          version: 1.0.0
        paths:
          /users:
            post:
              summary: Create user
              requestBody:
                required: true
                content:
                  application/json:
                    schema:
                      $ref: '#/components/schemas/CreateUserRequest'
              responses:
                '201':
                  description: User created
                  content:
                    application/json:
                      schema:
                        $ref: '#/components/schemas/UserResponse'
              x-amazon-apigateway-integration:
                type: aws_proxy
                httpMethod: POST
                uri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${CreateUserFunction.Arn}/invocations"
          /users/{id}:
            get:
              summary: Get user
              parameters:
                - name: id
                  in: path
                  required: true
                  schema: { type: string }
              responses:
                '200':
                  description: User found
                  content:
                    application/json:
                      schema:
                        $ref: '#/components/schemas/UserResponse'
              x-amazon-apigateway-integration:
                type: aws_proxy
                httpMethod: POST
                uri: !Sub "arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${GetUserFunction.Arn}/invocations"
        components:
          schemas:
            CreateUserRequest:
              type: object
              required: [name, email]
              properties:
                name: { type: string, minLength: 1 }
                email: { type: string, format: email }
                department: { type: string }
            UserResponse:
              type: object
              properties:
                id: { type: string }
                name: { type: string }
                email: { type: string }
                department: { type: string }
                createdAt: { type: string, format: date-time }
                updatedAt: { type: string, format: date-time }

  # Lambda Functions
  CreateUserFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: handlers/users.createUser
      Events:
        CreateUser:
          Type: Api
          Properties:
            RestApiId: !Ref UsersApi
            Path: /users
            Method: POST
      Policies:
        - DynamoDBWritePolicy:
            TableName: !Ref UsersTable

  GetUserFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: handlers/users.getUser
      Events:
        GetUser:
          Type: Api
          Properties:
            RestApiId: !Ref UsersApi
            Path: /users/{id}
            Method: GET
      Policies:
        - DynamoDBReadPolicy:
            TableName: !Ref UsersTable

  UpdateUserFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: handlers/users.updateUser
      Events:
        UpdateUser:
          Type: Api
          Properties:
            RestApiId: !Ref UsersApi
            Path: /users/{id}
            Method: PUT
      Policies:
        - DynamoDBWritePolicy:
            TableName: !Ref UsersTable

  DeleteUserFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: handlers/users.deleteUser
      Events:
        DeleteUser:
          Type: Api
          Properties:
            RestApiId: !Ref UsersApi
            Path: /users/{id}
            Method: DELETE
      Policies:
        - DynamoDBWritePolicy:
            TableName: !Ref UsersTable

  # DynamoDB Table
  UsersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: id
          AttributeType: S
      KeySchema:
        - AttributeName: id
          KeyType: HASH
      PointInTimeRecoverySpecification:
        PointInTimeRecoveryEnabled: true

Outputs:
  ApiUrl:
    Description: API Gateway endpoint URL
    Value: !Sub "https://${UsersApi}.execute-api.${AWS::Region}.amazonaws.com/${Stage}"
    Export:
      Name: !Sub "${AWS::StackName}-api-url"
  
  TableName:
    Description: DynamoDB table name
    Value: !Ref UsersTable
    Export:
      Name: !Sub "${AWS::StackName}-table-name"
```

## Advanced Patterns and Best Practices

### Request/Response Middleware

Implement middleware for common concerns:

```typescript
// src/utils/middleware.ts
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createErrorResponse } from './response';

type HandlerFunction = (event: APIGatewayProxyEvent) => Promise<APIGatewayProxyResult>;

export const withErrorHandling = (handler: HandlerFunction): HandlerFunction => 
  async (event: APIGatewayProxyEvent) => {
    try {
      return await handler(event);
    } catch (error) {
      console.error('Unhandled error:', error);
      return createErrorResponse(500, 'Internal Server Error', 'An unexpected error occurred');
    }
  };

export const withRequestLogging = (handler: HandlerFunction): HandlerFunction => 
  async (event: APIGatewayProxyEvent) => {
    const requestId = event.requestContext.requestId;
    console.log(`[${requestId}] ${event.httpMethod} ${event.path}`);
    
    const startTime = Date.now();
    const result = await handler(event);
    const duration = Date.now() - startTime;
    
    console.log(`[${requestId}] Response: ${result.statusCode} (${duration}ms)`);
    return result;
  };

export const compose = (...middlewares: any[]) => (handler: HandlerFunction) =>
  middlewares.reduceRight((acc, middleware) => middleware(acc), handler);
```

### Schema Validation with JSON Schema

For complex validation scenarios, use JSON Schema:

```typescript
// src/utils/schema-validation.ts
import Ajv from 'ajv';
import addFormats from 'ajv-formats';

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

const createUserSchema = {
  type: 'object',
  required: ['name', 'email'],
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 100 },
    email: { type: 'string', format: 'email', maxLength: 255 },
    department: { type: 'string', maxLength: 100 }
  },
  additionalProperties: false
};

export const validateCreateUserSchema = ajv.compile(createUserSchema);

export const getValidationErrors = (validate: any): string[] => {
  return validate.errors?.map((error: any) => 
    `${error.instancePath || 'root'} ${error.message}`
  ) || [];
};
```

## Comprehensive Testing Strategy

Implement thorough testing for type-safe APIs:

```typescript
// tests/api.test.ts
import { APIGatewayProxyEvent } from 'aws-lambda';
import { createUser, getUser, updateUser, deleteUser } from '../src/handlers/users';
import { CreateUserRequest, UpdateUserRequest } from '../src/types/api';

// Mock AWS SDK
jest.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: jest.fn(() => ({ send: jest.fn() }))
  },
  PutCommand: jest.fn(),
  GetCommand: jest.fn(),
  UpdateCommand: jest.fn(),
  DeleteCommand: jest.fn()
}));

const createMockEvent = (
  body?: any,
  pathParameters?: Record<string, string>
): APIGatewayProxyEvent => ({
  body: body ? JSON.stringify(body) : null,
  pathParameters,
  headers: {},
  multiValueHeaders: {},
  httpMethod: 'POST',
  isBase64Encoded: false,
  path: '/users',
  queryStringParameters: null,
  multiValueQueryStringParameters: null,
  stageVariables: null,
  requestContext: {
    requestId: 'test-request-id',
    // ... other required properties
  } as any,
  resource: ''
});

describe('Users API Handlers', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('creates user with valid data', async () => {
      const validUser: CreateUserRequest = {
        name: 'John Doe',
        email: 'john@example.com',
        department: 'Engineering'
      };

      const event = createMockEvent(validUser);
      const result = await createUser(event);

      expect(result.statusCode).toBe(201);
      const responseBody = JSON.parse(result.body);
      expect(responseBody.name).toBe('John Doe');
      expect(responseBody.email).toBe('john@example.com');
      expect(responseBody.id).toBeDefined();
    });

    it('rejects invalid email format', async () => {
      const invalidUser = {
        name: 'John Doe',
        email: 'invalid-email',
        department: 'Engineering'
      };

      const event = createMockEvent(invalidUser);
      const result = await createUser(event);

      expect(result.statusCode).toBe(400);
      const responseBody = JSON.parse(result.body);
      expect(responseBody.error).toBe('Validation Error');
    });

    it('handles missing request body', async () => {
      const event = createMockEvent();
      const result = await createUser(event);

      expect(result.statusCode).toBe(400);
      const responseBody = JSON.parse(result.body);
      expect(responseBody.message).toBe('Request body required');
    });
  });

  describe('updateUser', () => {
    it('updates user with partial data', async () => {
      const updateData: UpdateUserRequest = {
        name: 'Jane Doe',
        department: 'Product'
      };

      const event = createMockEvent(updateData, { id: 'user-123' });
      // Mock successful DynamoDB response would go here
      
      const result = await updateUser(event);
      expect(result.statusCode).toBeDefined();
    });

    it('rejects empty update request', async () => {
      const emptyUpdate = {};
      const event = createMockEvent(emptyUpdate, { id: 'user-123' });
      
      const result = await updateUser(event);
      expect(result.statusCode).toBe(400);
    });
  });
});
```

## Local Development Environment

Set up efficient local development with hot reloading:

```json
{
  "name": "aws-api-gateway-typescript",
  "version": "1.0.0",
  "scripts": {
    "build": "tsc",
    "build:watch": "tsc --watch",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "lint": "eslint src/**/*.ts --fix",
    "local:api": "sam local start-api --parameter-overrides Stage=local --docker-network lambda-local",
    "local:dynamodb": "docker run -p 8000:8000 amazon/dynamodb-local",
    "deploy:dev": "sam build && sam deploy --parameter-overrides Stage=dev --config-env dev",
    "deploy:prod": "sam build && sam deploy --parameter-overrides Stage=prod --config-env prod",
    "logs:tail": "sam logs --name CreateUserFunction --stack-name users-api-dev --tail"
  },
  "dependencies": {
    "@aws-sdk/client-dynamodb": "^3.300.0",
    "@aws-sdk/lib-dynamodb": "^3.300.0",
    "uuid": "^9.0.0"
  },
  "devDependencies": {
    "@types/aws-lambda": "^8.10.114",
    "@types/jest": "^29.5.0",
    "@types/node": "^18.15.0",
    "@types/uuid": "^9.0.1",
    "jest": "^29.5.0",
    "ts-jest": "^29.1.0",
    "typescript": "^5.0.0",
    "eslint": "^8.37.0",
    "@typescript-eslint/eslint-plugin": "^5.57.0",
    "@typescript-eslint/parser": "^5.57.0"
  },
  "jest": {
    "preset": "ts-jest",
    "testEnvironment": "node",
    "collectCoverageFrom": [
      "src/**/*.ts",
      "!src/**/*.d.ts"
    ],
    "coverageThreshold": {
      "global": {
        "branches": 80,
        "functions": 80,
        "lines": 80,
        "statements": 80
      }
    }
  }
}
```

## Security and Monitoring Best Practices

### Request Rate Limiting and Throttling

```yaml
# In your SAM template
UsersApi:
  Type: AWS::Serverless::Api
  Properties:
    ThrottleConfig:
      BurstLimit: 1000
      RateLimit: 500
    RequestValidatorId: !Ref RequestValidator
    
RequestValidator:
  Type: AWS::ApiGateway::RequestValidator
  Properties:
    RestApiId: !Ref UsersApi
    ValidateRequestBody: true
    ValidateRequestParameters: true
```

### API Key Management

```typescript
// src/utils/auth.ts
import { APIGatewayProxyEvent } from 'aws-lambda';
import { createErrorResponse } from './response';

export const validateApiKey = (event: APIGatewayProxyEvent) => {
  const apiKey = event.headers['x-api-key'] || event.headers['X-API-Key'];
  
  if (!apiKey) {
    return createErrorResponse(401, 'Unauthorized', 'API key required');
  }
  
  // In production, validate against AWS API Gateway or external service
  if (apiKey !== process.env.EXPECTED_API_KEY) {
    return createErrorResponse(403, 'Forbidden', 'Invalid API key');
  }
  
  return null; // Valid key
};
```

### CloudWatch Integration

```typescript
// src/utils/metrics.ts
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

const cloudWatch = new CloudWatchClient({});

export const recordMetric = async (metricName: string, value: number, unit: string = 'Count') => {
  try {
    await cloudWatch.send(new PutMetricDataCommand({
      Namespace: 'UsersAPI',
      MetricData: [{
        MetricName: metricName,
        Value: value,
        Unit: unit,
        Timestamp: new Date()
      }]
    }));
  } catch (error) {
    console.error('Failed to record metric:', error);
  }
};

// Usage in handlers
export const createUserWithMetrics = async (event: APIGatewayProxyEvent) => {
  const startTime = Date.now();
  
  try {
    const result = await createUser(event);
    await recordMetric('UserCreated', 1);
    await recordMetric('CreateUserLatency', Date.now() - startTime, 'Milliseconds');
    return result;
  } catch (error) {
    await recordMetric('CreateUserError', 1);
    throw error;
  }
};
```

## Deployment and Operations

{{< plantuml id="deployment-pipeline" >}}
@startuml Deployment Pipeline
!define RECTANGLE class

rectangle "Development" as dev {
  rectangle "Local SAM" as local
  rectangle "Unit Tests" as tests
  rectangle "Type Checking" as types
}

rectangle "CI/CD Pipeline" as cicd {
  rectangle "Build" as build
  rectangle "Test" as citest
  rectangle "Security Scan" as security
}

rectangle "AWS Environments" as aws {
  rectangle "Dev Stage" as devstage
  rectangle "Staging Stage" as staging
  rectangle "Prod Stage" as prod
}

dev --> cicd : Push to Git
cicd --> devstage : Auto Deploy
devstage --> staging : Manual Promotion
staging --> prod : Manual Promotion

note right of cicd
  • TypeScript compilation
  • Linting and formatting
  • Unit & integration tests
  • SAM build and package
end note

note right of aws
  • API Gateway stages  • Lambda versions
  • DynamoDB tables
  • CloudWatch monitoring
end note
@enduml
{{< /plantuml >}}

### Multi-Stage Deployment

```yaml
# samconfig.toml
version = 0.1

[default]
[default.global.parameters]
stack_name = "users-api"

[default.build.parameters]
cached = true
parallel = true

[default.deploy.parameters]
capabilities = "CAPABILITY_IAM"
confirm_changeset = true
resolve_s3 = true

[dev]
[dev.deploy.parameters]
stack_name = "users-api-dev"
s3_prefix = "users-api-dev"
region = "us-east-1"
parameter_overrides = "Stage=dev"

[prod]
[prod.deploy.parameters]
stack_name = "users-api-prod"
s3_prefix = "users-api-prod"
region = "us-east-1"
parameter_overrides = "Stage=prod"
```

## Performance Optimization

### Response Caching

```typescript
// src/utils/cache.ts
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

export const withCaching = (handler: Function, ttlSeconds: number = 300) => 
  async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const result = await handler(event);
    
    if (result.statusCode === 200) {
      result.headers = {
        ...result.headers,
        'Cache-Control': `max-age=${ttlSeconds}`,
        'ETag': `"${Buffer.from(result.body).toString('base64').slice(0, 32)}"`
      };
    }
    
    return result;
  };

// Usage
export const getCachedUser = withCaching(getUser, 600); // 10 minutes
```

### Connection Reuse

```typescript
// src/utils/db.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';

// Reuse connection across Lambda invocations
let docClient: DynamoDBDocumentClient;

export const getDocumentClient = (): DynamoDBDocumentClient => {
  if (!docClient) {
    const dynamoClient = new DynamoDBClient({
      maxAttempts: 3,
      retryMode: 'adaptive'
    });
    
    docClient = DynamoDBDocumentClient.from(dynamoClient, {
      marshallOptions: {
        convertEmptyValues: false,
        removeUndefinedValues: true
      }
    });
  }
  
  return docClient;
};
```

## Conclusion

Building type-safe APIs with AWS API Gateway and TypeScript creates a robust foundation for scalable applications. This approach provides:

- **Compile-time Safety**: Catch errors before deployment
- **Developer Experience**: Enhanced tooling and documentation
- **Maintainability**: Clear contracts and consistent patterns
- **Production Readiness**: Comprehensive error handling and monitoring

The patterns demonstrated here extend to support authentication, complex validation, caching, and advanced API features. Key takeaways include:

1. **Start with Types**: Define clear interfaces that serve as contracts
2. **Validate Early**: Use type guards and schema validation at API boundaries
3. **Handle Errors Gracefully**: Provide consistent error responses with proper HTTP codes
4. **Test Thoroughly**: Implement comprehensive testing at unit and integration levels
5. **Monitor Actively**: Use CloudWatch metrics and logging for production insights

In our next post, we'll explore **DynamoDB with TypeScript**, building upon these API patterns to create type-safe data access layers that integrate seamlessly with your API Gateway endpoints.
