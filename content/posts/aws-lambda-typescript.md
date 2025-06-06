---
title: "How to deploy an AWS Lambda function written in TypeScript using SAM CLI"
date: 2023-02-17T13:30:32-07:00
draft: false
categories: ["Cloud Computing", "Development Tutorials"]
tags:
- Development
- AWS
- Serverless
- TypeScript
series: "AWS and Typescript"
---

Welcome to the world of AWS Serverless! In this blog post, we will be discussing how to deploy an AWS Lambda function written in TypeScript using the AWS SAM CLI.

AWS Lambda is a compute service that allows you to run your code in response to events or triggers, such as changes to data in an S3 bucket, or updates to a DynamoDB table. AWS Serverless Application Model (SAM) is an open-source framework for building serverless applications. The SAM CLI provides a local development and testing environment for AWS Serverless applications.

## Prerequisites

Before we dive into the instructions, let's make sure we have the prerequisites installed:

- Node.js (v20.x or later)
- AWS CLI (v2.x or later)
- SAM CLI (v1.x or later)
- TypeScript (v3.x or later)
- An AWS account with appropriate permissions

## Instructions

Now, let's get started:

1. Create a new TypeScript project

Create a new directory for your project and navigate to that directory in your terminal. Run the following command to create a new TypeScript project:

`$ tsc --init`

This will create a `tsconfig.json` file that TypeScript will use to compile your code. You'll also need to create a `package.json` file:

```bash
$ npm init -y
```

Then update the `package.json` with build scripts:

```json
{
  "scripts": {
    "build": "tsc",
    "watch": "tsc -w",
    "test": "jest"
  }
}
```

2. Install necessary dependencies

We will be using the `aws-sdk` and `aws-lambda` modules in our Lambda function. Run the following command to install the necessary dependencies:

`$ npm install --save @aws-sdk/client-dynamodb @types/aws-lambda`
`$ npm install --save-dev typescript @types/node esbuild`

Note: We're using the modular AWS SDK v3 which is recommended for Lambda functions as it allows for better tree-shaking and smaller deployment packages.

3. Configure TypeScript

Update your `tsconfig.json` with these recommended settings for AWS Lambda:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules"]
}
```

4. Write your Lambda function code

Create a new file in your project directory called `handler.ts` and write your Lambda function code. For example, let's create a simple function that returns the current date and time:

```typescript
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

// Define response type for better type safety
interface ResponseBody {
  message: string;
  timestamp: string;
  requestId?: string;
}

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const response: ResponseBody = {
      message: 'Hello from AWS Lambda!',
      timestamp: new Date().toISOString(),
      requestId: event.requestContext.requestId
    };

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        // Enable CORS if needed
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET'
      },
      body: JSON.stringify(response)
    };
  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        message: 'Internal server error',
        timestamp: new Date().toISOString()
      })
    };
  }
};
```

4. Define your SAM template

Create a new file in your project directory called template.yaml and define your SAM template. Here is an example:
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Resources:
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: dist/handler.handler
      Runtime: nodejs14.x
      CodeUri: ./
      MemorySize: 128
      Timeout: 10
      Events:
        GetEvent:
          Type: Api
          Properties:
            Path: /my-function
            Method: get
```

This template defines a new AWS Lambda function with a memory size of 128MB and a timeout of 10 seconds. The function is triggered by an HTTP GET request to the /my-function endpoint.

5. Build and package your TypeScript code

Run the following command to build your TypeScript code: `$ npm run build`

This will compile your TypeScript code into JavaScript and output it to a new dist directory.

Run the following command to package your code into a ZIP file: `$ sam package --template-file template.yaml --output-template-file packaged.yaml --s3-bucket your-s3-bucket`

This will create a new packaged.yaml file that contains your AWS SAM template and a ZIP file with your compiled code.

## Optimizing the Build Process

Instead of using plain `tsc` for compilation, we can use esbuild to create optimized bundles. Create a `build.js` file in your project root:

```javascript
const { build } = require('esbuild');

build({
  entryPoints: ['src/handler.ts'],
  bundle: true,
  minify: true,
  sourcemap: true,
  platform: 'node',
  target: 'node14',
  outdir: 'dist',
}).catch(() => process.exit(1));
```

Update your package.json scripts:

```json
{
  "scripts": {
    "build": "node build.js",
    "watch": "node build.js --watch"
  }
}
```

This will create a single bundled file that includes only the necessary code, resulting in faster cold starts and smaller deployment packages.

## Testing Your Lambda Function

Install testing dependencies:

```bash
$ npm install --save-dev jest @types/jest ts-jest
```

Create a `jest.config.js`:

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
};
```

Create a test file `src/handler.test.ts`:

```typescript
import { APIGatewayProxyEvent } from 'aws-lambda';
import { handler } from './handler';

describe('Lambda Handler', () => {
  it('returns successful response', async () => {
    const event = {
      requestContext: {
        requestId: 'test-123'
      }
    } as APIGatewayProxyEvent;

    const response = await handler(event);

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.message).toBe('Hello from AWS Lambda!');
    expect(body.requestId).toBe('test-123');
    expect(body.timestamp).toBeDefined();
  });
});
```

Add test script to package.json:

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch"
  }
}
```

## Local Development

You can test your Lambda function locally using the SAM CLI:

```bash
# Start API locally
$ sam local start-api

# Test specific function with event
$ sam local invoke MyFunction --event events/api-gateway-event.json
```

Create a test event file `events/api-gateway-event.json`:

```json
{
  "resource": "/my-function",
  "path": "/my-function",
  "httpMethod": "GET",
  "requestContext": {
    "requestId": "test-123"
  }
}
```

## Deployment Best Practices

1. **Environment Variables**: Use AWS Systems Manager Parameter Store for configuration:

```yaml
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      Environment:
        Variables:
          PARAMETER_NAME: '/my-app/${AWS::Stage}/config'
```

2. **Monitoring**: Add X-Ray tracing:

```yaml
  MyFunction:
    Type: AWS::Serverless::Function
    Properties:
      Tracing: Active
```

3. **Error Handling**: Use AWS CloudWatch Logs Insights to analyze errors:

```bash
fields @timestamp, @message
| filter @message like /ERROR/
| sort @timestamp desc
| limit 20
```

## Security Considerations

1. Keep dependencies updated:
```bash
$ npm audit
$ npm update
```

2. Use the principle of least privilege in IAM roles:

```yaml
  MyFunctionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: MinimalPermissions
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ssm:GetParameter
                Resource: !Sub 'arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/my-app/${AWS::Stage}/*'
```

## Conclusion

By following these best practices, you'll have a well-structured, type-safe Lambda function that's easy to test and maintain. Remember to:

- Use TypeScript for type safety
- Bundle your code with esbuild for optimal performance
- Include proper error handling and logging
- Implement comprehensive tests
- Follow security best practices
- Use local development tools for faster iteration
