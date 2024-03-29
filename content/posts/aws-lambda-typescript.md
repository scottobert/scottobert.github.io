---
title: "How to deploy an AWS Lambda function written in TypeScript using SAM CLI"
date: 2023-02-17T13:30:32-07:00
draft: false
tags:
- Development
- AWS
- Serverless
- TypeScript
---

Welcome to the world of AWS Serverless! In this blog post, we will be discussing how to deploy an AWS Lambda function written in TypeScript using the AWS SAM CLI.

AWS Lambda is a compute service that allows you to run your code in response to events or triggers, such as changes to data in an S3 bucket, or updates to a DynamoDB table. AWS Serverless Application Model (SAM) is an open-source framework for building serverless applications. The SAM CLI provides a local development and testing environment for AWS Serverless applications.

## Prerequisites

Before we dive into the instructions, let's make sure we have the prerequisites installed:

- Node.js (v10.x or later)
- AWS CLI (v2.x or later)
- SAM CLI (v1.x or later)
- TypeScript (v3.x or later)
- An AWS account with appropriate permissions

## Instructions

Now, let's get started:

1. Create a new TypeScript project

Create a new directory for your project and navigate to that directory in your terminal. Run the following command to create a new TypeScript project:

`$ tsc --init`

This will create a `tsconfig.json` file that TypeScript will use to compile your code.

2. Install necessary dependencies

We will be using the `aws-sdk` and `aws-lambda` modules in our Lambda function. Run the following command to install the necessary dependencies:

`$ npm install --save aws-sdk aws-lambda`

3. Write your Lambda function code

Create a new file in your project directory called `handler.ts` and write your Lambda function code. For example, let's create a simple function that returns the current date and time:

```typescript
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  return {
    statusCode: 200,
    body: JSON.stringify({
      message: `Hello from AWS Lambda! The current time is ${new Date().toTimeString()}.`,
    }),
  };
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
