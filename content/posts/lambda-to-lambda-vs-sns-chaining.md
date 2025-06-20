---
title: "Lambda-to-Lambda Calls vs. SNS Chaining in AWS: When and How to Use Each"
date: 2025-06-19T09:00:00-07:00
draft: false
categories: ["Cloud Computing", "Architecture and Design"]
tags:
- AWS
- TypeScript
- Serverless
- Architecture
- Development
series: "AWS and Typescript"
---

Modern serverless architectures often require connecting multiple AWS Lambda functions. Two common patterns are direct Lambda-to-Lambda invocation and chaining via Amazon SNS. This post explains when to use each, with diagrams, CloudFormation templates, and TypeScript code for both approaches.

## When to Use Each Pattern

Choosing between direct Lambda-to-Lambda calls and SNS chaining depends on your workflow's requirements for coupling, reliability, and scalability. While it is technically possible to invoke one Lambda function from another, it is important to understand the implications of doing so synchronously. Synchronous Lambda-to-Lambda calls—where the first function waits for a response from the second—are generally discouraged as a best practice. This is because they can lead to increased latency, higher costs, and more complex error handling, especially if the downstream Lambda experiences throttling or failures. In most cases, tightly coupled, synchronous workflows are better implemented using other AWS services such as Step Functions, which are designed for orchestrating distributed processes with built-in error handling and state management.

However, making an asynchronous Lambda-to-Lambda call is a valid and supported pattern. In this approach, the first Lambda invokes the second using the "Event" invocation type, which does not wait for a response and allows both functions to scale independently. Asynchronous invocation is not considered an anti-pattern and can be useful for fire-and-forget scenarios where the result is not immediately needed by the caller.

SNS chaining, on the other hand, is better suited for loosely coupled, event-driven, or fan-out scenarios. By introducing SNS as an intermediary, you can decouple the producer (the first Lambda) from one or more consumers (downstream Lambdas). This pattern is ideal when you want to enable retries, support multiple subscribers, or build more resilient and scalable systems. SNS allows each consumer to process messages independently, making it easier to evolve your architecture over time.

---

## 1. Direct Lambda-to-Lambda Calls

This approach lets one Lambda invoke another directly using the AWS SDK. While asynchronous invocation is possible and sometimes useful, synchronous Lambda-to-Lambda calls should generally be avoided in favor of more robust orchestration solutions.

### Lambda-to-Lambda Architecture

{{< plantuml id="lambda-to-lambda" >}}
@startuml
!theme aws-orange
actor Client
[Lambda A] as LambdaA
[Lambda B] as LambdaB
Client --> LambdaA : Trigger (API/Event)
LambdaA --> LambdaB : Invoke (sync/async)
@enduml
{{< /plantuml >}}

### Lambda-to-Lambda CloudFormation Template (AWS SAM)

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    Runtime: nodejs18.x
    Timeout: 10
    Architectures:
      - x86_64
    Environment:
      Variables:
        AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1'
Resources:
  LambdaA:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: LambdaA
      Handler: index.handler
      CodeUri: ./lambda-a/
      Policies:
        - Statement:
            - Effect: Allow
              Action: lambda:InvokeFunction
              Resource: !GetAtt LambdaB.Arn
      Environment:
        Variables:
          LAMBDA_B_ARN: !GetAtt LambdaB.Arn
  LambdaB:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: LambdaB
      Handler: index.handler
      CodeUri: ./lambda-b/
```

### Lambda-to-Lambda TypeScript Example (AWS SDK v3)

```typescript
// LambdaA: Invoking LambdaB directly
import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda";

const lambda = new LambdaClient({ region: process.env.AWS_REGION });

export const handler = async () => {
  const command = new InvokeCommand({
    FunctionName: process.env.LAMBDA_B_ARN!,
    Payload: Buffer.from(JSON.stringify({ key: "value" })),
    InvocationType: "Event", // "Event" for async
  });
  const response = await lambda.send(command);
  const payload = response.Payload ? Buffer.from(response.Payload).toString() : undefined;
  return { statusCode: 200, body: payload };
};
```

---

## 2. Chaining with SNS

This pattern uses SNS to decouple Lambda functions. LambdaA publishes a message to SNS; LambdaB and other subscribers are subscribed to the topic and triggered asynchronously.

### SNS Chaining Architecture

{{< plantuml id="sns-chaining" >}}
@startuml
!theme aws-orange
actor Client
[Lambda A] as LambdaA
[SNS Topic] as SNS
[Lambda B] as LambdaB
[Lambda C] as LambdaC
[SQS Queue] as Queue
[Lambda D] as LambdaD
Client --> LambdaA : Trigger (API/Event)
LambdaA --> SNS : Publish Event
SNS --> LambdaB : Event Notification
SNS --> LambdaC : Event Notification
SNS --> Queue : Fan-out to SQS
Queue --> LambdaD : SQS Trigger
@enduml
{{< /plantuml >}}

### SNS Chaining CloudFormation Template (AWS SAM)

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Globals:
  Function:
    Runtime: nodejs18.x
    Timeout: 10
    Architectures:
      - x86_64
    Environment:
      Variables:
        AWS_NODEJS_CONNECTION_REUSE_ENABLED: '1'
Resources:
  LambdaA:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: LambdaA
      Handler: index.handler
      CodeUri: ./lambda-a/
      Policies:
        - Statement:
            - Effect: Allow
              Action: sns:Publish
              Resource: !Ref Topic
      Environment:
        Variables:
          SNS_TOPIC_ARN: !Ref Topic
  LambdaB:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: LambdaB
      Handler: index.handler
      CodeUri: ./lambda-b/
      Events:
        SnsEvent:
          Type: SNS
          Properties:
            Topic: !Ref Topic
  LambdaC:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: LambdaC
      Handler: index.handler
      CodeUri: ./lambda-c/
      Events:
        SnsEvent:
          Type: SNS
          Properties:
            Topic: !Ref Topic
  Queue:
    Type: AWS::SQS::Queue
  QueueSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref Topic
      Protocol: sqs
      Endpoint: !GetAtt Queue.Arn
  LambdaD:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: LambdaD
      Handler: index.handler
      CodeUri: ./lambda-d/
      Events:
        SQSTrigger:
          Type: SQS
          Properties:
            Queue: !GetAtt Queue.Arn
  Topic:
    Type: AWS::SNS::Topic
```

### SNS Chaining TypeScript Example (AWS SDK v3)

```typescript
// LambdaA: Publish to SNS
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const sns = new SNSClient({ region: process.env.AWS_REGION });

export const handler = async () => {
  const command = new PublishCommand({
    TopicArn: process.env.SNS_TOPIC_ARN!,
    Message: JSON.stringify({ key: "value" }),
  });
  await sns.send(command);
  return { statusCode: 200, body: "Message sent" };
};
```

---

## Conclusion

To summarize, synchronous Lambda-to-Lambda calls—where one function waits for a response from another—are considered an anti-pattern and should be avoided. This approach can introduce unnecessary latency, increase costs, and complicate error handling. If you need to coordinate multiple Lambda functions in a workflow, consider using AWS Step Functions or event-driven patterns instead.

If you must trigger another Lambda from your function, prefer asynchronous invocation. Asynchronous Lambda-to-Lambda calls are not an anti-pattern and can be useful for fire-and-forget scenarios where the result is not needed immediately by the caller.

SNS chaining is the recommended approach for decoupling, fan-out, and building resilient, scalable serverless systems. By using SNS, you can easily support multiple independent subscribers, enable retries, and evolve your architecture as requirements change. Choose the pattern that best fits your application's needs, but avoid synchronous Lambda-to-Lambda calls in production systems.
