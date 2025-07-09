---
title: "Cross-Account EventBridge Integration: Building Event-Driven Architectures Across AWS Accounts"
date: 2025-07-30T09:00:00-07:00
draft: false
categories: ["Cloud Computing", "AWS"]
tags:
- AWS
- EventBridge
- Cross-Account
- Event-Driven Architecture
- IAM
- Lambda
- Microservices
series: AWS Cross-Account Patterns
---

Event-driven architectures have become the backbone of modern distributed systems, enabling loose coupling between services and supporting scalable, resilient applications. When implementing these patterns across multiple AWS accounts, Amazon EventBridge provides powerful capabilities for cross-account event routing while maintaining security boundaries and organizational isolation.

Cross-account EventBridge integration enables events generated in one AWS account to trigger processing in another account, supporting complex enterprise workflows where different business units or environments operate in separate accounts. This pattern is essential for building comprehensive event-driven systems that span organizational boundaries while maintaining proper security controls.

## Architecture Overview

Cross-account EventBridge integration involves several key components working together to route events securely between AWS accounts. **Account A** (the producer) generates events and publishes them to a custom event bus. **Account B** (the consumer) receives these events through cross-account permissions and processes them with Lambda functions or other AWS services. **Resource-based policies** control which accounts can send events to specific event buses.

{{< plantuml id="cross-account-eventbridge-architecture" >}}
@startuml
!theme aws-orange
title Cross-Account EventBridge Integration Architecture

cloud "Producer Account (123456789012)" as ProducerAccount {
  rectangle "Lambda Function" as ProducerLambda
  rectangle "Custom Event Bus\n(orders-events)" as CustomBus
  rectangle "EventBridge Rules" as ProducerRules
}

cloud "Consumer Account (987654321098)" as ConsumerAccount {
  rectangle "Custom Event Bus\n(consumer-events)" as ConsumerBus
  rectangle "EventBridge Rules" as ConsumerRules
  rectangle "Lambda Function" as ConsumerLambda
  storage "DynamoDB Table" as DynamoDB
}

cloud "AWS EventBridge Service" as EventBridge {
  rectangle "Cross-Account\nEvent Routing" as Routing
}

ProducerLambda --> CustomBus : "Publishes Events"
CustomBus --> ProducerRules : "Matches Patterns"
ProducerRules --> Routing : "Routes Events"
Routing --> ConsumerBus : "Cross-Account Delivery"
ConsumerBus --> ConsumerRules : "Matches Patterns"
ConsumerRules --> ConsumerLambda : "Triggers Processing"
ConsumerLambda --> DynamoDB : "Stores Data"

note right of CustomBus
  Resource-based policy allows
  Consumer Account access
end note

note left of ConsumerBus
  Receives events from
  Producer Account
end note
@enduml
{{< /plantuml >}}

## Step 1: Setting Up Custom Event Buses

The foundation of cross-account EventBridge integration starts with creating custom event buses in both producer and consumer accounts. Custom event buses provide isolation from the default event bus and enable fine-grained access control for cross-account scenarios.

Create a custom event bus in the producer account that will receive events from your applications:

```typescript
import { EventBridgeClient, CreateEventBusCommand } from '@aws-sdk/client-eventbridge';

const eventBridgeClient = new EventBridgeClient({ region: 'us-east-1' });

async function createProducerEventBus(): Promise<void> {
  const command = new CreateEventBusCommand({
    Name: 'orders-events',
    EventSourceName: 'mycompany.orders'
  });

  try {
    const response = await eventBridgeClient.send(command);
    console.log('Created producer event bus:', {
      eventBusArn: response.EventBusArn,
      name: 'orders-events'
    });
  } catch (error) {
    console.error('Failed to create producer event bus:', error);
    throw error;
  }
}
```

Create the event bus using AWS CLI for quick setup:

```bash
# Create custom event bus in producer account
aws events create-event-bus \
    --name orders-events \
    --event-source-name mycompany.orders

# Create custom event bus in consumer account
aws events create-event-bus \
    --name consumer-events \
    --event-source-name mycompany.processing
```

For Infrastructure as Code deployments, use AWS CDK to define the event buses:

```typescript
import * as events from 'aws-cdk-lib/aws-events';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class ProducerAccountStack extends cdk.Stack {
  public readonly ordersEventBus: events.EventBus;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create custom event bus for orders
    this.ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
      eventBusName: 'orders-events',
      description: 'Custom event bus for order processing events'
    });

    // Output the event bus ARN for cross-account reference
    new cdk.CfnOutput(this, 'OrdersEventBusArn', {
      value: this.ordersEventBus.eventBusArn,
      description: 'ARN of the orders event bus',
      exportName: 'OrdersEventBusArn'
    });
  }
}

export class ConsumerAccountStack extends cdk.Stack {
  public readonly consumerEventBus: events.EventBus;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create custom event bus for consumer processing
    this.consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events',
      description: 'Custom event bus for processing cross-account events'
    });
  }
}
```

Document the event bus ARNs as you'll need them for configuring cross-account permissions and rules. The ARN format follows the pattern: `arn:aws:events:region:account-id:event-bus/event-bus-name`.

## Step 2: Configuring Cross-Account Permissions

Cross-account EventBridge access requires resource-based policies that explicitly grant permission for the consumer account to receive events from the producer account's event bus. These policies work similarly to S3 bucket policies but apply to EventBridge resources.

Create a resource-based policy for the producer account's event bus that allows the consumer account to create rules and receive events:

```typescript
// event-bus-policy.json - Grants cross-account access to event bus
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCrossAccountEventAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::987654321098:root"
      },
      "Action": [
        "events:PutRule",
        "events:DeleteRule",
        "events:DescribeRule",
        "events:DisableRule",
        "events:EnableRule",
        "events:ListTargetsByRule",
        "events:PutTargets",
        "events:RemoveTargets"
      ],
      "Resource": "arn:aws:events:us-east-1:123456789012:event-bus/orders-events"
    },
    {
      "Sid": "AllowCrossAccountRuleTargets",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::987654321098:root"
      },
      "Action": [
        "events:PutRule",
        "events:PutTargets"
      ],
      "Resource": "arn:aws:events:us-east-1:123456789012:rule/orders-events/*"
    }
  ]
}
```

Apply the resource-based policy to the event bus:

```bash
# Apply cross-account policy to the producer event bus
aws events put-permission \
    --principal arn:aws:iam::987654321098:root \
    --action "events:PutRule" \
    --statement-id "CrossAccountAccess" \
    --source-arn arn:aws:events:us-east-1:123456789012:event-bus/orders-events
```

Using AWS CDK, you can define the cross-account permissions declaratively:

```typescript
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';

export class ProducerAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & { 
    consumerAccountId: string 
  }) {
    super(scope, id, props);

    const ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
      eventBusName: 'orders-events'
    });

    // Grant cross-account permissions to consumer account
    ordersEventBus.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCrossAccountEventAccess',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal(props.consumerAccountId)],
      actions: [
        'events:PutRule',
        'events:DeleteRule',
        'events:DescribeRule',
        'events:DisableRule',
        'events:EnableRule',
        'events:ListTargetsByRule',
        'events:PutTargets',
        'events:RemoveTargets'
      ],
      resources: [ordersEventBus.eventBusArn]
    }));

    // Allow consumer account to create rules targeting this event bus
    ordersEventBus.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCrossAccountRuleTargets',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal(props.consumerAccountId)],
      actions: [
        'events:PutRule',
        'events:PutTargets'
      ],
      resources: [`${ordersEventBus.eventBusArn.replace(':event-bus/', ':rule/')}/orders-events/*`]
    }));
  }
}
```

For more granular control, create IAM roles in the consumer account with specific permissions for EventBridge operations:

```typescript
// cross-account-eventbridge-role-policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "events:PutRule",
        "events:PutTargets",
        "events:DeleteRule",
        "events:RemoveTargets",
        "events:DescribeRule",
        "events:ListTargetsByRule"
      ],
      "Resource": [
        "arn:aws:events:us-east-1:123456789012:event-bus/orders-events",
        "arn:aws:events:us-east-1:123456789012:rule/orders-events/*",
        "arn:aws:events:us-east-1:987654321098:event-bus/consumer-events",
        "arn:aws:events:us-east-1:987654321098:rule/consumer-events/*"
      ]
    }
  ]
}
```

Create the IAM role using AWS CDK for better maintainability:

```typescript
export class ConsumerAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    producerAccountId: string
  }) {
    super(scope, id, props);

    const consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events'
    });

    // Create IAM role for EventBridge cross-account operations
    const eventBridgeRole = new iam.Role(this, 'EventBridgeCrossAccountRole', {
      roleName: 'EventBridgeCrossAccountRole',
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com'),
      inlinePolicies: {
        CrossAccountEventBridgePolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'events:PutRule',
                'events:PutTargets',
                'events:DeleteRule',
                'events:RemoveTargets',
                'events:DescribeRule',
                'events:ListTargetsByRule'
              ],
              resources: [
                `arn:aws:events:${this.region}:${props.producerAccountId}:event-bus/orders-events`,
                `arn:aws:events:${this.region}:${props.producerAccountId}:rule/orders-events/*`,
                consumerEventBus.eventBusArn,
                `${consumerEventBus.eventBusArn.replace(':event-bus/', ':rule/')}/consumer-events/*`
              ]
            })
          ]
        })
      }
    });

    // Output the role ARN for use in cross-account rules
    new cdk.CfnOutput(this, 'EventBridgeRoleArn', {
      value: eventBridgeRole.roleArn,
      description: 'IAM Role ARN for EventBridge cross-account operations'
    });
  }
}
```

## Step 3: Creating Cross-Account EventBridge Rules

EventBridge rules define which events should be routed between accounts and where they should be delivered. Create rules in the consumer account that listen for events from the producer account's event bus and route them to appropriate targets.

Create a rule in the consumer account that matches events from the producer account:

```typescript
import { 
  EventBridgeClient, 
  PutRuleCommand, 
  PutTargetsCommand 
} from '@aws-sdk/client-eventbridge';

async function createCrossAccountRule(): Promise<void> {
  const eventBridgeClient = new EventBridgeClient({ region: 'us-east-1' });

  // Create rule that matches order events from producer account
  const ruleCommand = new PutRuleCommand({
    Name: 'cross-account-order-processing',
    EventBusName: 'arn:aws:events:us-east-1:123456789012:event-bus/orders-events',
    EventPattern: JSON.stringify({
      source: ['mycompany.orders'],
      'detail-type': ['Order Created', 'Order Updated', 'Order Cancelled'],
      detail: {
        status: ['pending', 'confirmed', 'cancelled']
      }
    }),
    State: 'ENABLED',
    Description: 'Routes order events from producer account to consumer processing'
  });

  try {
    await eventBridgeClient.send(ruleCommand);
    console.log('Created cross-account EventBridge rule');

    // Add targets to the rule
    const targetsCommand = new PutTargetsCommand({
      Rule: 'cross-account-order-processing',
      EventBusName: 'arn:aws:events:us-east-1:123456789012:event-bus/orders-events',
      Targets: [
        {
          Id: '1',
          Arn: 'arn:aws:events:us-east-1:987654321098:event-bus/consumer-events',
          RoleArn: 'arn:aws:iam::987654321098:role/EventBridgeExecutionRole'
        }
      ]
    });

    await eventBridgeClient.send(targetsCommand);
    console.log('Added targets to cross-account rule');
  } catch (error) {
    console.error('Failed to create cross-account rule:', error);
    throw error;
  }
}
```

Create rules using AWS CLI for simpler scenarios:

```bash
# Create rule in consumer account that listens to producer account's event bus
aws events put-rule \
    --event-bus-name arn:aws:events:us-east-1:123456789012:event-bus/orders-events \
    --name cross-account-order-processing \
    --event-pattern '{
        "source": ["mycompany.orders"],
        "detail-type": ["Order Created", "Order Updated"],
        "detail": {
            "status": ["pending", "confirmed"]
        }
    }' \
    --state ENABLED

# Add target to route events to consumer account's event bus
aws events put-targets \
    --event-bus-name arn:aws:events:us-east-1:123456789012:event-bus/orders-events \
    --rule cross-account-order-processing \
    --targets "Id"="1","Arn"="arn:aws:events:us-east-1:987654321098:event-bus/consumer-events"
```

Use AWS CDK to define cross-account rules with type safety and better maintainability:

```typescript
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class ConsumerAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    producerAccountId: string;
    producerEventBusArn: string;
  }) {
    super(scope, id, props);

    const consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events'
    });

    // Import the producer account's event bus
    const producerEventBus = events.EventBus.fromEventBusArn(
      this, 
      'ProducerEventBus', 
      props.producerEventBusArn
    );

    // Create cross-account rule that routes to consumer event bus
    const crossAccountRule = new events.Rule(this, 'CrossAccountOrderProcessing', {
      ruleName: 'cross-account-order-processing',
      eventBus: producerEventBus,
      description: 'Routes order events from producer account to consumer processing',
      eventPattern: {
        source: ['mycompany.orders'],
        detailType: ['Order Created', 'Order Updated', 'Order Cancelled'],
        detail: {
          status: ['pending', 'confirmed', 'cancelled']
        }
      },
      enabled: true
    });

    // Add consumer event bus as target
    crossAccountRule.addTarget(new events_targets.EventBusTarget(consumerEventBus, {
      role: iam.Role.fromRoleArn(this, 'EventBridgeExecutionRole', 
        'arn:aws:iam::987654321098:role/EventBridgeExecutionRole'
      )
    }));

    // Create local rule in consumer account to process events
    const localProcessingRule = new events.Rule(this, 'LocalOrderProcessing', {
      ruleName: 'local-order-processing',
      eventBus: consumerEventBus,
      description: 'Processes cross-account order events locally',
      eventPattern: {
        source: ['mycompany.orders'],
        detailType: ['Order Created', 'Order Updated', 'Order Cancelled']
      }
    });

    // Add Lambda function as target (we'll define this in Step 5)
    // localProcessingRule.addTarget(new events_targets.LambdaFunction(orderProcessorFunction));
  }
}
```

## Step 4: Implementing Event Publishers

Event publishers in the producer account generate and send events to the custom event bus. These publishers should follow consistent event schemas and include appropriate metadata for routing and processing.

Create an event publisher that sends structured events to the custom event bus:

```typescript
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';

interface OrderEvent {
  orderId: string;
  customerId: string;
  status: 'pending' | 'confirmed' | 'cancelled';
  amount: number;
  timestamp: string;
  metadata?: Record<string, any>;
}

class OrderEventPublisher {
  private eventBridgeClient: EventBridgeClient;
  private eventBusName: string;

  constructor(eventBusName: string) {
    this.eventBridgeClient = new EventBridgeClient({ region: 'us-east-1' });
    this.eventBusName = eventBusName;
  }

  async publishOrderEvent(event: OrderEvent, eventType: string): Promise<void> {
    const putEventsCommand = new PutEventsCommand({
      Entries: [
        {
          Source: 'mycompany.orders',
          DetailType: eventType,
          Detail: JSON.stringify(event),
          EventBusName: this.eventBusName,
          Time: new Date(),
          Resources: [
            `arn:aws:orders:us-east-1:123456789012:order/${event.orderId}`
          ]
        }
      ]
    });

    try {
      const response = await this.eventBridgeClient.send(putEventsCommand);
      
      if (response.FailedEntryCount && response.FailedEntryCount > 0) {
        console.error('Failed to publish some events:', response.Entries);
        throw new Error(`Failed to publish ${response.FailedEntryCount} events`);
      }

      console.log('Successfully published order event:', {
        orderId: event.orderId,
        eventType,
        status: event.status
      });
    } catch (error) {
      console.error('Failed to publish order event:', {
        error: error.message,
        orderId: event.orderId,
        eventType
      });
      throw error;
    }
  }
}

// Usage example in Lambda function
export const handler = async (event: any): Promise<void> => {
  const publisher = new OrderEventPublisher('orders-events');
  
  const orderEvent: OrderEvent = {
    orderId: event.orderId,
    customerId: event.customerId,
    status: event.status,
    amount: event.amount,
    timestamp: new Date().toISOString(),
    metadata: {
      region: 'us-east-1',
      version: '1.0'
    }
  };

  await publisher.publishOrderEvent(orderEvent, 'Order Created');
};
```

Implement batch publishing for high-throughput scenarios:

```typescript
async function publishBatchEvents(events: OrderEvent[]): Promise<void> {
  const eventBridgeClient = new EventBridgeClient({ region: 'us-east-1' });
  
  // EventBridge supports up to 10 events per batch
  const batchSize = 10;
  const batches = [];
  
  for (let i = 0; i < events.length; i += batchSize) {
    batches.push(events.slice(i, i + batchSize));
  }

  for (const batch of batches) {
    const entries = batch.map(event => ({
      Source: 'mycompany.orders',
      DetailType: 'Order Batch Update',
      Detail: JSON.stringify(event),
      EventBusName: 'orders-events',
      Time: new Date()
    }));

    const command = new PutEventsCommand({ Entries: entries });
    await eventBridgeClient.send(command);
  }
}
```

Deploy the event publisher infrastructure using AWS CDK:

```typescript
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';

export class EventPublisherStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Create event bus
    const ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
      eventBusName: 'orders-events'
    });

    // Create Lambda function for publishing events
    const eventPublisherFunction = new lambda.Function(this, 'EventPublisherFunction', {
      functionName: 'OrderEventPublisher',
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda-publisher'), // Publisher code directory
      timeout: cdk.Duration.seconds(30),
      environment: {
        EVENT_BUS_NAME: ordersEventBus.eventBusName
      }
    });

    // Grant Lambda permission to publish to event bus
    ordersEventBus.grantPutEventsTo(eventPublisherFunction);

    // Create IAM role for EventBridge execution
    const eventBridgeExecutionRole = new iam.Role(this, 'EventBridgeExecutionRole', {
      roleName: 'EventBridgeExecutionRole',
      assumedBy: new iam.ServicePrincipal('events.amazonaws.com'),
      inlinePolicies: {
        EventBridgeExecutionPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['events:PutEvents'],
              resources: ['*']
            })
          ]
        })
      }
    });

    // Output important values
    new cdk.CfnOutput(this, 'EventPublisherFunctionArn', {
      value: eventPublisherFunction.functionArn,
      description: 'Lambda function ARN for event publishing'
    });

    new cdk.CfnOutput(this, 'EventBusArn', {
      value: ordersEventBus.eventBusArn,
      description: 'Event bus ARN for cross-account sharing'
    });
  }
}
```

## Step 5: Building Event Consumers

Event consumers in the consumer account process events routed from the producer account. These consumers should be designed to handle events idempotently and include proper error handling for failed processing scenarios.

Create an event consumer Lambda function that processes cross-account events:

```typescript
import { EventBridgeEvent } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';

interface OrderEventDetail {
  orderId: string;
  customerId: string;
  status: string;
  amount: number;
  timestamp: string;
  metadata?: Record<string, any>;
}

const dynamoDbClient = new DynamoDBClient({ region: 'us-east-1' });

export const handler = async (
  event: EventBridgeEvent<string, OrderEventDetail>
): Promise<void> => {
  console.log('Received cross-account event:', {
    source: event.source,
    detailType: event['detail-type'],
    account: event.account,
    region: event.region
  });

  try {
    // Validate event structure
    if (!event.detail || !event.detail.orderId) {
      throw new Error('Invalid event structure: missing orderId');
    }

    // Process the event based on type
    switch (event['detail-type']) {
      case 'Order Created':
        await processOrderCreated(event.detail);
        break;
      case 'Order Updated':
        await processOrderUpdated(event.detail);
        break;
      case 'Order Cancelled':
        await processOrderCancelled(event.detail);
        break;
      default:
        console.warn('Unknown event type:', event['detail-type']);
    }

    console.log('Successfully processed cross-account event:', {
      orderId: event.detail.orderId,
      eventType: event['detail-type']
    });
  } catch (error) {
    console.error('Failed to process cross-account event:', {
      error: error.message,
      event: event.detail,
      eventType: event['detail-type']
    });
    throw error;
  }
};

async function processOrderCreated(orderDetail: OrderEventDetail): Promise<void> {
  const putItemCommand = new PutItemCommand({
    TableName: 'ProcessedOrders',
    Item: {
      orderId: { S: orderDetail.orderId },
      customerId: { S: orderDetail.customerId },
      status: { S: orderDetail.status },
      amount: { N: orderDetail.amount.toString() },
      processedAt: { S: new Date().toISOString() },
      originalTimestamp: { S: orderDetail.timestamp },
      eventType: { S: 'Order Created' }
    },
    ConditionExpression: 'attribute_not_exists(orderId)' // Ensure idempotency
  });

  await dynamoDbClient.send(putItemCommand);
}

async function processOrderUpdated(orderDetail: OrderEventDetail): Promise<void> {
  // Update existing order record
  const putItemCommand = new PutItemCommand({
    TableName: 'ProcessedOrders',
    Item: {
      orderId: { S: orderDetail.orderId },
      customerId: { S: orderDetail.customerId },
      status: { S: orderDetail.status },
      amount: { N: orderDetail.amount.toString() },
      lastUpdatedAt: { S: new Date().toISOString() },
      originalTimestamp: { S: orderDetail.timestamp },
      eventType: { S: 'Order Updated' }
    }
  });

  await dynamoDbClient.send(putItemCommand);
}

async function processOrderCancelled(orderDetail: OrderEventDetail): Promise<void> {
  // Mark order as cancelled and trigger cleanup processes
  const putItemCommand = new PutItemCommand({
    TableName: 'ProcessedOrders',
    Item: {
      orderId: { S: orderDetail.orderId },
      customerId: { S: orderDetail.customerId },
      status: { S: 'cancelled' },
      amount: { N: orderDetail.amount.toString() },
      cancelledAt: { S: new Date().toISOString() },
      originalTimestamp: { S: orderDetail.timestamp },
      eventType: { S: 'Order Cancelled' }
    }
  });

  await dynamoDbClient.send(putItemCommand);
}
```

Deploy the event consumer infrastructure using AWS CDK:

```typescript
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as iam from 'aws-cdk-lib/aws-iam';

export class EventConsumerStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    producerAccountId: string;
    producerEventBusArn: string;
  }) {
    super(scope, id, props);

    // Create DynamoDB table for processed orders
    const processedOrdersTable = new dynamodb.Table(this, 'ProcessedOrdersTable', {
      tableName: 'ProcessedOrders',
      partitionKey: { name: 'orderId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN // Use RETAIN for production
    });

    // Create consumer event bus
    const consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events'
    });

    // Create Dead Letter Queue for failed processing
    const dlqQueue = new sqs.Queue(this, 'OrderProcessingDLQ', {
      queueName: 'order-processing-dlq',
      retentionPeriod: cdk.Duration.days(14)
    });

    // Create Lambda function for processing events
    const orderProcessorFunction = new lambda.Function(this, 'OrderProcessorFunction', {
      functionName: 'CrossAccountEventProcessor',
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda-consumer'), // Consumer code directory
      timeout: cdk.Duration.seconds(30),
      environment: {
        DYNAMODB_TABLE_NAME: processedOrdersTable.tableName
      },
      deadLetterQueue: dlqQueue
    });

    // Grant Lambda permission to write to DynamoDB
    processedOrdersTable.grantWriteData(orderProcessorFunction);

    // Import producer event bus for cross-account rule
    const producerEventBus = events.EventBus.fromEventBusArn(
      this, 
      'ProducerEventBus', 
      props.producerEventBusArn
    );

    // Create cross-account rule that routes to consumer event bus
    const crossAccountRule = new events.Rule(this, 'CrossAccountOrderProcessing', {
      ruleName: 'cross-account-order-processing',
      eventBus: producerEventBus,
      description: 'Routes order events from producer account to consumer processing',
      eventPattern: {
        source: ['mycompany.orders'],
        detailType: ['Order Created', 'Order Updated', 'Order Cancelled'],
        detail: {
          status: ['pending', 'confirmed', 'cancelled']
        }
      }
    });

    // Add consumer event bus as target for cross-account rule
    crossAccountRule.addTarget(new events_targets.EventBusTarget(consumerEventBus));

    // Create local rule in consumer account to process events
    const localProcessingRule = new events.Rule(this, 'LocalOrderProcessing', {
      ruleName: 'local-order-processing',
      eventBus: consumerEventBus,
      description: 'Processes cross-account order events locally',
      eventPattern: {
        source: ['mycompany.orders'],
        detailType: ['Order Created', 'Order Updated', 'Order Cancelled']
      }
    });

    // Add Lambda function as target with error handling
    localProcessingRule.addTarget(new events_targets.LambdaFunction(orderProcessorFunction, {
      deadLetterQueue: dlqQueue,
      maxEventAge: cdk.Duration.hours(2),
      retryAttempts: 3
    }));

    // Output important values
    new cdk.CfnOutput(this, 'OrderProcessorFunctionArn', {
      value: orderProcessorFunction.functionArn,
      description: 'Lambda function ARN for order processing'
    });

    new cdk.CfnOutput(this, 'ProcessedOrdersTableName', {
      value: processedOrdersTable.tableName,
      description: 'DynamoDB table name for processed orders'
    });

    new cdk.CfnOutput(this, 'ConsumerEventBusArn', {
      value: consumerEventBus.eventBusArn,
      description: 'Consumer event bus ARN'
    });
  }
}
```

## Step 6: Event Filtering and Routing Patterns

Advanced EventBridge configurations support sophisticated event filtering and routing patterns that enable fine-grained control over which events are processed by specific consumers.

Implement content-based filtering to route events based on their payload content:

```typescript
// Complex event pattern for content-based routing
const advancedEventPattern = {
  source: ['mycompany.orders'],
  'detail-type': ['Order Created', 'Order Updated'],
  detail: {
    status: ['confirmed'],
    amount: [{ numeric: ['>=', 1000] }], // Orders over $1000
    metadata: {
      priority: ['high', 'critical']
    }
  },
  region: ['us-east-1', 'us-west-2']
};

// Create rule with advanced filtering
const ruleCommand = new PutRuleCommand({
  Name: 'high-value-order-processing',
  EventBusName: 'arn:aws:events:us-east-1:123456789012:event-bus/orders-events',
  EventPattern: JSON.stringify(advancedEventPattern),
  State: 'ENABLED'
});
```

Implement transformation patterns to modify events before delivery:

```typescript
// EventBridge rule with input transformation
const transformedTargetsCommand = new PutTargetsCommand({
  Rule: 'high-value-order-processing',
  EventBusName: 'orders-events',
  Targets: [
    {
      Id: '1',
      Arn: 'arn:aws:lambda:us-east-1:987654321098:function:ProcessHighValueOrders',
      InputTransformer: {
        InputPathsMap: {
          orderId: '$.detail.orderId',
          amount: '$.detail.amount',
          timestamp: '$.time'
        },
        InputTemplate: JSON.stringify({
          processedOrderId: '<orderId>',
          orderValue: '<amount>',
          receivedAt: '<timestamp>',
          priority: 'high',
          crossAccountSource: true
        })
      }
    }
  ]
});
```

## Testing and Monitoring

Comprehensive testing and monitoring ensure reliable cross-account event delivery and processing. Implement both synthetic testing and real-time monitoring to detect issues quickly.

Create test events to validate cross-account routing:

```typescript
// Test event publisher for validation
async function publishTestEvent(): Promise<void> {
  const testEvent = {
    orderId: `test-${Date.now()}`,
    customerId: 'test-customer',
    status: 'pending' as const,
    amount: 100,
    timestamp: new Date().toISOString(),
    metadata: {
      test: true,
      environment: 'staging'
    }
  };

  const publisher = new OrderEventPublisher('orders-events');
  await publisher.publishOrderEvent(testEvent, 'Test Order Created');
}

// Automated test to verify cross-account delivery
export const testCrossAccountDelivery = async (): Promise<boolean> => {
  const testOrderId = `test-${Date.now()}`;
  
  // Publish test event
  await publishTestEvent();
  
  // Wait for processing
  await new Promise(resolve => setTimeout(resolve, 5000));
  
  // Verify event was processed in consumer account
  // Implementation depends on your storage/logging setup
  return true; // Replace with actual verification logic
};
```

Set up CloudWatch monitoring for cross-account EventBridge operations:

```typescript
// CloudWatch alarm for failed cross-account events
const failedEventsAlarm = {
  AlarmName: 'CrossAccountEventBridgeFailures',
  MetricName: 'FailedInvocations',
  Namespace: 'AWS/Events',
  Statistic: 'Sum',
  Period: 300,
  EvaluationPeriods: 2,
  Threshold: 5,
  ComparisonOperator: 'GreaterThanThreshold',
  Dimensions: [
    {
      Name: 'RuleName',
      Value: 'cross-account-order-processing'
    }
  ]
};
```

## Security Best Practices

Cross-account EventBridge integration requires careful security considerations to prevent unauthorized access and ensure event integrity. Implement multiple layers of security controls to protect sensitive event data.

**Event payload encryption** protects sensitive data in transit between accounts:

```typescript
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';

class SecureEventPublisher {
  private kmsClient: KMSClient;
  private keyId: string;

  constructor(keyId: string) {
    this.kmsClient = new KMSClient({ region: 'us-east-1' });
    this.keyId = keyId;
  }

  async publishSecureEvent(event: OrderEvent, eventType: string): Promise<void> {
    // Encrypt sensitive data before publishing
    const encryptCommand = new EncryptCommand({
      KeyId: this.keyId,
      Plaintext: Buffer.from(JSON.stringify(event))
    });

    const encryptedResult = await this.kmsClient.send(encryptCommand);
    
    const secureEvent = {
      encryptedPayload: Buffer.from(encryptedResult.CiphertextBlob!).toString('base64'),
      keyId: this.keyId,
      algorithm: 'AWS_KMS'
    };

    // Publish encrypted event
    const putEventsCommand = new PutEventsCommand({
      Entries: [{
        Source: 'mycompany.orders.secure',
        DetailType: eventType,
        Detail: JSON.stringify(secureEvent),
        EventBusName: 'orders-events'
      }]
    });

    await this.eventBridgeClient.send(putEventsCommand);
  }
}
```

## Deploying with AWS CDK

To deploy the complete cross-account EventBridge infrastructure, create a CDK application that coordinates both producer and consumer stacks:

```typescript
// app.ts - Main CDK application
import * as cdk from 'aws-cdk-lib';
import { ProducerAccountStack } from './producer-stack';
import { ConsumerAccountStack } from './consumer-stack';
import { EventPublisherStack } from './event-publisher-stack';
import { EventConsumerStack } from './event-consumer-stack';

const app = new cdk.App();

// Get account IDs from context or environment variables
const producerAccountId = app.node.tryGetContext('producerAccountId') || process.env.PRODUCER_ACCOUNT_ID;
const consumerAccountId = app.node.tryGetContext('consumerAccountId') || process.env.CONSUMER_ACCOUNT_ID;

// Deploy to producer account
const producerStack = new ProducerAccountStack(app, 'ProducerStack', {
  env: { account: producerAccountId, region: 'us-east-1' },
  consumerAccountId: consumerAccountId
});

const publisherStack = new EventPublisherStack(app, 'EventPublisherStack', {
  env: { account: producerAccountId, region: 'us-east-1' }
});

// Deploy to consumer account
const consumerStack = new ConsumerAccountStack(app, 'ConsumerStack', {
  env: { account: consumerAccountId, region: 'us-east-1' },
  producerAccountId: producerAccountId
});

const eventConsumerStack = new EventConsumerStack(app, 'EventConsumerStack', {
  env: { account: consumerAccountId, region: 'us-east-1' },
  producerAccountId: producerAccountId,
  producerEventBusArn: producerStack.ordersEventBus.eventBusArn
});

// Add dependencies
eventConsumerStack.addDependency(producerStack);
```

Deploy the stacks with proper account targeting:

```bash
# Set up environment variables
export PRODUCER_ACCOUNT_ID=123456789012
export CONSUMER_ACCOUNT_ID=987654321098

# Bootstrap CDK in both accounts (if not already done)
npx cdk bootstrap aws://123456789012/us-east-1 --profile producer-account
npx cdk bootstrap aws://987654321098/us-east-1 --profile consumer-account

# Deploy producer account infrastructure
npx cdk deploy ProducerStack EventPublisherStack \
    --profile producer-account \
    --context producerAccountId=123456789012 \
    --context consumerAccountId=987654321098

# Deploy consumer account infrastructure
npx cdk deploy ConsumerStack EventConsumerStack \
    --profile consumer-account \
    --context producerAccountId=123456789012 \
    --context consumerAccountId=987654321098
```

Create a `cdk.json` configuration file for consistent deployments:

```json
{
  "app": "npx ts-node --prefer-ts-exts app.ts",
  "watch": {
    "include": [
      "**"
    ],
    "exclude": [
      "README.md",
      "cdk*.json",
      "**/*.d.ts",
      "**/*.js",
      "tsconfig.json",
      "package*.json",
      "yarn.lock",
      "node_modules",
      "test"
    ]
  },
  "context": {
    "@aws-cdk/aws-lambda:recognizeLayerVersion": true,
    "@aws-cdk/core:checkSecretUsage": true,
    "@aws-cdk/core:target": "aws-cdk-lib",
    "@aws-cdk-containers/ecs-service-extensions:enableDefaultLogDriver": true,
    "@aws-cdk/aws-ec2:uniqueImdsv2TemplateName": true,
    "@aws-cdk/aws-ecs:arnFormatIncludesClusterName": true,
    "@aws-cdk/core:validateSnapshotRemovalPolicy": true,
    "@aws-cdk/aws-codepipeline:crossAccountKeyAliasStackSafeResourceName": true,
    "@aws-cdk/aws-s3:createDefaultLoggingPolicy": true,
    "@aws-cdk/aws-sns-subscriptions:restrictSqsDescryption": true,
    "@aws-cdk/aws-apigateway:disableCloudWatchRole": true,
    "@aws-cdk/core:enablePartitionLiterals": true,
    "@aws-cdk/aws-events:eventsTargetQueueSameAccount": true,
    "@aws-cdk/aws-iam:minimizePolicies": true,
    "@aws-cdk/core:disableStackIdSuffix": true,
    "@aws-cdk/aws-lambda:recognizeVersionProps": true,
    "@aws-cdk/aws-cloudfront:defaultSecurityPolicyTLSv1.2_2021": true
  }
}
```

**Network isolation** using VPC endpoints provides additional security for EventBridge operations:

```bash
# Create VPC endpoint for EventBridge
aws ec2 create-vpc-endpoint \
    --vpc-id vpc-12345678 \
    --service-name com.amazonaws.us-east-1.events \
    --vpc-endpoint-type Interface \
    --subnet-ids subnet-12345678 subnet-87654321 \
    --security-group-ids sg-12345678
```

Cross-account EventBridge integration enables powerful event-driven architectures that span organizational boundaries while maintaining security and isolation. By implementing proper IAM policies, event filtering, and monitoring, you can build robust systems that process events reliably across multiple AWS accounts. Start with basic cross-account rules and gradually add security enhancements and advanced routing patterns as your requirements evolve.

The patterns demonstrated in this guide provide a foundation for implementing sophisticated event-driven workflows in enterprise environments where different teams and applications operate in separate AWS accounts while maintaining seamless integration capabilities.
