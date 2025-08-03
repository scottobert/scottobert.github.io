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

Imagine running an e-commerce platform that processes thousands of orders daily across multiple AWS accounts. The Orders team manages customer transactions in Account A, while the Fulfillment team handles inventory and shipping from Account B. Without proper integration, these teams find themselves trapped in a cycle of polling APIs, batch file transfers, and—worse yet—manual processes that introduce delays and potential data inconsistencies.

This integration nightmare is exactly why Amazon EventBridge's cross-account capabilities have become a game-changer for enterprise architects. Instead of building complex point-to-point integrations that inevitably break under scale, you can create elegant event-driven workflows that automatically route order events from producer accounts to consumer systems in real-time, all while maintaining the strict security boundaries that drove you to multi-account architecture in the first place.

{{< image src="/posts/2025/07/30/cross-account-eventbridge-integration.png" alt="Overview of cross-account EventBridge integration architecture showing events flowing from one AWS account to another" width="800" >}}

Cross-account EventBridge integration transforms how enterprise applications communicate across organizational boundaries. Events generated in one AWS account seamlessly trigger processing in another, enabling complex workflows while preserving the security isolation that separate accounts provide. This pattern has become essential for large organizations where different business units or environments operate independently but need to share critical business events.

## When You Need Cross-Account Event Integration

Before diving into the technical implementation, let's explore the scenarios where cross-account EventBridge becomes invaluable:

**Multi-team organizations** often separate concerns by AWS account—the Platform team manages shared infrastructure in one account while individual product teams operate in their own accounts. When a user signs up in the Auth account, multiple downstream systems need notification: the Marketing account for campaign attribution, the Analytics account for user tracking, and the Billing account for subscription setup.

**Environment separation** becomes critical when you need production events to trigger staging or development processes. Security teams might run vulnerability scanning in a separate account that needs notification when new container images are pushed to production registries.

**Compliance requirements** frequently mandate data segregation, but business processes still need coordination. A healthcare application might store patient data in a HIPAA-compliant account while processing billing events in a separate financial systems account.

**Vendor integrations** work seamlessly when third-party SaaS providers need access to specific events without broad account permissions. You can route sanitized events to a dedicated integration account that partners can access without exposing your core infrastructure.

## The Architecture: Simple Yet Powerful

The beauty of cross-account EventBridge lies in its simplicity. Three core components work together to create a secure, scalable event pipeline:

The **Producer Account** (let's call it Account A) generates business events—new orders, user registrations, payment confirmations—and publishes them to a custom EventBridge bus. The **Consumer Account** (Account B) receives these events through carefully configured cross-account permissions and processes them with Lambda functions, Step Functions, or any other AWS service. **Resource-based policies** act as the security gatekeepers, controlling exactly which accounts can send events to which buses.

Think of it like a secure postal system between buildings. The producer account drops events into a specific mailbox (custom event bus), the EventBridge service routes them across account boundaries, and the consumer account processes them according to predefined rules.

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

## Implementation: Building Your Event Pipeline

Let's build this step by step using our e-commerce example. We'll create custom event buses, configure secure cross-account access, and implement both event publishers and consumers.

### Step 1: Custom Event Buses - Your Foundation

Custom event buses provide the isolation and access control necessary for cross-account scenarios. Unlike the default event bus, custom buses allow fine-grained permissions and cleaner event organization.

Here's the most straightforward approach using AWS CDK (though I'll show CLI alternatives for those who prefer them):

```typescript
import * as events from 'aws-cdk-lib/aws-events';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export class EventBusStack extends cdk.Stack {
  public readonly ordersEventBus: events.EventBus;
  public readonly consumerEventBus: events.EventBus;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Producer account: Create event bus for orders
    this.ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
      eventBusName: 'orders-events',
      description: 'Cross-account event bus for order processing'
    });

    // Consumer account: Create event bus for processing
    this.consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events',
      description: 'Receives and processes cross-account events'
    });

    // Export the ARN for cross-account reference
    new cdk.CfnOutput(this, 'OrdersEventBusArn', {
      value: this.ordersEventBus.eventBusArn,
      exportName: 'OrdersEventBusArn'
    });
  }
}
```

> **Quick Alternative**: If you prefer CLI commands, you can create these buses with:
>
> ```bash
> aws events create-event-bus --name orders-events
> aws events create-event-bus --name consumer-events
> ```

### Step 2: Cross-Account Permissions - The Security Layer

This is where the magic happens. We need to tell the producer account's event bus that it's okay to receive rules and targets from the consumer account. Think of this as giving the consumer account a key to the producer's mailbox.

The cleanest approach uses CDK to set up these permissions declaratively:

```typescript
import * as iam from 'aws-cdk-lib/aws-iam';

export class ProducerAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: { consumerAccountId: string }) {
    super(scope, id);

    const ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
      eventBusName: 'orders-events'
    });

    // Grant the consumer account permission to create rules and targets
    ordersEventBus.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowCrossAccountAccess',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal(props.consumerAccountId)],
      actions: [
        'events:PutRule',
        'events:PutTargets',
        'events:DeleteRule',
        'events:RemoveTargets'
      ],
      resources: [ordersEventBus.eventBusArn]
    }));
  }
}
```

This resource policy essentially says: "Consumer account 987654321098, you're allowed to create rules on my event bus and tell me where to send matching events."

### Step 3: Creating the Event Flow

Now we connect the dots. The consumer account creates a rule on the producer's event bus that says "when you see order events, send them to my event bus." Here's how that works:

```typescript
import * as events_targets from 'aws-cdk-lib/aws-events-targets';

export class ConsumerAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: {
    producerAccountId: string;
    producerEventBusArn: string;
  }) {
    super(scope, id);

    // Consumer's event bus for processing
    const consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events'
    });

    // Import the producer's event bus
    const producerEventBus = events.EventBus.fromEventBusArn(
      this, 'ProducerEventBus', props.producerEventBusArn
    );

    // Create rule on producer's bus that routes to our bus
    const crossAccountRule = new events.Rule(this, 'CrossAccountOrderRule', {
      eventBus: producerEventBus,
      eventPattern: {
        source: ['mycompany.orders'],
        detailType: ['Order Created', 'Order Updated', 'Order Cancelled']
      }
    });

    // Route matching events to our consumer bus
    crossAccountRule.addTarget(new events_targets.EventBusTarget(consumerEventBus));
    
    // Now create a local rule to process events in our account
    const localRule = new events.Rule(this, 'ProcessOrdersLocally', {
      eventBus: consumerEventBus,
      eventPattern: {
        source: ['mycompany.orders']
      }
    });
    
    // We'll add targets like Lambda functions here in the next step
  }
}
```

The beauty of this setup is that the consumer account controls its own destiny. It decides which events it wants from the producer and where those events should go locally.

### Step 4: Publishers and Consumers - The Business Logic

Now for the fun part—actually sending and receiving events. Let's start with a clean, reusable event publisher:

```typescript
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';

interface OrderEvent {
  orderId: string;
  customerId: string;
  status: 'pending' | 'confirmed' | 'cancelled';
  amount: number;
  timestamp: string;
}

class OrderEventPublisher {
  private eventBridge = new EventBridgeClient({ region: 'us-east-1' });
  
  async publishOrderEvent(event: OrderEvent, eventType: string): Promise<void> {
    await this.eventBridge.send(new PutEventsCommand({
      Entries: [{
        Source: 'mycompany.orders',
        DetailType: eventType,
        Detail: JSON.stringify(event),
        EventBusName: 'orders-events',
        Time: new Date()
      }]
    }));
  }
}

// Usage in your order processing Lambda
export const handleOrderCreated = async (orderData: any) => {
  const publisher = new OrderEventPublisher();
  
  await publisher.publishOrderEvent({
    orderId: orderData.id,
    customerId: orderData.customerId,
    status: 'pending',
    amount: orderData.totalAmount,
    timestamp: new Date().toISOString()
  }, 'Order Created');
};
```

The key insight here is maintaining consistent event schemas. Every order event should have the same basic structure, making it easier for consumers to process them reliably.

**On the consumer side**, we process these cross-account events with clean, focused Lambda functions:

```typescript
import { EventBridgeEvent } from 'aws-lambda';
import { DynamoDBClient, PutItemCommand } from '@aws-sdk/client-dynamodb';

interface OrderEventDetail {
  orderId: string;
  customerId: string;
  status: string;
  amount: number;
  timestamp: string;
}

const dynamodb = new DynamoDBClient({ region: 'us-east-1' });

export const processOrderEvent = async (
  event: EventBridgeEvent<string, OrderEventDetail>
): Promise<void> => {
  const { detail, 'detail-type': eventType, account } = event;
  
  console.log(`Processing ${eventType} from account ${account}:`, detail.orderId);

  // Route to appropriate handler based on event type
  switch (eventType) {
    case 'Order Created':
      await handleNewOrder(detail);
      break;
    case 'Order Updated':
      await handleOrderUpdate(detail);
      break;
    case 'Order Cancelled':
      await handleOrderCancellation(detail);
      break;
    default:
      console.warn(`Unknown event type: ${eventType}`);
  }
};

async function handleNewOrder(order: OrderEventDetail): Promise<void> {
  // Idempotent processing - only create if doesn't exist
  await dynamodb.send(new PutItemCommand({
    TableName: 'ProcessedOrders',
    Item: {
      orderId: { S: order.orderId },
      customerId: { S: order.customerId },
      status: { S: order.status },
      amount: { N: order.amount.toString() },
      processedAt: { S: new Date().toISOString() }
    },
    ConditionExpression: 'attribute_not_exists(orderId)'
  }));
  
  // Trigger downstream processes like inventory allocation, shipping prep, etc.
  // await allocateInventory(order);
  // await notifyWarehouse(order);
}
```

The consumer pattern emphasizes **idempotency** and **error handling**. Since events might be delivered more than once, your processing logic should be safe to run multiple times without side effects.

## Advanced Patterns That Matter

### Content-Based Routing

You can create sophisticated routing rules that filter events based on their content. For example, high-value orders might need special handling:

```typescript
// Route only high-value orders to premium processing
const highValueOrderRule = new events.Rule(this, 'HighValueOrders', {
  eventBus: producerEventBus,
  eventPattern: {
    source: ['mycompany.orders'],
    detailType: ['Order Created'],
    detail: {
      amount: [{ numeric: ['>=', 1000] }], // Orders >= $1000
      status: ['confirmed']
    }
  }
});
```

### Event Transformation

EventBridge can transform events before delivery, which is incredibly useful for cross-account scenarios where you want to sanitize or reshape data:

```typescript
crossAccountRule.addTarget(new events_targets.LambdaFunction(processorFunction, {
  event: events.RuleTargetInput.fromObject({
    orderId: events.EventField.fromPath('$.detail.orderId'),
    value: events.EventField.fromPath('$.detail.amount'),
    timestamp: events.EventField.fromPath('$.time'),
    priority: 'high',
    source: 'cross-account'
  })
}));
```

## Testing and Monitoring: Don't Skip This

Testing cross-account EventBridge requires a different approach than single-account testing. Here's a pragmatic testing strategy:

```typescript
// Create synthetic test events to validate your pipeline
async function validateCrossAccountFlow(): Promise<boolean> {
  const testOrderId = `test-${Date.now()}`;
  
  // Publish test event
  await publisher.publishOrderEvent({
    orderId: testOrderId,
    customerId: 'test-customer',
    status: 'pending',
    amount: 100,
    timestamp: new Date().toISOString()
  }, 'Order Created');
  
  // Wait a moment for processing
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Verify the event was processed in consumer account
  // (Check your DynamoDB table, logs, or other indicators)
  return true;
}
```

Set up CloudWatch alarms for the metrics that matter:

- **Failed invocations** on your EventBridge rules
- **Dead letter queue depth** for your Lambda consumers  
- **Cross-account delivery failures** using EventBridge metrics

## Security Considerations for Production

**Principle of least privilege** becomes critical in cross-account scenarios. Only grant the minimum permissions necessary:

```typescript
// Restrict permissions to specific event patterns
ordersEventBus.addToResourcePolicy(new iam.PolicyStatement({
  effect: iam.Effect.ALLOW,
  principals: [new iam.AccountPrincipal(consumerAccountId)],
  actions: ['events:PutRule'],
  resources: [ordersEventBus.eventBusArn],
  conditions: {
    StringEquals: {
      'events:source': 'mycompany.orders'
    }
  }
}));
```

For sensitive data, consider **event payload encryption**:

```typescript
import { KMSClient, EncryptCommand } from '@aws-sdk/client-kms';

class SecureOrderPublisher extends OrderEventPublisher {
  private kms = new KMSClient({ region: 'us-east-1' });
  
  async publishSecureOrderEvent(event: OrderEvent, eventType: string): Promise<void> {
    const encrypted = await this.kms.send(new EncryptCommand({
      KeyId: 'arn:aws:kms:us-east-1:123456789012:key/your-key-id',
      Plaintext: Buffer.from(JSON.stringify(event))
    }));
    
    // Publish encrypted payload
    await this.publishOrderEvent({
      ...event,
      encryptedData: Buffer.from(encrypted.CiphertextBlob!).toString('base64')
    }, eventType);
  }
}
```

## Putting It All Together

Cross-account EventBridge integration solves real business problems elegantly. Instead of building complex API integrations between teams and accounts, you create a clean event-driven architecture that scales naturally and maintains security boundaries.

The pattern works particularly well when you have:
- **Clear event schemas** that multiple consumers can understand
- **Idempotent processing** that handles duplicate events gracefully  
- **Comprehensive monitoring** that alerts you to delivery issues quickly
- **Security policies** that follow least-privilege principles

Start simple with basic cross-account event routing, then add advanced features like content filtering, transformation, and encryption as your needs evolve. The foundational patterns demonstrated here will support sophisticated event-driven workflows that span organizational boundaries while maintaining the security and isolation that separate AWS accounts provide.
