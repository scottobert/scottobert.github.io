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
series: "AWS Cross-Account Patterns"
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

    // Surface the ARN so you can copy it into the consumer account's config.
    // Note: `exportName` creates a CloudFormation export, which is resolvable
    // only within this account and region -- `Fn::ImportValue` cannot cross an
    // account boundary. Treat this as a convenience output, not a wiring
    // mechanism; the consumer account gets the ARN via SSM, config file or
    // pipeline variable.
    new cdk.CfnOutput(this, 'OrdersEventBusArn', {
      value: this.ordersEventBus.eventBusArn
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

### Step 2: Which Account Grants What — Getting the Direction Right

This is the step people get backwards, so it's worth being precise. Events flow producer → consumer, and **the resource policy goes on the receiving end**: the *consumer's* event bus grants `events:PutEvents` to the producer. The producer's bus does not need a policy for this pattern at all.

```typescript
import * as iam from 'aws-cdk-lib/aws-iam';

export class ConsumerAccountStack extends cdk.Stack {
  public readonly consumerEventBus: events.EventBus;

  constructor(scope: Construct, id: string, props: cdk.StackProps & {
    producerAccountId: string;
  }) {
    super(scope, id, props);

    this.consumerEventBus = new events.EventBus(this, 'ConsumerEventBus', {
      eventBusName: 'consumer-events'
    });

    // Let the producer account deliver events into our bus.
    this.consumerEventBus.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowProducerAccountToPutEvents',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountPrincipal(props.producerAccountId)],
      actions: ['events:PutEvents'],
      resources: [this.consumerEventBus.eventBusArn],
      // Narrow the grant to the events we actually expect. Without this the
      // producer account can push anything at all onto our bus.
      conditions: {
        StringEquals: { 'events:source': 'mycompany.orders' }
      }
    }));
  }
}
```

In an AWS Organization, prefer `new iam.OrganizationPrincipal('o-abc123')` over enumerating account IDs — new producer accounts then work without a policy change.

You may also see the reverse arrangement, where the producer's bus grants `events:PutRule` and `events:PutTargets` so the *consumer* can create a rule directly on the producer's bus. EventBridge does support this (the `PutRule` family accepts a full bus ARN), but it is the harder road: the rule lives in the producer's account, so the IAM role EventBridge assumes to deliver the event must also live there, which means the producer has to pre-create that role and grant `iam:PassRole` anyway. You end up coordinating more, not less. Use the `PutEvents` direction above unless you have a specific reason not to.

### Step 3: Creating the Event Flow

Now the producer forwards matching events to the consumer's bus. Two things are mandatory here and both are easy to omit:

- **A rule target for a cross-account bus needs a `RoleArn`.** EventBridge assumes that role to call `PutEvents` on the destination. CDK creates it for you when you use `targets.EventBus`; if you are writing raw CloudFormation or CLI calls, you must supply it yourself.
- **A dead-letter queue.** Cross-account delivery can fail for reasons entirely outside the producer's control — the consumer's policy changed, the bus was deleted. Without a DLQ those events are silently dropped after EventBridge exhausts its retries.

```typescript
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as sqs from 'aws-cdk-lib/aws-sqs';

export class ProducerAccountStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: cdk.StackProps & {
    consumerEventBusArn: string;
  }) {
    super(scope, id, props);

    const ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
      eventBusName: 'orders-events'
    });

    // Undeliverable events land here instead of vanishing.
    const deliveryDlq = new sqs.Queue(this, 'CrossAccountDeliveryDlq', {
      retentionPeriod: cdk.Duration.days(14),
      enforceSSL: true
    });

    const crossAccountRule = new events.Rule(this, 'ForwardOrdersToConsumer', {
      eventBus: ordersEventBus,
      eventPattern: {
        source: ['mycompany.orders'],
        detailType: ['Order Created', 'Order Updated', 'Order Cancelled']
      }
    });

    // The class is `targets.EventBus` -- CDK synthesises the delivery role
    // and wires it to the target automatically.
    crossAccountRule.addTarget(new events_targets.EventBus(
      events.EventBus.fromEventBusArn(
        this, 'ConsumerEventBus', props.consumerEventBusArn
      ),
      { deadLetterQueue: deliveryDlq }
    ));
  }
}
```

Back in the consumer account, a local rule picks the events up off the consumer bus and hands them to a Lambda function:

```typescript
const localRule = new events.Rule(this, 'ProcessOrdersLocally', {
  eventBus: this.consumerEventBus,
  eventPattern: {
    source: ['mycompany.orders']
  }
});

localRule.addTarget(new events_targets.LambdaFunction(orderProcessor, {
  deadLetterQueue: processingDlq,
  retryAttempts: 2
}));
```

### One limitation to design around

**Events cannot be forwarded twice.** If the consumer account sets up a rule that sends events it received from the producer on to a *third* account's bus, those events are not delivered. EventBridge permits exactly one cross-account hop.

This matters for hub-and-spoke designs. A central bus that receives from every producer and re-fans-out to every consumer looks obvious on a whiteboard and does not work. Instead, have each producer target the consumer buses directly, or have consumers subscribe to the producer's bus — one hop either way. The same region constraint applies to bus-to-bus delivery, so a cross-region *and* cross-account hop needs the region change handled separately.

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
  private eventBridge = new EventBridgeClient({});

  async publishOrderEvent(event: OrderEvent, eventType: string): Promise<void> {
    const response = await this.eventBridge.send(new PutEventsCommand({
      Entries: [{
        Source: 'mycompany.orders',
        DetailType: eventType,
        Detail: JSON.stringify(event),
        EventBusName: 'orders-events',
        Time: new Date()
      }]
    }));

    // This is the single most important thing to get right about PutEvents:
    // it returns HTTP 200 even when entries were rejected. The SDK does not
    // throw. If you ignore FailedEntryCount you will lose events silently and
    // your metrics will show a perfectly healthy publisher.
    if (response.FailedEntryCount && response.FailedEntryCount > 0) {
      const failures = (response.Entries ?? [])
        .filter(entry => entry.ErrorCode)
        .map(entry => `${entry.ErrorCode}: ${entry.ErrorMessage}`);

      throw new Error(
        `PutEvents rejected ${response.FailedEntryCount} of 1 entries: ${failures.join('; ')}`
      );
    }
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

Two things matter here. Keep event schemas consistent, so every order event has the same basic shape and consumers can process them reliably. And batch carefully: `PutEvents` accepts up to 10 entries or 256 KB per call, and a partial rejection means *some* of your batch landed. Retrying the whole batch then duplicates the entries that succeeded, which is one more reason consumers must be idempotent.

**On the consumer side**, we process these cross-account events with clean, focused Lambda functions:

```typescript
import { EventBridgeEvent } from 'aws-lambda';
import {
  DynamoDBClient,
  PutItemCommand,
  ConditionalCheckFailedException
} from '@aws-sdk/client-dynamodb';

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
  try {
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
  } catch (error) {
    // The conditional write is only half of idempotency. On a duplicate
    // delivery DynamoDB throws ConditionalCheckFailedException, and if that
    // escapes the handler the invocation fails, EventBridge retries, and the
    // same duplicate fails again -- until the event ends up in the DLQ. A
    // duplicate is a success case here, so swallow exactly this error.
    if (error instanceof ConditionalCheckFailedException) {
      console.log(`Order ${order.orderId} already processed, skipping`);
      return;
    }
    throw error;
  }

  // Trigger downstream processes like inventory allocation, shipping prep, etc.
  // await allocateInventory(order);
  // await notifyWarehouse(order);
}
```

The consumer pattern emphasises **idempotency** and **error handling**. EventBridge guarantees at-least-once delivery, so duplicates are normal operation rather than an error condition — and note that the guard above only protects the DynamoDB write. Everything after it (inventory allocation, warehouse notification) runs again on a duplicate unless it is separately idempotent. That is usually the bug: the database is protected and the side effects are not.

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
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

// Create synthetic test events to validate your pipeline end to end.
// The point of a canary is that it can fail, so it has to actually assert
// something on the consumer side -- a helper that ends in `return true`
// passes even when the pipeline is completely broken.
async function validateCrossAccountFlow(
  publisher: OrderEventPublisher,
  dynamodb: DynamoDBClient
): Promise<boolean> {
  const testOrderId = `canary-${Date.now()}`;

  await publisher.publishOrderEvent({
    orderId: testOrderId,
    customerId: 'canary-customer',
    status: 'pending',
    amount: 100,
    timestamp: new Date().toISOString()
  }, 'Order Created');

  // Poll rather than sleeping a fixed interval: cross-account delivery is
  // usually sub-second but the tail is long, and a hard-coded 3s sleep turns
  // a slow pipeline into a flaky test.
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const result = await dynamodb.send(new GetItemCommand({
      TableName: 'ProcessedOrders',
      Key: { orderId: { S: testOrderId } },
      ConsistentRead: true
    }));

    if (result.Item) {
      return true;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  throw new Error(
    `Canary order ${testOrderId} never arrived in the consumer account within 30s`
  );
}
```

Run this on a schedule against production. Cross-account event delivery is exactly the kind of thing that breaks quietly during an unrelated IAM cleanup, and a canary that writes a real event through the real path is the only check that catches a policy change immediately.

Set up CloudWatch alarms for the metrics that matter:

- **Failed invocations** on your EventBridge rules
- **Dead letter queue depth** for your Lambda consumers  
- **Cross-account delivery failures** using EventBridge metrics

## Security Considerations for Production

**Principle of least privilege** becomes critical in cross-account scenarios. The `events:source` condition shown in Step 2 is the main lever — it stops a producer account from putting arbitrary events onto your bus. Also worth knowing: EventBridge supports customer managed KMS keys on a custom bus, so events are encrypted at rest under a key you control rather than an AWS-owned one:

```typescript
const ordersEventBus = new events.EventBus(this, 'OrdersEventBus', {
  eventBusName: 'orders-events',
  kmsKey: encryptionKey   // customer managed key, key policy must allow events.amazonaws.com
});
```

**Do not hand-roll payload encryption on top of this.** It is tempting to encrypt the `detail` before publishing, but it breaks the thing that makes EventBridge useful: rules match on event content, so an encrypted payload cannot be filtered or routed, and every consumer needs `kms:Decrypt` plus your envelope format. `kms:Encrypt` also caps plaintext at 4 KB, which real order payloads exceed.

If a payload genuinely must not be visible to the event bus, use the **claim check** pattern instead — put the sensitive body in S3 under a key only the intended consumer can read, and publish an event containing the pointer plus whatever non-sensitive attributes rules need to match on:

```typescript
interface OrderEventEnvelope {
  orderId: string;
  status: 'pending' | 'confirmed' | 'cancelled';
  // Routable, non-sensitive attributes stay in the event...
  region: string;
  // ...and the sensitive body lives behind a reference.
  payloadLocation: { bucket: string; key: string };
}
```

This keeps the sensitive data out of the event entirely, keeps rules working, and reduces the access grant to a single S3 prefix.

## Putting It All Together

Cross-account EventBridge integration solves real business problems elegantly. Instead of building complex API integrations between teams and accounts, you create a clean event-driven architecture that scales naturally and maintains security boundaries.

The pattern works particularly well when you have:
- **Clear event schemas** that multiple consumers can understand
- **Idempotent processing** that handles duplicate events gracefully  
- **Comprehensive monitoring** that alerts you to delivery issues quickly
- **Security policies** that follow least-privilege principles

Start simple with basic cross-account event routing, then add advanced features like content filtering, transformation, and encryption as your needs evolve. The foundational patterns demonstrated here will support sophisticated event-driven workflows that span organizational boundaries while maintaining the security and isolation that separate AWS accounts provide.

## More in This Series

This is post 2 of 5 in the **AWS Cross-Account Patterns** series:

1. [Cross-Account Lambda Access to S3](/posts/cross-account-lambda-s3-access/)
2. **Cross-Account EventBridge Integration** (this post)
3. [Implementing Cross-Account CI/CD Pipelines](/posts/2025/08/06/cross-account-cicd-pipelines/)
4. [Cross-Account Monitoring and Observability](/posts/cross-account-monitoring-observability/)
5. [Simplified Cross-Account Backup and Disaster Recovery](/posts/2025/08/20/simplified-aws-backup-cross-account/)
