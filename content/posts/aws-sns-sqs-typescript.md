---
title: "Building Event-Driven Architectures with AWS SNS/SQS and TypeScript"
date: 2023-05-21T11:00:00-07:00
draft: false
categories: ["Cloud Computing", "Architecture and Design"]
tags:
- AWS
- TypeScript
- Serverless
- Development
- Architecture
series: "AWS and Typescript"
---

Event-driven architectures form the backbone of modern cloud applications, enabling systems to scale gracefully while maintaining loose coupling between components. This post explores how AWS SNS and SQS, combined with TypeScript's type safety, create robust messaging patterns that handle everything from simple notifications to complex distributed workflows.

## Event-Driven Architecture Benefits

Event-driven systems offer compelling advantages for modern applications. **Loose coupling** allows services to evolve independently without breaking dependencies. **Natural scalability** emerges as components can scale based on their specific load patterns rather than system-wide peaks. **Resilience** improves through built-in buffering and retry mechanisms that handle traffic spikes and temporary failures gracefully.

Most importantly, **operational simplicity** increases as complex business logic becomes a series of discrete, testable event handlers rather than monolithic processes.

## SNS and SQS Messaging Patterns

Understanding the core messaging patterns helps you choose the right approach for your use cases:

{{< plantuml id="messaging-patterns" >}}
@startuml
!theme aws-orange
title SNS/SQS Messaging Patterns

package "Publish/Subscribe Pattern" {
  [Order Service] as OrderSvc
  [SNS Topic] as Topic
  [Email Service] as EmailSvc
  [Analytics Service] as AnalyticsSvc
  [Inventory Service] as InventorySvc
  
  OrderSvc --> Topic : publish event
  Topic --> EmailSvc : notification
  Topic --> AnalyticsSvc : metrics
  Topic --> InventorySvc : update stock
}

package "Point-to-Point Queuing" {
  [Producer] as Prod
  [SQS Queue] as Queue
  [Consumer] as Cons
  [DLQ] as DLQ
  
  Prod --> Queue : send message
  Queue --> Cons : process message
  Queue --> DLQ : failed messages
}

package "Fan-out Pattern" {
  [Event Source] as Source
  [SNS Topic] as FanTopic
  [Queue 1] as Q1
  [Queue 2] as Q2
  [Queue 3] as Q3
  [Lambda 1] as L1
  [Lambda 2] as L2
  [Lambda 3] as L3
  
  Source --> FanTopic
  FanTopic --> Q1
  FanTopic --> Q2
  FanTopic --> Q3
  Q1 --> L1
  Q2 --> L2
  Q3 --> L3
}

@enduml
{{< /plantuml >}}

These patterns provide the foundation for building scalable event-driven systems with clear separation of concerns and predictable data flow.

## Prerequisites

Before building event-driven systems with SNS and SQS, ensure you have:

- **AWS SDK v3** with `@aws-sdk/client-sns` and `@aws-sdk/client-sqs` packages
- **TypeScript development environment** configured for Node.js
- **AWS CLI** installed and configured with appropriate permissions
- **Understanding of event-driven concepts** and messaging patterns

## Infrastructure Setup with SAM

Let's build a complete order processing system that demonstrates real-world messaging patterns:

```yaml
# template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Parameters:
  Environment:
    Type: String
    Default: dev

Resources:
  # SNS Topic for order events
  OrderEventsTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub 'order-events-${Environment}'
      DisplayName: 'Order Processing Events'

  # High priority queue for critical orders
  CriticalOrdersQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'critical-orders-${Environment}'
      VisibilityTimeout: 300
      MessageRetentionPeriod: 1209600 # 14 days
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt CriticalOrdersDLQ.Arn
        maxReceiveCount: 3

  # Standard queue for regular orders
  StandardOrdersQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'standard-orders-${Environment}'
      VisibilityTimeout: 300
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt StandardOrdersDLQ.Arn
        maxReceiveCount: 5

  # Dead letter queues
  CriticalOrdersDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'critical-orders-dlq-${Environment}'
      MessageRetentionPeriod: 1209600

  StandardOrdersDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Sub 'standard-orders-dlq-${Environment}'
      MessageRetentionPeriod: 1209600

  # Filtered subscriptions based on order priority
  CriticalOrdersSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref OrderEventsTopic
      Protocol: sqs
      Endpoint: !GetAtt CriticalOrdersQueue.Arn
      FilterPolicy:
        priority: ['HIGH']

  StandardOrdersSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref OrderEventsTopic
      Protocol: sqs
      Endpoint: !GetAtt StandardOrdersQueue.Arn
      FilterPolicy:
        priority: ['MEDIUM', 'LOW']

  # Order processing Lambda functions
  CriticalOrderProcessor:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub 'critical-order-processor-${Environment}'
      Handler: src/handlers/processCriticalOrder.handler
      Runtime: nodejs18.x
      Timeout: 60
      ReservedConcurrencyLimit: 50
      Events:
        SQSEvent:
          Type: SQS
          Properties:
            Queue: !GetAtt CriticalOrdersQueue.Arn
            BatchSize: 5

  StandardOrderProcessor:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: !Sub 'standard-order-processor-${Environment}'
      Handler: src/handlers/processStandardOrder.handler
      Runtime: nodejs18.x
      Timeout: 30
      Events:
        SQSEvent:
          Type: SQS
          Properties:
            Queue: !GetAtt StandardOrdersQueue.Arn
            BatchSize: 10

Outputs:
  OrderEventsTopicArn:
    Description: "Order Events SNS Topic ARN"
    Value: !Ref OrderEventsTopic
    Export:
      Name: !Sub '${AWS::StackName}-OrderEventsTopic'
```

This infrastructure demonstrates several key patterns:

- **Message filtering** routes messages to appropriate queues based on priority
- **Dead letter queues** handle persistent failures gracefully
- **Different processing strategies** for critical vs. standard orders
- **Parameterized resources** enable environment-specific deployments

## Type-Safe Event Implementation

### Event Type Definitions

Strong typing is crucial for maintainable event-driven systems. Define comprehensive interfaces that capture your business domain:

```typescript
// src/types/events.ts
export interface OrderEvent {
  eventId: string;
  eventType: OrderEventType;
  orderId: string;
  timestamp: string;
  version: string;
  source: string;
  data: OrderData;
  metadata: EventMetadata;
}

export enum OrderEventType {
  CREATED = 'ORDER_CREATED',
  UPDATED = 'ORDER_UPDATED',
  CANCELLED = 'ORDER_CANCELLED',
  PAYMENT_PROCESSED = 'PAYMENT_PROCESSED',
  FULFILLED = 'ORDER_FULFILLED'
}

export interface OrderData {
  customerId: string;
  items: OrderItem[];
  totalAmount: number;
  currency: string;
  status: OrderStatus;
  shippingAddress?: Address;
}

export interface EventMetadata {
  priority: MessagePriority;
  correlationId: string;
  causationId?: string;
  userId?: string;
}

export enum MessagePriority {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM', 
  LOW = 'LOW'
}

export interface OrderItem {
  productId: string;
  quantity: number;
  unitPrice: number;
  productName: string;
}

export enum OrderStatus {
  PENDING = 'PENDING',
  CONFIRMED = 'CONFIRMED',
  PROCESSING = 'PROCESSING',
  SHIPPED = 'SHIPPED',
  DELIVERED = 'DELIVERED',
  CANCELLED = 'CANCELLED'
}
```

### Event Publisher Service

Create a robust publisher that handles message formatting, retry logic, and error handling:

```typescript
// src/services/eventPublisher.ts
import { SNSClient, PublishCommand, MessageAttributeValue } from '@aws-sdk/client-sns';
import { OrderEvent } from '../types/events';

export class EventPublisher {
  private sns: SNSClient;
  private topicArn: string;

  constructor(topicArn: string, region?: string) {
    this.sns = new SNSClient({ region });
    this.topicArn = topicArn;
  }

  async publishEvent(event: OrderEvent, options?: PublishOptions): Promise<PublishResult> {
    const messageAttributes = this.buildMessageAttributes(event);
    
    const command = new PublishCommand({
      TopicArn: this.topicArn,
      Message: JSON.stringify(event),
      Subject: `Order Event: ${event.eventType}`,
      MessageAttributes: messageAttributes,
      MessageDeduplicationId: options?.deduplicationId,
      MessageGroupId: options?.groupId
    });

    try {
      const startTime = Date.now();
      const response = await this.sns.send(command);
      const duration = Date.now() - startTime;

      console.log(`Event published successfully: ${response.MessageId} (${duration}ms)`);
      
      return {
        messageId: response.MessageId!,
        success: true,
        duration
      };
    } catch (error) {
      console.error('Failed to publish event:', error);
      throw new EventPublishError(`Failed to publish event: ${error.message}`, error);
    }
  }

  private buildMessageAttributes(event: OrderEvent): Record<string, MessageAttributeValue> {
    return {
      eventType: {
        DataType: 'String',
        StringValue: event.eventType
      },
      priority: {
        DataType: 'String',
        StringValue: event.metadata.priority
      },
      orderId: {
        DataType: 'String',
        StringValue: event.orderId
      },
      correlationId: {
        DataType: 'String',
        StringValue: event.metadata.correlationId
      },
      version: {
        DataType: 'String',
        StringValue: event.version
      }
    };
  }
}

export interface PublishOptions {
  deduplicationId?: string;
  groupId?: string;
}

export interface PublishResult {
  messageId: string;
  success: boolean;
  duration: number;
}

export class EventPublishError extends Error {
  constructor(message: string, public readonly cause: any) {
    super(message);
    this.name = 'EventPublishError';
  }
}
```

### Message Processing with Error Handling

Implement robust message processors that handle failures gracefully:

```typescript
// src/handlers/processCriticalOrder.ts
import { SQSEvent, Context } from 'aws-lambda';
import { OrderEvent, OrderEventType } from '../types/events';

export const handler = async (event: SQSEvent, context: Context): Promise<void> => {
  console.log(`Processing ${event.Records.length} critical order messages`);

  const results = await Promise.allSettled(
    event.Records.map(record => processMessage(record, context))
  );

  // Handle partial failures
  const failures = results.filter(result => result.status === 'rejected');
  if (failures.length > 0) {
    console.error(`${failures.length} messages failed processing`);
    // In a real implementation, you might implement selective retry
    throw new Error('Some messages failed processing');
  }
};

async function processMessage(record: any, context: Context): Promise<void> {
  try {
    // Parse the SNS message from SQS record
    const snsMessage = JSON.parse(record.body);
    const orderEvent: OrderEvent = JSON.parse(snsMessage.Message);

    // Validate event structure
    validateOrderEvent(orderEvent);

    // Route to appropriate handler
    switch (orderEvent.eventType) {
      case OrderEventType.CREATED:
        await handleCriticalOrderCreated(orderEvent);
        break;
      case OrderEventType.PAYMENT_PROCESSED:
        await handleCriticalPaymentProcessed(orderEvent);
        break;
      default:
        console.warn(`Unhandled event type for critical processing: ${orderEvent.eventType}`);
    }

    console.log(`Successfully processed critical order event: ${orderEvent.orderId}`);

  } catch (error) {
    console.error('Error processing critical order message:', error);
    // Re-throw to trigger SQS retry mechanism
    throw error;
  }
}

async function handleCriticalOrderCreated(event: OrderEvent): Promise<void> {
  // Prioritized processing for high-value orders
  console.log(`Processing critical order creation: ${event.orderId}`);
  
  // Implement expedited inventory reservation
  await reserveInventoryUrgent(event.data.items);
  
  // Send immediate notification to fulfillment team
  await notifyFulfillmentTeam(event);
  
  // Update analytics with high-priority flag
  await recordCriticalOrderMetrics(event);
}

async function handleCriticalPaymentProcessed(event: OrderEvent): Promise<void> {
  console.log(`Processing critical payment: ${event.orderId}`);
  
  // Immediate fraud check for high-value transactions
  await performEnhancedFraudCheck(event);
  
  // Expedite shipping preparation
  await initiatePriorityShipping(event);
}

function validateOrderEvent(event: OrderEvent): void {
  if (!event.eventId || !event.orderId || !event.eventType) {
    throw new Error('Invalid order event: missing required fields');
  }
  
  if (!event.data || !event.metadata) {
    throw new Error('Invalid order event: missing data or metadata');
  }
}

// Placeholder implementations for business logic
async function reserveInventoryUrgent(items: any[]): Promise<void> {
  // Implementation would integrate with inventory system
}

async function notifyFulfillmentTeam(event: OrderEvent): Promise<void> {
  // Implementation would send alerts to fulfillment team
}

async function recordCriticalOrderMetrics(event: OrderEvent): Promise<void> {
  // Implementation would record metrics in CloudWatch
}

async function performEnhancedFraudCheck(event: OrderEvent): Promise<void> {
  // Implementation would perform additional fraud checks
}

async function initiatePriorityShipping(event: OrderEvent): Promise<void> {
  // Implementation would prioritize in shipping queue
}
```

This implementation demonstrates several important patterns:

- **Message validation** ensures data integrity before processing
- **Error isolation** prevents single message failures from affecting batch processing
- **Business logic separation** keeps handlers focused and testable
- **Comprehensive logging** aids in debugging and monitoring

## Production-Ready Patterns

### Idempotency and Deduplication

Implement robust idempotency to handle duplicate messages gracefully:

```typescript
// src/utils/idempotency.ts
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';

export class IdempotencyHandler {
  private dynamodb: DynamoDBClient;
  private tableName: string;

  constructor(tableName: string) {
    this.dynamodb = new DynamoDBClient({});
    this.tableName = tableName;
  }

  async processIdempotently<T>(
    idempotencyKey: string,
    operation: () => Promise<T>,
    ttlSeconds: number = 86400
  ): Promise<T> {
    // Check if already processed
    const existing = await this.getProcessingRecord(idempotencyKey);
    if (existing) {
      console.log(`Skipping duplicate message: ${idempotencyKey}`);
      return existing.result;
    }

    // Process the operation
    const result = await operation();

    // Store the result
    await this.storeProcessingRecord(idempotencyKey, result, ttlSeconds);

    return result;
  }

  private async getProcessingRecord(key: string): Promise<any> {
    try {
      const response = await this.dynamodb.send(new GetItemCommand({
        TableName: this.tableName,
        Key: { id: { S: key } }
      }));

      return response.Item ? JSON.parse(response.Item.result.S!) : null;
    } catch (error) {
      console.error('Error checking idempotency:', error);
      return null;
    }
  }

  private async storeProcessingRecord(key: string, result: any, ttl: number): Promise<void> {
    const expirationTime = Math.floor(Date.now() / 1000) + ttl;

    await this.dynamodb.send(new PutItemCommand({
      TableName: this.tableName,
      Item: {
        id: { S: key },
        result: { S: JSON.stringify(result) },
        ttl: { N: expirationTime.toString() }
      }
    }));
  }
}
```

### Circuit Breaker for External Services

Implement resilience patterns for external service calls:

```typescript
// src/utils/circuitBreaker.ts
export class CircuitBreaker {
  private failures: number = 0;
  private lastFailureTime?: number;
  private state: CircuitState = CircuitState.CLOSED;

  constructor(
    private readonly failureThreshold: number = 5,
    private readonly recoveryTimeout: number = 60000,
    private readonly monitoringWindow: number = 60000
  ) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      if (this.shouldAttemptReset()) {
        this.state = CircuitState.HALF_OPEN;
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failures = 0;
    this.state = CircuitState.CLOSED;
  }

  private onFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.failureThreshold) {
      this.state = CircuitState.OPEN;
    }
  }

  private shouldAttemptReset(): boolean {
    return this.lastFailureTime !== undefined && 
           Date.now() - this.lastFailureTime >= this.recoveryTimeout;
  }
}

enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}
```

### Monitoring and Metrics

Implement comprehensive monitoring for your event-driven system:

```typescript
// src/utils/monitoring.ts
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

export class EventMetrics {
  private cloudwatch: CloudWatchClient;
  private namespace: string;

  constructor(namespace: string = 'EventDriven/Orders') {
    this.cloudwatch = new CloudWatchClient({});
    this.namespace = namespace;
  }

  async recordEventProcessed(eventType: string, success: boolean, duration: number): Promise<void> {
    const metrics = [
      {
        MetricName: 'EventsProcessed',
        Value: 1,
        Unit: 'Count',
        Dimensions: [
          { Name: 'EventType', Value: eventType },
          { Name: 'Status', Value: success ? 'Success' : 'Failure' }
        ]
      },
      {
        MetricName: 'ProcessingDuration',
        Value: duration,
        Unit: 'Milliseconds',
        Dimensions: [
          { Name: 'EventType', Value: eventType }
        ]
      }
    ];

    await this.cloudwatch.send(new PutMetricDataCommand({
      Namespace: this.namespace,
      MetricData: metrics
    }));
  }

  async recordBusinessMetric(metricName: string, value: number, dimensions: Record<string, string> = {}): Promise<void> {
    const metricDimensions = Object.entries(dimensions).map(([name, value]) => ({
      Name: name,
      Value: value
    }));

    await this.cloudwatch.send(new PutMetricDataCommand({
      Namespace: this.namespace,
      MetricData: [{
        MetricName: metricName,
        Value: value,
        Unit: 'None',
        Dimensions: metricDimensions
      }]
    }));
  }
}

// Usage in message handlers
export async function withMetrics<T>(
  operation: () => Promise<T>,
  eventType: string,
  metrics: EventMetrics
): Promise<T> {
  const startTime = Date.now();
  
  try {
    const result = await operation();
    await metrics.recordEventProcessed(eventType, true, Date.now() - startTime);
    return result;
  } catch (error) {
    await metrics.recordEventProcessed(eventType, false, Date.now() - startTime);
    throw error;
  }
}
```

### Message Schema Evolution

Handle evolving message schemas gracefully:

```typescript
// src/utils/schemaEvolution.ts
export interface MessageTransformer<T> {
  version: string;
  transform(message: any): T;
}

export class MessageProcessor<T> {
  private transformers: Map<string, MessageTransformer<T>> = new Map();

  registerTransformer(transformer: MessageTransformer<T>): void {
    this.transformers.set(transformer.version, transformer);
  }

  processMessage(rawMessage: any): T {
    const version = rawMessage.version || '1.0';
    const transformer = this.transformers.get(version);
    
    if (!transformer) {
      throw new Error(`No transformer found for version ${version}`);
    }

    return transformer.transform(rawMessage);
  }
}

// Example transformers
export class OrderEventV1Transformer implements MessageTransformer<OrderEvent> {
  version = '1.0';

  transform(message: any): OrderEvent {
    return {
      eventId: message.id || crypto.randomUUID(),
      eventType: message.type,
      orderId: message.orderId,
      timestamp: message.timestamp,
      version: '1.0',
      source: 'order-service-v1',
      data: {
        customerId: message.customerId,
        items: message.items,
        totalAmount: message.total,
        currency: message.currency || 'USD',
        status: message.status
      },
      metadata: {
        priority: message.priority || 'MEDIUM',
        correlationId: message.correlationId || crypto.randomUUID()
      }
    };
  }
}

export class OrderEventV2Transformer implements MessageTransformer<OrderEvent> {
  version = '2.0';

  transform(message: any): OrderEvent {
    // V2 already matches our current format
    return message as OrderEvent;
  }
}
```

## Testing Event-Driven Systems

Comprehensive testing strategies for event-driven architectures require multiple approaches:

### Unit Testing Event Handlers

```typescript
// src/__tests__/eventHandlers.test.ts
import { OrderEvent, OrderEventType } from '../types/events';
import { handleCriticalOrderCreated } from '../handlers/processCriticalOrder';

describe('Critical Order Handlers', () => {
  test('handles critical order creation with proper validation', async () => {
    const mockEvent: OrderEvent = {
      eventId: 'test-event-001',
      eventType: OrderEventType.CREATED,
      orderId: 'order-123',
      timestamp: new Date().toISOString(),
      version: '2.0',
      source: 'order-service',
      data: {
        customerId: 'customer-456',
        items: [
          { productId: 'product-001', quantity: 2, unitPrice: 50.00, productName: 'Test Product' }
        ],
        totalAmount: 100.00,
        currency: 'USD',
        status: 'PENDING'
      },
      metadata: {
        priority: 'HIGH',
        correlationId: 'correlation-123'
      }
    };

    // Mock external services
    jest.mock('../services/inventoryService');
    jest.mock('../services/notificationService');

    await expect(handleCriticalOrderCreated(mockEvent)).resolves.toBeUndefined();
    
    // Verify that critical path functions were called
    expect(mockInventoryService.reserveInventoryUrgent).toHaveBeenCalledWith(mockEvent.data.items);
    expect(mockNotificationService.notifyFulfillmentTeam).toHaveBeenCalledWith(mockEvent);
  });
});
```

### Integration Testing with LocalStack

```typescript
// src/__tests__/integration/eventFlow.test.ts
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';

describe('Event Flow Integration Tests', () => {
  let sns: SNSClient;
  let sqs: SQSClient;
  
  beforeAll(() => {
    // Configure clients for LocalStack
    sns = new SNSClient({
      endpoint: 'http://localhost:4566',
      region: 'us-east-1'
    });
    
    sqs = new SQSClient({
      endpoint: 'http://localhost:4566',
      region: 'us-east-1'
    });
  });

  test('message flows from SNS to appropriate SQS queue based on priority', async () => {
    const highPriorityEvent = {
      eventType: 'ORDER_CREATED',
      orderId: 'test-order-001',
      // ... other event data
      metadata: { priority: 'HIGH' }
    };

    // Publish to SNS
    await sns.send(new PublishCommand({
      TopicArn: process.env.TEST_TOPIC_ARN,
      Message: JSON.stringify(highPriorityEvent),
      MessageAttributes: {
        priority: { DataType: 'String', StringValue: 'HIGH' }
      }
    }));

    // Verify message appears in critical queue
    const messages = await sqs.send(new ReceiveMessageCommand({
      QueueUrl: process.env.CRITICAL_QUEUE_URL,
      MaxNumberOfMessages: 1,
      WaitTimeSeconds: 5
    }));

    expect(messages.Messages).toHaveLength(1);
    const receivedEvent = JSON.parse(messages.Messages![0].Body!);
    expect(receivedEvent.orderId).toBe('test-order-001');

    // Clean up
    await sqs.send(new DeleteMessageCommand({
      QueueUrl: process.env.CRITICAL_QUEUE_URL,
      ReceiptHandle: messages.Messages![0].ReceiptHandle
    }));
  });
});
```

### Load Testing Event Systems

```typescript
// src/__tests__/load/eventLoad.test.ts
import { EventPublisher } from '../services/eventPublisher';

describe('Event System Load Tests', () => {
  test('handles high-volume message publishing', async () => {
    const publisher = new EventPublisher(process.env.TEST_TOPIC_ARN!);
    const promises: Promise<any>[] = [];
    const messageCount = 1000;

    const startTime = Date.now();

    // Generate concurrent publish operations
    for (let i = 0; i < messageCount; i++) {
      const event = generateTestEvent(i);
      promises.push(publisher.publishEvent(event));
    }

    const results = await Promise.allSettled(promises);
    const duration = Date.now() - startTime;

    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    console.log(`Published ${successful} messages in ${duration}ms`);
    console.log(`Success rate: ${(successful / messageCount) * 100}%`);

    expect(successful).toBeGreaterThan(messageCount * 0.95); // 95% success rate
    expect(duration).toBeLessThan(30000); // Complete within 30 seconds
  });
});
```

## Conclusion

Building event-driven architectures with AWS SNS, SQS, and TypeScript creates systems that are both resilient and maintainable. The combination of strong typing, message durability, and flexible routing patterns enables applications that can scale from simple notifications to complex distributed workflows.

Key benefits of this approach include **decoupled architecture** that enables independent service evolution, **natural scalability** through message buffering and parallel processing, **operational resilience** via dead letter queues and retry mechanisms, and **type safety** that catches integration issues at compile time.

The patterns demonstrated here—from basic pub/sub to sophisticated priority processing—provide a foundation for building production-ready event-driven systems. **Message filtering** enables efficient resource utilization, **idempotency handling** ensures reliable processing, **circuit breakers** provide resilience against downstream failures, and **comprehensive monitoring** offers visibility into system health.

As you advance your event-driven architecture, consider implementing **event sourcing patterns** for audit trails and temporal queries, **saga patterns** for distributed transaction management, **CQRS implementations** for optimized read/write patterns, and **stream processing** for real-time analytics and complex event correlation.

These foundational patterns scale from simple microservice communication to enterprise-wide event mesh architectures, providing the building blocks for systems that can evolve with your business requirements while maintaining reliability and performance.

In our next post, we'll explore building type-safe APIs with AWS API Gateway and TypeScript, showing how to create robust HTTP interfaces that complement our event-driven architecture.
