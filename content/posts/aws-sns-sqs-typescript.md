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

Event-driven architectures are fundamental to building scalable, loosely coupled systems in the cloud. In this post, we'll explore how to use AWS SNS (Simple Notification Service) and SQS (Simple Queue Service) with TypeScript to create robust event-driven applications.

## Why Event-Driven Architecture?

Event-driven architectures bring numerous advantages to modern cloud applications. At their core, they enable loose coupling between services, allowing components to evolve independently without affecting the entire system. This architectural approach naturally leads to improved scalability and resilience, as services can scale independently based on their specific load patterns. When traffic spikes occur, the system can better handle the increased load by buffering messages and processing them at an appropriate pace. The architecture also simplifies error handling and retry logic through built-in messaging capabilities, while the overall system becomes more maintainable due to clear boundaries between components.

## Prerequisites

Before diving into implementation, you'll need to set up your development environment. Start by installing AWS SDK v3, specifically the `@aws-sdk/client-sns` and `@aws-sdk/client-sqs` packages for interacting with AWS messaging services. You should also have a TypeScript development environment configured and the AWS CLI installed and configured with your credentials. Additionally, familiarity with AWS Lambda is important—if you need a refresher, check out our previous posts on AWS Lambda and Step Functions for foundational knowledge.

## Setting Up SNS and SQS

Let's start with the infrastructure setup using AWS SAM:

```yaml
# template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31

Resources:
  # SNS Topic for order events
  OrderEventsTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: OrderEventsTopic

  # SQS Queue for order processing
  OrderProcessingQueue:
    Type: AWS::SQS::Queue
    Properties:
      VisibilityTimeout: 300
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt OrdersDLQ.Arn
        maxReceiveCount: 3

  # Dead Letter Queue
  OrdersDLQ:
    Type: AWS::SQS::Queue
    Properties:
      MessageRetentionPeriod: 1209600 # 14 days

  # Subscribe queue to topic
  OrderQueueSubscription:
    Type: AWS::SNS::Subscription
    Properties:
      TopicArn: !Ref OrderEventsTopic
      Protocol: sqs
      Endpoint: !GetAtt OrderProcessingQueue.Arn

  # Lambda function to process orders
  OrderProcessorFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: src/functions/processOrder.handler
      Runtime: nodejs18.x
      Events:
        SQSEvent:
          Type: SQS
          Properties:
            Queue: !GetAtt OrderProcessingQueue.Arn
            BatchSize: 10
```

## TypeScript Implementation

### 1. Shared Types

First, let's define our type definitions:

```typescript
// src/types/events.ts
export interface OrderEvent {
  eventType: OrderEventType;
  orderId: string;
  timestamp: string;
  data: OrderData;
}

export enum OrderEventType {
  CREATED = 'ORDER_CREATED',
  UPDATED = 'ORDER_UPDATED',
  CANCELLED = 'ORDER_CANCELLED'
}

export interface OrderData {
  customerId: string;
  items: OrderItem[];
  totalAmount: number;
  status: OrderStatus;
}

export interface OrderItem {
  productId: string;
  quantity: number;
  price: number;
}

export enum OrderStatus {
  PENDING = 'PENDING',
  PROCESSING = 'PROCESSING',
  COMPLETED = 'COMPLETED',
  CANCELLED = 'CANCELLED'
}

export enum MessagePriority {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW'
}

export interface PrioritizedEvent extends OrderEvent {
  priority: MessagePriority;
}
```

### 2. Publishing Events to SNS

Let's create a service to publish events:

```typescript
// src/services/eventPublisher.ts
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";
import { OrderEvent } from "../types/events";

export class EventPublisher {
  private sns: SNSClient;
  private topicArn: string;

  constructor(topicArn: string) {
    this.sns = new SNSClient({});
    this.topicArn = topicArn;
  }

  async publishEvent(event: OrderEvent): Promise<string> {
    const command = new PublishCommand({
      TopicArn: this.topicArn,
      Message: JSON.stringify(event),
      MessageAttributes: {
        eventType: {
          DataType: 'String',
          StringValue: event.eventType
        }
      }
    });

    try {
      const response = await this.sns.send(command);
      console.log(`Event published successfully: ${response.MessageId}`);
      return response.MessageId!;
    } catch (error) {
      console.error('Failed to publish event:', error);
      throw error;
    }
  }
}
```

### 3. Processing Messages from SQS

Now, let's implement our Lambda function to process messages:

```typescript
// src/functions/processOrder.ts
import { SQSEvent, Context } from 'aws-lambda';
import { OrderEvent, OrderEventType } from '../types/events';

export const handler = async (event: SQSEvent, context: Context): Promise<void> => {
  for (const record of event.Records) {
    try {
      const orderEvent: OrderEvent = JSON.parse(record.body);
      console.log(`Processing order event: ${orderEvent.orderId}`);

      switch (orderEvent.eventType) {
        case OrderEventType.CREATED:
          await handleOrderCreated(orderEvent);
          break;
        case OrderEventType.UPDATED:
          await handleOrderUpdated(orderEvent);
          break;
        case OrderEventType.CANCELLED:
          await handleOrderCancelled(orderEvent);
          break;
        default:
          console.warn(`Unknown event type: ${orderEvent.eventType}`);
      }
    } catch (error) {
      console.error('Error processing message:', error);
      // Let the message go to DLQ after max retries
      throw error;
    }
  }
};

async function handleOrderCreated(event: OrderEvent): Promise<void> {
  // Implementation for handling new orders
  console.log(`Processing new order: ${event.orderId}`);
}

async function handleOrderUpdated(event: OrderEvent): Promise<void> {
  // Implementation for handling order updates
  console.log(`Processing order update: ${event.orderId}`);
}

async function handleOrderCancelled(event: OrderEvent): Promise<void> {
  // Implementation for handling cancelled orders
  console.log(`Processing order cancellation: ${event.orderId}`);
}
```

## Best Practices

### 1. Message Durability

Always use Dead Letter Queues (DLQ) to handle failed message processing:

```typescript
// Example of checking message attributes
const messageAge = Date.now() - new Date(orderEvent.timestamp).getTime();
if (messageAge > 24 * 60 * 60 * 1000) { // 24 hours
  console.warn(`Message too old, skipping: ${orderEvent.orderId}`);
  return; // Skip processing without error
}
```

### 2. Message Filtering

Use SNS message filtering to reduce unnecessary processing:

```yaml
# Add to template.yaml subscription
FilterPolicy:
  eventType:
    - ORDER_CREATED
    - ORDER_UPDATED
```

### 3. Batch Processing

Optimize Lambda costs by processing messages in batches:

```typescript
// Example batch processing with error handling
export const handler = async (event: SQSEvent): Promise<void> => {
  const successfulMessages: string[] = [];
  const failedMessages: string[] = [];

  for (const record of event.Records) {
    try {
      await processMessage(record);
      successfulMessages.push(record.messageId);
    } catch (error) {
      console.error(`Failed to process message ${record.messageId}:`, error);
      failedMessages.push(record.messageId);
    }
  }

  // Log batch processing results
  console.log(`Successfully processed: ${successfulMessages.length}`);
  console.log(`Failed to process: ${failedMessages.length}`);

  if (failedMessages.length > 0) {
    throw new Error('Some messages failed processing');
  }
};
```

### 4. Monitoring and Observability

Implement comprehensive monitoring:

```typescript
// Example monitoring wrapper
async function withMonitoring<T>(
  operation: () => Promise<T>,
  metricName: string
): Promise<T> {
  const startTime = Date.now();
  try {
    const result = await operation();
    await recordMetric(metricName, 'Success', Date.now() - startTime);
    return result;
  } catch (error) {
    await recordMetric(metricName, 'Failure', Date.now() - startTime);
    throw error;
  }
}

// Usage in handler
await withMonitoring(
  () => processMessage(record),
  'MessageProcessing'
);
```

## Error Handling Patterns

### 1. Message Validation

Always validate messages before processing:

```typescript
function validateOrderEvent(event: unknown): OrderEvent {
  if (!event || typeof event !== 'object') {
    throw new Error('Invalid event format');
  }

  // Add more validation logic here
  return event as OrderEvent;
}
```

### 2. Idempotency

Implement idempotency to handle duplicate messages:

```typescript
async function processMessageIdempotently(event: OrderEvent): Promise<void> {
  const idempotencyKey = `${event.eventType}-${event.orderId}-${event.timestamp}`;
  
  // Check if we've processed this message before
  if (await hasBeenProcessed(idempotencyKey)) {
    console.log(`Skipping duplicate message: ${idempotencyKey}`);
    return;
  }

  // Process the message
  await processMessage(event);

  // Mark as processed
  await markAsProcessed(idempotencyKey);
}
```

## Advanced Patterns and Real-World Considerations

### 1. Message Batching and Chunking

When dealing with large datasets, it's important to implement proper batching:

```typescript
// src/utils/batchProcessor.ts
export class BatchProcessor<T> {
  private readonly batchSize: number;
  private batch: T[] = [];

  constructor(batchSize: number = 10) {
    this.batchSize = batchSize;
  }

  async addItem(item: T, processor: (items: T[]) => Promise<void>): Promise<void> {
    this.batch.push(item);
    if (this.batch.length >= this.batchSize) {
      await this.processBatch(processor);
    }
  }

  private async processBatch(processor: (items: T[]) => Promise<void>): Promise<void> {
    const itemsToProcess = [...this.batch];
    this.batch = [];
    await processor(itemsToProcess);
  }

  async flush(processor: (items: T[]) => Promise<void>): Promise<void> {
    if (this.batch.length > 0) {
      await this.processBatch(processor);
    }
  }
}
```

### 2. Circuit Breaker Pattern

Implement circuit breakers to handle downstream service failures:

```typescript
// src/utils/circuitBreaker.ts
export class CircuitBreaker {
  private failures: number = 0;
  private lastFailure?: Date;
  private readonly threshold: number;
  private readonly resetTimeout: number;

  constructor(threshold: number = 5, resetTimeout: number = 60000) {
    this.threshold = threshold;
    this.resetTimeout = resetTimeout;
  }

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.isOpen()) {
      throw new Error('Circuit is open - too many failures');
    }

    try {
      const result = await operation();
      this.reset();
      return result;
    } catch (error) {
      this.recordFailure();
      throw error;
    }
  }

  private isOpen(): boolean {
    if (!this.lastFailure) return false;
    
    const timeSinceLastFailure = Date.now() - this.lastFailure.getTime();
    return this.failures >= this.threshold && timeSinceLastFailure < this.resetTimeout;
  }

  private recordFailure(): void {
    this.failures++;
    this.lastFailure = new Date();
  }

  private reset(): void {
    this.failures = 0;
    this.lastFailure = undefined;
  }
}
```

### 3. Message Priority Handling

Implement priority queues for critical messages:

```typescript
// src/types/events.ts
export enum MessagePriority {
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW'
}

export interface PrioritizedEvent extends OrderEvent {
  priority: MessagePriority;
}
```

### 4. Performance Optimization with Caching

Add caching to improve performance:

```typescript
// src/utils/cache.ts
export class MessageCache<T> {
  private cache: Map<string, T>;
  private readonly maxSize: number;

  constructor(maxSize: number = 1000) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }

  set(key: string, value: T): void {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  get(key: string): T | undefined {
    return this.cache.get(key);
  }

  clear(): void {
    this.cache.clear();
  }
}
```

### 5. Message Versioning and Schema Evolution

Handle message schema changes gracefully:

```typescript
// src/utils/messageTransformer.ts
export class MessageTransformer {
  private readonly transformers: Map<string, (data: any) => OrderEvent>;

  constructor() {
    this.transformers = new Map();
    this.registerTransformers();
  }

  private registerTransformers() {
    this.transformers.set('1.0', this.transformV1);
    this.transformers.set('2.0', this.transformV2);
  }

  transform(message: any, version: string): OrderEvent {
    const transformer = this.transformers.get(version);
    if (!transformer) {
      throw new Error(`No transformer found for version ${version}`);
    }
    return transformer(message);
  }

  private transformV1(data: any): OrderEvent {
    // Transform v1 message format
    return {
      eventType: data.type,
      orderId: data.id,
      timestamp: data.time,
      data: {
        customerId: data.customer,
        items: data.items,
        totalAmount: data.total,
        status: data.status
      }
    };
  }

  private transformV2(data: any): OrderEvent {
    // Transform v2 message format
    return {
      eventType: data.eventType,
      orderId: data.orderId,
      timestamp: data.timestamp,
      data: data.orderData
    };
  }
}
```

## Testing

Here's how to test your event-driven components:

```typescript
// src/__tests__/eventPublisher.test.ts
import { EventPublisher } from '../services/eventPublisher';
import { mockClient } from 'aws-sdk-client-mock';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

describe('EventPublisher', () => {
  const snsMock = mockClient(SNSClient);

  beforeEach(() => {
    snsMock.reset();
  });

  it('should publish event successfully', async () => {
    const messageId = '123456';
    snsMock.on(PublishCommand).resolves({ MessageId: messageId });

    const publisher = new EventPublisher('topic-arn');
    const event = {
      eventType: 'ORDER_CREATED',
      orderId: '123',
      timestamp: new Date().toISOString(),
      data: {
        // ... event data
      }
    };

    const result = await publisher.publishEvent(event);
    expect(result).toBe(messageId);
  });
});
```

## Conclusion

Event-driven architectures using SNS and SQS provide a robust foundation for building scalable applications. When combined with TypeScript's type safety and AWS Lambda's serverless compute, you can create maintainable and reliable systems that handle complex workflows efficiently.

As you build event-driven systems, remember to leverage SNS for pub/sub messaging and fan-out patterns while using SQS for reliable message processing and traffic spike handling. Proper error handling and monitoring are crucial for system reliability, and TypeScript's type safety features help catch potential issues early in development. Following best practices for message processing and implementing idempotency will ensure your system remains robust and maintainable.

Looking ahead, consider enhancing your implementation by exploring SNS message filtering to optimize message routing and processing efficiency. Implementing dead letter queues will improve your system's resilience by properly handling failed messages. Adding distributed tracing with AWS X-Ray will give you better visibility into your distributed system, and considering event sourcing patterns could provide additional benefits for certain use cases. These advanced techniques will help you build even more sophisticated and reliable event-driven architectures.
