---
title: "Microservices Communication Patterns: Building Resilient Distributed Systems"
date: 2021-10-17
description: "Explore essential communication patterns for microservices architectures, including synchronous and asynchronous patterns, event-driven design, and resilience strategies in TypeScript and AWS."
categories: ["Software Development", "Architecture", "Microservices"]
tags: ["Microservices", "TypeScript", "AWS", "Event-Driven Architecture", "Communication Patterns", "Distributed Systems"]
series: "Modern Development Practices"
---

## Introduction

In our Modern Development Practices series, we've explored test-driven development, code quality gates, and API design patterns. Today, we're diving into microservices communication patterns – the backbone of any successful distributed system. Effective communication between services determines the resilience, scalability, and maintainability of your entire architecture.

## Synchronous Communication Patterns

### HTTP/REST with Circuit Breaker Pattern

The most common synchronous pattern uses HTTP/REST calls with resilience mechanisms:

```typescript
interface CircuitBreakerConfig {
  failureThreshold: number;
  resetTimeout: number;
  monitoringPeriod: number;
}

class CircuitBreaker {
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private failureCount = 0;
  private lastFailureTime?: Date;

  constructor(private config: CircuitBreakerConfig) {}

  async execute<T>(operation: () => Promise<T>): Promise<T> {
    if (this.state === 'OPEN') {
      if (this.shouldAttemptReset()) {
        this.state = 'HALF_OPEN';
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
    this.failureCount = 0;
    this.state = 'CLOSED';
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = new Date();
    
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = 'OPEN';
    }
  }

  private shouldAttemptReset(): boolean {
    const now = new Date();
    const timeSinceLastFailure = now.getTime() - (this.lastFailureTime?.getTime() || 0);
    return timeSinceLastFailure >= this.config.resetTimeout;
  }
}

// Usage in a service client
class UserServiceClient {
  private circuitBreaker: CircuitBreaker;

  constructor() {
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      resetTimeout: 60000, // 1 minute
      monitoringPeriod: 10000 // 10 seconds
    });
  }

  async getUser(userId: string): Promise<User> {
    return this.circuitBreaker.execute(async () => {
      const response = await fetch(`${this.baseUrl}/users/${userId}`, {
        timeout: 5000,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.authToken}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch user: ${response.statusText}`);
      }

      return response.json();
    });
  }
}
```

### Request-Response with Retry and Timeout

Implement robust retry mechanisms with exponential backoff:

```typescript
interface RetryConfig {
  maxAttempts: number;
  baseDelay: number;
  maxDelay: number;
  backoffMultiplier: number;
}

class RetryableHttpClient {
  constructor(private retryConfig: RetryConfig) {}

  async request<T>(
    url: string, 
    options: RequestInit & { timeout?: number } = {}
  ): Promise<T> {
    const { timeout = 10000, ...fetchOptions } = options;
    
    for (let attempt = 1; attempt <= this.retryConfig.maxAttempts; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        const response = await fetch(url, {
          ...fetchOptions,
          signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.ok) {
          return await response.json();
        }

        // Don't retry on client errors (4xx)
        if (response.status >= 400 && response.status < 500) {
          throw new Error(`Client error: ${response.statusText}`);
        }

        throw new Error(`Server error: ${response.statusText}`);
      } catch (error) {
        if (attempt === this.retryConfig.maxAttempts) {
          throw error;
        }

        const delay = Math.min(
          this.retryConfig.baseDelay * Math.pow(this.retryConfig.backoffMultiplier, attempt - 1),
          this.retryConfig.maxDelay
        );

        await this.sleep(delay);
      }
    }

    throw new Error('Max retry attempts exceeded');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

## Asynchronous Communication Patterns

### Event-Driven Architecture with AWS SNS/SQS

Implement robust event-driven communication using AWS services:

```typescript
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';

interface DomainEvent {
  eventType: string;
  aggregateId: string;
  version: number;
  timestamp: Date;
  data: Record<string, any>;
  metadata?: Record<string, any>;
}

class EventPublisher {
  private snsClient: SNSClient;

  constructor() {
    this.snsClient = new SNSClient({ region: process.env.AWS_REGION });
  }

  async publishEvent(event: DomainEvent, topicArn: string): Promise<void> {
    const message = {
      ...event,
      timestamp: event.timestamp.toISOString()
    };

    const command = new PublishCommand({
      TopicArn: topicArn,
      Message: JSON.stringify(message),
      MessageAttributes: {
        eventType: {
          DataType: 'String',
          StringValue: event.eventType
        },
        aggregateId: {
          DataType: 'String',
          StringValue: event.aggregateId
        }
      }
    });

    await this.snsClient.send(command);
  }
}

class EventHandler {
  private sqsClient: SQSClient;

  constructor() {
    this.sqsClient = new SQSClient({ region: process.env.AWS_REGION });
  }

  async processMessages(queueUrl: string, handler: (event: DomainEvent) => Promise<void>): Promise<void> {
    while (true) {
      try {
        const command = new ReceiveMessageCommand({
          QueueUrl: queueUrl,
          MaxNumberOfMessages: 10,
          WaitTimeSeconds: 20, // Long polling
          VisibilityTimeoutSeconds: 60
        });

        const response = await this.sqsClient.send(command);

        if (!response.Messages || response.Messages.length === 0) {
          continue;
        }

        for (const message of response.Messages) {
          try {
            const snsMessage = JSON.parse(message.Body || '{}');
            const event: DomainEvent = JSON.parse(snsMessage.Message);
            
            await handler(event);

            // Delete message only after successful processing
            await this.sqsClient.send(new DeleteMessageCommand({
              QueueUrl: queueUrl,
              ReceiptHandle: message.ReceiptHandle
            }));
          } catch (error) {
            console.error('Failed to process message:', error);
            // Message will become visible again after visibility timeout
          }
        }
      } catch (error) {
        console.error('Error receiving messages:', error);
        await this.sleep(5000); // Wait before retrying
      }
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
```

### Saga Pattern for Distributed Transactions

Implement the Saga pattern for managing distributed transactions:

```typescript
interface SagaStep {
  execute(): Promise<any>;
  compensate(): Promise<void>;
}

class OrderSaga {
  private steps: SagaStep[] = [];
  private completedSteps: SagaStep[] = [];

  constructor(
    private orderService: OrderService,
    private paymentService: PaymentService,
    private inventoryService: InventoryService,
    private shippingService: ShippingService
  ) {}

  async execute(orderData: CreateOrderRequest): Promise<void> {
    this.steps = [
      new CreateOrderStep(this.orderService, orderData),
      new ReserveInventoryStep(this.inventoryService, orderData.items),
      new ProcessPaymentStep(this.paymentService, orderData.payment),
      new CreateShipmentStep(this.shippingService, orderData)
    ];

    try {
      for (const step of this.steps) {
        await step.execute();
        this.completedSteps.push(step);
      }
    } catch (error) {
      await this.compensate();
      throw error;
    }
  }

  private async compensate(): Promise<void> {
    // Execute compensation in reverse order
    for (let i = this.completedSteps.length - 1; i >= 0; i--) {
      try {
        await this.completedSteps[i].compensate();
      } catch (compensationError) {
        console.error('Compensation failed:', compensationError);
        // Log for manual intervention
      }
    }
  }
}

class CreateOrderStep implements SagaStep {
  private orderId?: string;

  constructor(
    private orderService: OrderService,
    private orderData: CreateOrderRequest
  ) {}

  async execute(): Promise<string> {
    this.orderId = await this.orderService.createOrder(this.orderData);
    return this.orderId;
  }

  async compensate(): Promise<void> {
    if (this.orderId) {
      await this.orderService.cancelOrder(this.orderId);
    }
  }
}

class ReserveInventoryStep implements SagaStep {
  private reservationId?: string;

  constructor(
    private inventoryService: InventoryService,
    private items: OrderItem[]
  ) {}

  async execute(): Promise<string> {
    this.reservationId = await this.inventoryService.reserveItems(this.items);
    return this.reservationId;
  }

  async compensate(): Promise<void> {
    if (this.reservationId) {
      await this.inventoryService.releaseReservation(this.reservationId);
    }
  }
}
```

## Event Sourcing with CQRS

Implement event sourcing for audit trails and eventual consistency:

```typescript
interface Event {
  id: string;
  aggregateId: string;
  eventType: string;
  data: any;
  version: number;
  timestamp: Date;
}

class EventStore {
  private events: Map<string, Event[]> = new Map();

  async appendEvents(aggregateId: string, events: Event[], expectedVersion: number): Promise<void> {
    const existingEvents = this.events.get(aggregateId) || [];
    
    if (existingEvents.length !== expectedVersion) {
      throw new Error('Concurrency conflict');
    }

    this.events.set(aggregateId, [...existingEvents, ...events]);
  }

  async getEvents(aggregateId: string, fromVersion?: number): Promise<Event[]> {
    const events = this.events.get(aggregateId) || [];
    return fromVersion ? events.filter(e => e.version > fromVersion) : events;
  }
}

abstract class AggregateRoot {
  protected uncommittedEvents: Event[] = [];
  protected version = 0;

  constructor(protected id: string) {}

  getUncommittedEvents(): Event[] {
    return this.uncommittedEvents;
  }

  markEventsAsCommitted(): void {
    this.uncommittedEvents = [];
  }

  loadFromHistory(events: Event[]): void {
    events.forEach(event => {
      this.applyEvent(event);
      this.version = event.version;
    });
  }

  protected addEvent(eventType: string, data: any): void {
    const event: Event = {
      id: this.generateId(),
      aggregateId: this.id,
      eventType,
      data,
      version: this.version + 1,
      timestamp: new Date()
    };

    this.uncommittedEvents.push(event);
    this.applyEvent(event);
    this.version = event.version;
  }

  protected abstract applyEvent(event: Event): void;
  
  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }
}

class Order extends AggregateRoot {
  private status: 'PENDING' | 'CONFIRMED' | 'SHIPPED' | 'CANCELLED' = 'PENDING';
  private items: OrderItem[] = [];

  static create(id: string, items: OrderItem[]): Order {
    const order = new Order(id);
    order.addEvent('OrderCreated', { items });
    return order;
  }

  confirm(): void {
    if (this.status !== 'PENDING') {
      throw new Error('Order cannot be confirmed');
    }
    this.addEvent('OrderConfirmed', {});
  }

  protected applyEvent(event: Event): void {
    switch (event.eventType) {
      case 'OrderCreated':
        this.items = event.data.items;
        this.status = 'PENDING';
        break;
      case 'OrderConfirmed':
        this.status = 'CONFIRMED';
        break;
      // ... other events
    }
  }
}
```

## Service Mesh and API Gateway Patterns

### API Gateway with Rate Limiting

```typescript
interface RateLimitConfig {
  windowSize: number; // in seconds
  maxRequests: number;
}

class RateLimiter {
  private requests: Map<string, number[]> = new Map();

  constructor(private config: RateLimitConfig) {}

  isAllowed(clientId: string): boolean {
    const now = Date.now();
    const windowStart = now - (this.config.windowSize * 1000);
    
    const clientRequests = this.requests.get(clientId) || [];
    const validRequests = clientRequests.filter(timestamp => timestamp > windowStart);
    
    if (validRequests.length >= this.config.maxRequests) {
      return false;
    }

    validRequests.push(now);
    this.requests.set(clientId, validRequests);
    return true;
  }
}

// AWS Lambda API Gateway integration
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  const rateLimiter = new RateLimiter({
    windowSize: 60, // 1 minute
    maxRequests: 100
  });

  const clientId = event.requestContext.identity.sourceIp;

  if (!rateLimiter.isAllowed(clientId)) {
    return {
      statusCode: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': '60'
      },
      body: JSON.stringify({ error: 'Rate limit exceeded' })
    };
  }

  // Process request...
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ message: 'Success' })
  };
};
```

## Monitoring and Observability

### Distributed Tracing

```typescript
import { trace, SpanStatusCode, SpanKind } from '@opentelemetry/api';

class TracedHttpClient {
  private tracer = trace.getTracer('http-client');

  async request<T>(url: string, options: RequestInit = {}): Promise<T> {
    const span = this.tracer.startSpan('http.request', {
      kind: SpanKind.CLIENT,
      attributes: {
        'http.method': options.method || 'GET',
        'http.url': url,
        'http.user_agent': 'microservice-client'
      }
    });

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...options.headers,
          'traceparent': this.getTraceParent(span)
        }
      });

      span.setAttributes({
        'http.status_code': response.status,
        'http.response.size': response.headers.get('content-length') || 0
      });

      if (!response.ok) {
        span.setStatus({
          code: SpanStatusCode.ERROR,
          message: `HTTP ${response.status}: ${response.statusText}`
        });
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      span.setStatus({ code: SpanStatusCode.OK });
      return data;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    } finally {
      span.end();
    }
  }

  private getTraceParent(span: any): string {
    // Implementation would extract trace context for propagation
    return 'trace-context-header';
  }
}
```

## Testing Communication Patterns

### Contract Testing with Pact

```typescript
import { Pact } from '@pact-foundation/pact';
import { UserServiceClient } from './user-service-client';

describe('User Service Contract', () => {
  const provider = new Pact({
    consumer: 'order-service',
    provider: 'user-service',
    port: 1234,
    log: path.resolve(process.cwd(), 'logs', 'pact.log'),
    dir: path.resolve(process.cwd(), 'pacts'),
    logLevel: 'INFO'
  });

  beforeAll(() => provider.setup());
  afterAll(() => provider.finalize());
  afterEach(() => provider.verify());

  it('should get user by id', async () => {
    await provider.addInteraction({
      state: 'user exists',
      uponReceiving: 'a request for user with id 123',
      withRequest: {
        method: 'GET',
        path: '/users/123',
        headers: {
          'Accept': 'application/json'
        }
      },
      willRespondWith: {
        status: 200,
        headers: {
          'Content-Type': 'application/json'
        },
        body: {
          id: '123',
          name: 'John Doe',
          email: 'john@example.com'
        }
      }
    });

    const client = new UserServiceClient('http://localhost:1234');
    const user = await client.getUser('123');

    expect(user.id).toBe('123');
    expect(user.name).toBe('John Doe');
  });
});
```

## Best Practices and Anti-Patterns

### Service Boundaries and Data Consistency

```typescript
// Good: Services own their data
class OrderService {
  async createOrder(customerId: string, items: OrderItem[]): Promise<Order> {
    // Don't call customer service to validate - use eventual consistency
    const order = new Order(customerId, items);
    
    // Publish event for other services to react
    await this.eventPublisher.publishEvent({
      eventType: 'OrderCreated',
      aggregateId: order.id,
      data: { customerId, items },
      version: 1,
      timestamp: new Date()
    });

    return order;
  }
}

// Bad: Distributed transactions across services
class BadOrderService {
  async createOrder(customerId: string, items: OrderItem[]): Promise<Order> {
    // Anti-pattern: Synchronous calls to multiple services
    await this.customerService.validateCustomer(customerId);
    await this.inventoryService.reserveItems(items);
    await this.paymentService.authorizePayment(customerId, total);
    
    // If any of these fail, the entire transaction fails
    return this.orderRepository.save(new Order(customerId, items));
  }
}
```

## Conclusion

Effective microservices communication requires careful consideration of patterns, resilience, and consistency models. The patterns we've explored – from circuit breakers and saga patterns to event sourcing and service mesh – provide the foundation for building robust distributed systems.

Key takeaways:
- Use synchronous communication sparingly and always with resilience patterns
- Embrace asynchronous, event-driven communication for loose coupling
- Implement proper monitoring and distributed tracing
- Design for failure and eventual consistency
- Test communication patterns with contract testing

In our next post, "Database Design for Serverless Applications," we'll explore how data architecture patterns align with these communication strategies in cloud-native environments.

## Further Reading

- [Microservices Patterns by Chris Richardson](https://microservices.io/patterns/)
- [Building Event-Driven Microservices by Adam Bellemare](https://www.oreilly.com/library/view/building-event-driven-microservices/9781492057888/)
- [AWS Well-Architected Framework - Reliability Pillar](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html)
