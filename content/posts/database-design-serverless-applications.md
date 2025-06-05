---
title: "Database Design for Serverless Applications: NoSQL Patterns and Data Modeling"
date: 2021-11-07
description: "Master database design patterns for serverless applications using DynamoDB, event sourcing, and data modeling strategies that scale with your cloud-native architecture."
categories: ["Software Development", "Database", "Serverless"]
tags: ["DynamoDB", "NoSQL", "Serverless", "AWS", "Database Design", "Data Modeling", "TypeScript"]
series: "Modern Development Practices"
---

## Introduction

In our Modern Development Practices series, we've covered test-driven development, code quality gates, API design patterns, and microservices communication. Today, we're diving into database design for serverless applications – a critical aspect that can make or break your application's performance, scalability, and cost-effectiveness.

Serverless applications demand a different approach to data storage. Traditional relational database patterns often don't align with the ephemeral, stateless nature of serverless functions. Instead, we need to embrace NoSQL patterns, denormalization strategies, and event-driven data synchronization.

## Understanding Serverless Database Constraints

### Connection Pooling Challenges

```typescript
// Anti-pattern: Creating new connections in Lambda functions
import { Client } from 'pg';

export const badHandler = async (event: APIGatewayProxyEvent) => {
  // This creates a new connection for every invocation
  const client = new Client({
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  });

  await client.connect();
  
  try {
    const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    return { statusCode: 200, body: JSON.stringify(result.rows) };
  } finally {
    await client.end(); // Connection closed, resources wasted
  }
};

// Better: Using RDS Proxy for connection pooling
export const betterHandler = async (event: APIGatewayProxyEvent) => {
  // RDS Proxy handles connection pooling automatically
  const client = new Client({
    host: process.env.RDS_PROXY_ENDPOINT,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  });

  await client.connect();
  // RDS Proxy reuses connections efficiently
};
```

### DynamoDB: The Serverless-First Choice

DynamoDB eliminates connection management entirely and scales automatically:

```typescript
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';

class UserRepository {
  private docClient: DynamoDBDocumentClient;

  constructor() {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION });
    this.docClient = DynamoDBDocumentClient.from(client);
  }

  async getUser(userId: string): Promise<User | null> {
    const command = new GetCommand({
      TableName: process.env.USERS_TABLE,
      Key: { PK: `USER#${userId}`, SK: `USER#${userId}` }
    });

    const result = await this.docClient.send(command);
    return result.Item ? this.mapToUser(result.Item) : null;
  }

  async createUser(user: User): Promise<void> {
    const command = new PutCommand({
      TableName: process.env.USERS_TABLE,
      Item: {
        PK: `USER#${user.id}`,
        SK: `USER#${user.id}`,
        GSI1PK: `USER#${user.email}`,
        GSI1SK: `USER#${user.email}`,
        ...user,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      },
      ConditionExpression: 'attribute_not_exists(PK)'
    });

    await this.docClient.send(command);
  }

  private mapToUser(item: any): User {
    return {
      id: item.id,
      email: item.email,
      name: item.name,
      createdAt: new Date(item.createdAt),
      updatedAt: new Date(item.updatedAt)
    };
  }
}
```

## Single Table Design Patterns

### Entity Relationship Modeling

```typescript
interface EntitySchema {
  PK: string;      // Partition Key
  SK: string;      // Sort Key
  GSI1PK?: string; // Global Secondary Index 1 Partition Key
  GSI1SK?: string; // Global Secondary Index 1 Sort Key
  GSI2PK?: string; // Global Secondary Index 2 Partition Key
  GSI2SK?: string; // Global Secondary Index 2 Sort Key
  entityType: string;
  [key: string]: any;
}

class SingleTableRepository {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor() {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = process.env.MAIN_TABLE || 'MainTable';
  }

  // User entity: PK = USER#userId, SK = USER#userId
  async createUser(user: CreateUserRequest): Promise<User> {
    const userId = this.generateId();
    const userEntity: EntitySchema = {
      PK: `USER#${userId}`,
      SK: `USER#${userId}`,
      GSI1PK: `USER#${user.email}`, // Query by email
      GSI1SK: `USER#${user.email}`,
      entityType: 'USER',
      id: userId,
      email: user.email,
      name: user.name,
      createdAt: new Date().toISOString()
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: userEntity,
      ConditionExpression: 'attribute_not_exists(PK)'
    }));

    return this.mapToUser(userEntity);
  }

  // Order entity: PK = USER#userId, SK = ORDER#orderId
  async createOrder(order: CreateOrderRequest): Promise<Order> {
    const orderId = this.generateId();
    const orderEntity: EntitySchema = {
      PK: `USER#${order.userId}`,
      SK: `ORDER#${orderId}`,
      GSI1PK: `ORDER#${order.status}`, // Query by status
      GSI1SK: order.createdAt,
      GSI2PK: `ORDER#${orderId}`, // Direct order lookup
      GSI2SK: `ORDER#${orderId}`,
      entityType: 'ORDER',
      id: orderId,
      userId: order.userId,
      items: order.items,
      total: order.total,
      status: order.status,
      createdAt: new Date().toISOString()
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: orderEntity
    }));

    return this.mapToOrder(orderEntity);
  }

  // Get all orders for a user
  async getUserOrders(userId: string): Promise<Order[]> {
    const command = new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `USER#${userId}`,
        ':sk': 'ORDER#'
      }
    });

    const result = await this.docClient.send(command);
    return result.Items?.map(item => this.mapToOrder(item)) || [];
  }

  // Get orders by status using GSI
  async getOrdersByStatus(status: string): Promise<Order[]> {
    const command = new QueryCommand({
      TableName: this.tableName,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `ORDER#${status}`
      }
    });

    const result = await this.docClient.send(command);
    return result.Items?.map(item => this.mapToOrder(item)) || [];
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }

  private mapToUser(item: any): User {
    return {
      id: item.id,
      email: item.email,
      name: item.name,
      createdAt: new Date(item.createdAt)
    };
  }

  private mapToOrder(item: any): Order {
    return {
      id: item.id,
      userId: item.userId,
      items: item.items,
      total: item.total,
      status: item.status,
      createdAt: new Date(item.createdAt)
    };
  }
}
```

### Hierarchical Data Patterns

```typescript
// Forum system with categories, topics, and posts
class ForumRepository extends SingleTableRepository {
  
  // Category: PK = CATEGORY#categoryId, SK = CATEGORY#categoryId
  async createCategory(category: CreateCategoryRequest): Promise<Category> {
    const categoryId = this.generateId();
    const entity: EntitySchema = {
      PK: `CATEGORY#${categoryId}`,
      SK: `CATEGORY#${categoryId}`,
      GSI1PK: 'CATEGORY',
      GSI1SK: category.name,
      entityType: 'CATEGORY',
      id: categoryId,
      name: category.name,
      description: category.description,
      topicCount: 0,
      createdAt: new Date().toISOString()
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: entity
    }));

    return this.mapToCategory(entity);
  }

  // Topic: PK = CATEGORY#categoryId, SK = TOPIC#topicId
  async createTopic(topic: CreateTopicRequest): Promise<Topic> {
    const topicId = this.generateId();
    const entity: EntitySchema = {
      PK: `CATEGORY#${topic.categoryId}`,
      SK: `TOPIC#${topicId}`,
      GSI1PK: `TOPIC#${topic.authorId}`, // Topics by author
      GSI1SK: new Date().toISOString(),
      GSI2PK: `TOPIC#${topicId}`, // Direct topic lookup
      GSI2SK: `TOPIC#${topicId}`,
      entityType: 'TOPIC',
      id: topicId,
      categoryId: topic.categoryId,
      title: topic.title,
      content: topic.content,
      authorId: topic.authorId,
      postCount: 0,
      lastPostAt: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: entity
    }));

    return this.mapToTopic(entity);
  }

  // Post: PK = TOPIC#topicId, SK = POST#timestamp#postId
  async createPost(post: CreatePostRequest): Promise<Post> {
    const postId = this.generateId();
    const timestamp = new Date().toISOString();
    
    const entity: EntitySchema = {
      PK: `TOPIC#${post.topicId}`,
      SK: `POST#${timestamp}#${postId}`,
      GSI1PK: `POST#${post.authorId}`, // Posts by author
      GSI1SK: timestamp,
      entityType: 'POST',
      id: postId,
      topicId: post.topicId,
      content: post.content,
      authorId: post.authorId,
      createdAt: timestamp
    };

    await this.docClient.send(new PutCommand({
      TableName: this.tableName,
      Item: entity
    }));

    return this.mapToPost(entity);
  }

  // Get all topics in a category (with pagination)
  async getCategoryTopics(
    categoryId: string, 
    limit: number = 20, 
    lastEvaluatedKey?: any
  ): Promise<{ topics: Topic[], lastEvaluatedKey?: any }> {
    const command = new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `CATEGORY#${categoryId}`,
        ':sk': 'TOPIC#'
      },
      Limit: limit,
      ExclusiveStartKey: lastEvaluatedKey
    });

    const result = await this.docClient.send(command);
    return {
      topics: result.Items?.map(item => this.mapToTopic(item)) || [],
      lastEvaluatedKey: result.LastEvaluatedKey
    };
  }

  // Get posts in a topic (chronologically ordered)
  async getTopicPosts(
    topicId: string, 
    limit: number = 50, 
    lastEvaluatedKey?: any
  ): Promise<{ posts: Post[], lastEvaluatedKey?: any }> {
    const command = new QueryCommand({
      TableName: this.tableName,
      KeyConditionExpression: 'PK = :pk AND begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `TOPIC#${topicId}`,
        ':sk': 'POST#'
      },
      ScanIndexForward: true, // Ascending order (chronological)
      Limit: limit,
      ExclusiveStartKey: lastEvaluatedKey
    });

    const result = await this.docClient.send(command);
    return {
      posts: result.Items?.map(item => this.mapToPost(item)) || [],
      lastEvaluatedKey: result.LastEvaluatedKey
    };
  }
}
```

## Event Sourcing for Serverless

### Event Store Implementation

```typescript
interface DomainEvent {
  eventId: string;
  aggregateId: string;
  eventType: string;
  eventData: any;
  eventVersion: number;
  timestamp: string;
  metadata?: any;
}

class DynamoDBEventStore {
  private docClient: DynamoDBDocumentClient;
  private eventTable: string;

  constructor() {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.eventTable = process.env.EVENT_STORE_TABLE || 'EventStore';
  }

  async appendEvents(
    aggregateId: string, 
    events: DomainEvent[], 
    expectedVersion: number
  ): Promise<void> {
    // Optimistic concurrency control
    const versionCheckCommand = new GetCommand({
      TableName: this.eventTable,
      Key: {
        PK: `AGGREGATE#${aggregateId}`,
        SK: 'VERSION'
      }
    });

    const versionResult = await this.docClient.send(versionCheckCommand);
    const currentVersion = versionResult.Item?.version || 0;

    if (currentVersion !== expectedVersion) {
      throw new Error(`Concurrency conflict. Expected version ${expectedVersion}, but current version is ${currentVersion}`);
    }

    // Use transaction to ensure atomicity
    const transactItems = events.map(event => ({
      Put: {
        TableName: this.eventTable,
        Item: {
          PK: `AGGREGATE#${aggregateId}`,
          SK: `EVENT#${event.eventVersion.toString().padStart(10, '0')}`,
          GSI1PK: `EVENT#${event.eventType}`,
          GSI1SK: event.timestamp,
          ...event
        }
      }
    }));

    // Update version
    transactItems.push({
      Put: {
        TableName: this.eventTable,
        Item: {
          PK: `AGGREGATE#${aggregateId}`,
          SK: 'VERSION',
          version: expectedVersion + events.length
        }
      }
    });

    await this.docClient.send(new TransactWriteCommand({
      TransactItems: transactItems
    }));
  }

  async getEvents(aggregateId: string, fromVersion?: number): Promise<DomainEvent[]> {
    let keyCondition = 'PK = :pk AND begins_with(SK, :sk)';
    const expressionValues: any = {
      ':pk': `AGGREGATE#${aggregateId}`,
      ':sk': 'EVENT#'
    };

    if (fromVersion !== undefined) {
      keyCondition += ' AND SK >= :fromVersion';
      expressionValues[':fromVersion'] = `EVENT#${fromVersion.toString().padStart(10, '0')}`;
    }

    const command = new QueryCommand({
      TableName: this.eventTable,
      KeyConditionExpression: keyCondition,
      ExpressionAttributeValues: expressionValues,
      ScanIndexForward: true
    });

    const result = await this.docClient.send(command);
    return result.Items?.map(item => this.mapToDomainEvent(item)) || [];
  }

  async getEventsByType(eventType: string, limit?: number): Promise<DomainEvent[]> {
    const command = new QueryCommand({
      TableName: this.eventTable,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk',
      ExpressionAttributeValues: {
        ':pk': `EVENT#${eventType}`
      },
      ScanIndexForward: false, // Most recent first
      Limit: limit
    });

    const result = await this.docClient.send(command);
    return result.Items?.map(item => this.mapToDomainEvent(item)) || [];
  }

  private mapToDomainEvent(item: any): DomainEvent {
    return {
      eventId: item.eventId,
      aggregateId: item.aggregateId,
      eventType: item.eventType,
      eventData: item.eventData,
      eventVersion: item.eventVersion,
      timestamp: item.timestamp,
      metadata: item.metadata
    };
  }
}
```

### Aggregate Root with Event Sourcing

```typescript
abstract class EventSourcedAggregate {
  protected uncommittedEvents: DomainEvent[] = [];
  protected version = 0;

  constructor(protected id: string) {}

  getUncommittedEvents(): DomainEvent[] {
    return [...this.uncommittedEvents];
  }

  markEventsAsCommitted(): void {
    this.uncommittedEvents = [];
  }

  getVersion(): number {
    return this.version;
  }

  loadFromHistory(events: DomainEvent[]): void {
    events.forEach(event => {
      this.applyEvent(event, false);
      this.version = event.eventVersion;
    });
  }

  protected addEvent(eventType: string, eventData: any, metadata?: any): void {
    const event: DomainEvent = {
      eventId: this.generateEventId(),
      aggregateId: this.id,
      eventType,
      eventData,
      eventVersion: this.version + 1,
      timestamp: new Date().toISOString(),
      metadata
    };

    this.applyEvent(event, true);
    this.uncommittedEvents.push(event);
  }

  protected abstract applyEvent(event: DomainEvent, isNew: boolean): void;

  private generateEventId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

class BankAccount extends EventSourcedAggregate {
  private balance = 0;
  private isActive = false;

  static create(accountId: string, initialDeposit: number): BankAccount {
    const account = new BankAccount(accountId);
    account.addEvent('AccountOpened', { initialDeposit });
    return account;
  }

  static fromHistory(accountId: string, events: DomainEvent[]): BankAccount {
    const account = new BankAccount(accountId);
    account.loadFromHistory(events);
    return account;
  }

  deposit(amount: number): void {
    if (!this.isActive) {
      throw new Error('Account is not active');
    }
    if (amount <= 0) {
      throw new Error('Deposit amount must be positive');
    }

    this.addEvent('MoneyDeposited', { amount });
  }

  withdraw(amount: number): void {
    if (!this.isActive) {
      throw new Error('Account is not active');
    }
    if (amount <= 0) {
      throw new Error('Withdrawal amount must be positive');
    }
    if (this.balance < amount) {
      throw new Error('Insufficient funds');
    }

    this.addEvent('MoneyWithdrawn', { amount });
  }

  close(): void {
    if (!this.isActive) {
      throw new Error('Account is already closed');
    }

    this.addEvent('AccountClosed', {});
  }

  getBalance(): number {
    return this.balance;
  }

  isAccountActive(): boolean {
    return this.isActive;
  }

  protected applyEvent(event: DomainEvent, isNew: boolean): void {
    switch (event.eventType) {
      case 'AccountOpened':
        this.balance = event.eventData.initialDeposit;
        this.isActive = true;
        if (isNew) this.version++;
        break;

      case 'MoneyDeposited':
        this.balance += event.eventData.amount;
        if (isNew) this.version++;
        break;

      case 'MoneyWithdrawn':
        this.balance -= event.eventData.amount;
        if (isNew) this.version++;
        break;

      case 'AccountClosed':
        this.isActive = false;
        if (isNew) this.version++;
        break;

      default:
        throw new Error(`Unknown event type: ${event.eventType}`);
    }
  }
}
```

## Data Consistency Patterns

### Eventually Consistent Read Models

```typescript
// Projection handler for maintaining read models
export const projectionHandler = async (event: DynamoDBStreamEvent): Promise<void> => {
  for (const record of event.Records) {
    if (record.eventName === 'INSERT' && record.dynamodb?.NewImage) {
      const eventData = unmarshall(record.dynamodb.NewImage);
      
      if (eventData.eventType === 'AccountOpened') {
        await createAccountSummary(eventData);
      } else if (eventData.eventType === 'MoneyDeposited') {
        await updateAccountBalance(eventData);
      } else if (eventData.eventType === 'MoneyWithdrawn') {
        await updateAccountBalance(eventData);
      }
    }
  }
};

async function createAccountSummary(eventData: any): Promise<void> {
  const command = new PutCommand({
    TableName: process.env.ACCOUNT_SUMMARY_TABLE,
    Item: {
      accountId: eventData.aggregateId,
      balance: eventData.eventData.initialDeposit,
      status: 'ACTIVE',
      createdAt: eventData.timestamp,
      updatedAt: eventData.timestamp
    }
  });

  await docClient.send(command);
}

async function updateAccountBalance(eventData: any): Promise<void> {
  const updateExpression = eventData.eventType === 'MoneyDeposited'
    ? 'ADD balance :amount SET updatedAt = :timestamp'
    : 'ADD balance :negAmount SET updatedAt = :timestamp';

  const amount = eventData.eventData.amount;
  
  const command = new UpdateCommand({
    TableName: process.env.ACCOUNT_SUMMARY_TABLE,
    Key: { accountId: eventData.aggregateId },
    UpdateExpression: updateExpression,
    ExpressionAttributeValues: {
      ':amount': amount,
      ':negAmount': -amount,
      ':timestamp': eventData.timestamp
    }
  });

  await docClient.send(command);
}
```

### Saga Pattern with DynamoDB

```typescript
interface SagaStep {
  stepId: string;
  status: 'PENDING' | 'COMPLETED' | 'FAILED' | 'COMPENSATED';
  stepType: string;
  stepData: any;
  compensationData?: any;
}

class SagaOrchestrator {
  private docClient: DynamoDBDocumentClient;
  private sagaTable: string;

  constructor() {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.sagaTable = process.env.SAGA_TABLE || 'SagaTable';
  }

  async startSaga(sagaId: string, steps: Omit<SagaStep, 'status'>[]): Promise<void> {
    const sagaSteps: SagaStep[] = steps.map(step => ({
      ...step,
      status: 'PENDING'
    }));

    const command = new PutCommand({
      TableName: this.sagaTable,
      Item: {
        PK: `SAGA#${sagaId}`,
        SK: 'METADATA',
        sagaId,
        status: 'STARTED',
        currentStep: 0,
        steps: sagaSteps,
        createdAt: new Date().toISOString()
      },
      ConditionExpression: 'attribute_not_exists(PK)'
    });

    await this.docClient.send(command);
    await this.executeNextStep(sagaId);
  }

  async executeNextStep(sagaId: string): Promise<void> {
    const saga = await this.getSaga(sagaId);
    if (!saga || saga.status === 'COMPLETED' || saga.status === 'FAILED') {
      return;
    }

    const currentStep = saga.steps[saga.currentStep];
    if (!currentStep) {
      // All steps completed
      await this.completeSaga(sagaId);
      return;
    }

    try {
      await this.executeStep(currentStep);
      await this.markStepCompleted(sagaId, saga.currentStep);
      await this.executeNextStep(sagaId); // Execute next step
    } catch (error) {
      await this.markStepFailed(sagaId, saga.currentStep);
      await this.startCompensation(sagaId);
    }
  }

  private async executeStep(step: SagaStep): Promise<void> {
    switch (step.stepType) {
      case 'RESERVE_INVENTORY':
        await this.reserveInventory(step.stepData);
        break;
      case 'PROCESS_PAYMENT':
        await this.processPayment(step.stepData);
        break;
      case 'CREATE_SHIPMENT':
        await this.createShipment(step.stepData);
        break;
      default:
        throw new Error(`Unknown step type: ${step.stepType}`);
    }
  }

  private async startCompensation(sagaId: string): Promise<void> {
    const saga = await this.getSaga(sagaId);
    if (!saga) return;

    // Compensate completed steps in reverse order
    for (let i = saga.currentStep - 1; i >= 0; i--) {
      const step = saga.steps[i];
      if (step.status === 'COMPLETED') {
        try {
          await this.compensateStep(step);
          await this.markStepCompensated(sagaId, i);
        } catch (error) {
          console.error(`Failed to compensate step ${i}:`, error);
          // Log for manual intervention
        }
      }
    }

    await this.failSaga(sagaId);
  }

  private async compensateStep(step: SagaStep): Promise<void> {
    switch (step.stepType) {
      case 'RESERVE_INVENTORY':
        await this.releaseInventory(step.compensationData);
        break;
      case 'PROCESS_PAYMENT':
        await this.refundPayment(step.compensationData);
        break;
      case 'CREATE_SHIPMENT':
        await this.cancelShipment(step.compensationData);
        break;
    }
  }

  private async getSaga(sagaId: string): Promise<any> {
    const command = new GetCommand({
      TableName: this.sagaTable,
      Key: {
        PK: `SAGA#${sagaId}`,
        SK: 'METADATA'
      }
    });

    const result = await this.docClient.send(command);
    return result.Item;
  }
}
```

## Caching Strategies

### DynamoDB Accelerator (DAX)

```typescript
// DAX client for microsecond latency
import { DynamoDB } from '@aws-sdk/client-dynamodb';
import AmazonDaxClient from 'amazon-dax-client';

class CachedUserRepository {
  private daxClient: DynamoDB;
  private docClient: DynamoDBDocumentClient;

  constructor() {
    // DAX cluster for read-heavy workloads
    this.daxClient = new AmazonDaxClient({
      endpoints: [process.env.DAX_ENDPOINT],
      region: process.env.AWS_REGION
    });
    
    this.docClient = DynamoDBDocumentClient.from(this.daxClient);
  }

  async getUser(userId: string): Promise<User | null> {
    // This will hit DAX cache if available, DynamoDB if not
    const command = new GetCommand({
      TableName: process.env.USERS_TABLE,
      Key: { PK: `USER#${userId}`, SK: `USER#${userId}` }
    });

    const result = await this.docClient.send(command);
    return result.Item ? this.mapToUser(result.Item) : null;
  }

  // Writes still go directly to DynamoDB
  async updateUser(userId: string, updates: Partial<User>): Promise<void> {
    const command = new UpdateCommand({
      TableName: process.env.USERS_TABLE,
      Key: { PK: `USER#${userId}`, SK: `USER#${userId}` },
      UpdateExpression: 'SET #name = :name, updatedAt = :updatedAt',
      ExpressionAttributeNames: {
        '#name': 'name'
      },
      ExpressionAttributeValues: {
        ':name': updates.name,
        ':updatedAt': new Date().toISOString()
      }
    });

    await this.docClient.send(command);
  }
}
```

## Testing Database Patterns

### Integration Testing with DynamoDB Local

```typescript
import { GenericContainer } from 'testcontainers';
import { DynamoDBClient, CreateTableCommand } from '@aws-sdk/client-dynamodb';

describe('User Repository Integration Tests', () => {
  let dynamoContainer: any;
  let repository: UserRepository;

  beforeAll(async () => {
    // Start DynamoDB Local container
    dynamoContainer = await new GenericContainer('amazon/dynamodb-local')
      .withExposedPorts(8000)
      .withCommand(['-jar', 'DynamoDBLocal.jar', '-sharedDb', '-inMemory'])
      .start();

    const client = new DynamoDBClient({
      region: 'local',
      endpoint: `http://localhost:${dynamoContainer.getMappedPort(8000)}`,
      credentials: {
        accessKeyId: 'fake',
        secretAccessKey: 'fake'
      }
    });

    // Create test table
    await client.send(new CreateTableCommand({
      TableName: 'TestTable',
      KeySchema: [
        { AttributeName: 'PK', KeyType: 'HASH' },
        { AttributeName: 'SK', KeyType: 'RANGE' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'PK', AttributeType: 'S' },
        { AttributeName: 'SK', AttributeType: 'S' },
        { AttributeName: 'GSI1PK', AttributeType: 'S' },
        { AttributeName: 'GSI1SK', AttributeType: 'S' }
      ],
      GlobalSecondaryIndexes: [{
        IndexName: 'GSI1',
        KeySchema: [
          { AttributeName: 'GSI1PK', KeyType: 'HASH' },
          { AttributeName: 'GSI1SK', KeyType: 'RANGE' }
        ],
        Projection: { ProjectionType: 'ALL' },
        ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
      }],
      ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
    }));

    repository = new UserRepository();
  });

  afterAll(async () => {
    await dynamoContainer.stop();
  });

  it('should create and retrieve user', async () => {
    const user = await repository.createUser({
      email: 'test@example.com',
      name: 'Test User'
    });

    expect(user.id).toBeDefined();
    expect(user.email).toBe('test@example.com');

    const retrievedUser = await repository.getUser(user.id);
    expect(retrievedUser).toEqual(user);
  });

  it('should query user by email', async () => {
    const user = await repository.createUser({
      email: 'unique@example.com',
      name: 'Unique User'
    });

    const foundUser = await repository.getUserByEmail('unique@example.com');
    expect(foundUser).toEqual(user);
  });
});
```

## Performance Optimization

### Batch Operations

```typescript
class BatchUserRepository {
  private docClient: DynamoDBDocumentClient;

  constructor() {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION });
    this.docClient = DynamoDBDocumentClient.from(client);
  }

  async batchGetUsers(userIds: string[]): Promise<User[]> {
    const chunks = this.chunk(userIds, 100); // DynamoDB batch limit
    const users: User[] = [];

    for (const chunk of chunks) {
      const command = new BatchGetCommand({
        RequestItems: {
          [process.env.USERS_TABLE!]: {
            Keys: chunk.map(id => ({
              PK: `USER#${id}`,
              SK: `USER#${id}`
            }))
          }
        }
      });

      const result = await this.docClient.send(command);
      if (result.Responses?.[process.env.USERS_TABLE!]) {
        users.push(...result.Responses[process.env.USERS_TABLE!].map(item => this.mapToUser(item)));
      }
    }

    return users;
  }

  async batchCreateUsers(users: CreateUserRequest[]): Promise<void> {
    const chunks = this.chunk(users, 25); // DynamoDB batch write limit

    for (const chunk of chunks) {
      const command = new BatchWriteCommand({
        RequestItems: {
          [process.env.USERS_TABLE!]: chunk.map(user => ({
            PutRequest: {
              Item: {
                PK: `USER#${this.generateId()}`,
                SK: `USER#${this.generateId()}`,
                GSI1PK: `USER#${user.email}`,
                GSI1SK: `USER#${user.email}`,
                entityType: 'USER',
                ...user,
                createdAt: new Date().toISOString()
              }
            }
          }))
        }
      });

      await this.docClient.send(command);
    }
  }

  private chunk<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
}
```

## Conclusion

Database design for serverless applications requires a fundamental shift from traditional relational patterns to NoSQL, event-driven approaches. Key principles include:

- **Embrace denormalization** for query optimization
- **Use single-table design** to minimize cross-table operations
- **Implement event sourcing** for audit trails and temporal queries
- **Design for eventual consistency** rather than strong consistency
- **Leverage managed services** like DynamoDB and DAX for scalability
- **Plan access patterns first** before designing your schema

The patterns we've explored – from single-table design to event sourcing and saga orchestration – provide the foundation for building scalable, cost-effective serverless data layers.

In our next post, "Performance Testing Strategies for Cloud Applications," we'll explore how to validate that these database patterns perform under load in production environments.

## Further Reading

- [DynamoDB Best Practices](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/best-practices.html)
- [Event Sourcing Pattern by Martin Fowler](https://martinfowler.com/eaaDev/EventSourcing.html)
- [The DynamoDB Book by Alex DeBrie](https://www.dynamodbbook.com/)
