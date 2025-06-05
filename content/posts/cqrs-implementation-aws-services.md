---
title: "CQRS Implementation with AWS Services"
date: 2021-01-17T09:00:00-05:00
categories: ["Cloud Computing", "Architecture and Design"]
tags: ["AWS", "CQRS", "DynamoDB", "Lambda", "EventBridge", "Architecture"]
series: "Cloud Architecture Patterns"
---

Command Query Responsibility Segregation represents a fundamental shift in how we think about data persistence and retrieval in distributed systems. Rather than treating reads and writes as symmetric operations against a single data model, CQRS acknowledges the inherent differences between these operations and optimizes each path independently. In the context of AWS services, this pattern becomes particularly powerful when we leverage the managed services ecosystem to handle the complexity of maintaining separate command and query models.

The traditional approach of using a single database for both commands and queries often leads to compromises that satisfy neither use case optimally. Write operations typically require strong consistency, transactional guarantees, and normalized data structures that maintain referential integrity. Read operations, conversely, benefit from denormalized views, eventual consistency models, and optimized indexes that support complex query patterns. These conflicting requirements become more pronounced as systems scale, leading to performance bottlenecks and architectural complexity.

AWS DynamoDB serves as an excellent foundation for implementing the command side of CQRS architectures. Its single-table design philosophy aligns naturally with aggregate-oriented command models, where each business entity maintains its own consistency boundary. When designing command handlers, we focus on capturing the intent of business operations rather than optimizing for query flexibility. A customer registration command might store minimal data required for the business logic, using DynamoDB's conditional writes to ensure data integrity without the overhead of complex relational constraints.

```typescript
// CQRS Implementation with AWS Services
import { DynamoDBClient, PutItemCommand, UpdateItemCommand, TransactWriteItemsCommand } from '@aws-sdk/client-dynamodb';
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

// Command side - Write model
interface Command {
  commandId: string;
  aggregateId: string;
  commandType: string;
  payload: any;
  timestamp: number;
  version: number;
}

interface Event {
  eventId: string;
  aggregateId: string;
  eventType: string;
  payload: any;
  timestamp: number;
  version: number;
}

// Aggregate root for the command side
class CustomerAggregate {
  private customerId: string;
  private version: number;
  private email: string;
  private name: string;
  private status: 'ACTIVE' | 'INACTIVE' | 'SUSPENDED';
  private uncommittedEvents: Event[] = [];

  constructor(customerId: string) {
    this.customerId = customerId;
    this.version = 0;
    this.status = 'INACTIVE';
  }

  // Command handlers
  registerCustomer(email: string, name: string): void {
    if (this.version > 0) {
      throw new Error('Customer already exists');
    }

    this.applyEvent({
      eventId: `${this.customerId}-${Date.now()}`,
      aggregateId: this.customerId,
      eventType: 'CustomerRegistered',
      payload: { email, name },
      timestamp: Date.now(),
      version: this.version + 1
    });
  }

  updateEmail(newEmail: string): void {
    if (this.status !== 'ACTIVE') {
      throw new Error('Cannot update email for inactive customer');
    }

    if (newEmail === this.email) {
      return; // No change needed
    }

    this.applyEvent({
      eventId: `${this.customerId}-${Date.now()}`,
      aggregateId: this.customerId,
      eventType: 'CustomerEmailUpdated',
      payload: { oldEmail: this.email, newEmail },
      timestamp: Date.now(),
      version: this.version + 1
    });
  }

  suspendCustomer(reason: string): void {
    if (this.status !== 'ACTIVE') {
      throw new Error('Can only suspend active customers');
    }

    this.applyEvent({
      eventId: `${this.customerId}-${Date.now()}`,
      aggregateId: this.customerId,
      eventType: 'CustomerSuspended',
      payload: { reason },
      timestamp: Date.now(),
      version: this.version + 1
    });
  }

  private applyEvent(event: Event): void {
    // Apply the event to the aggregate state
    switch (event.eventType) {
      case 'CustomerRegistered':
        this.email = event.payload.email;
        this.name = event.payload.name;
        this.status = 'ACTIVE';
        break;
      case 'CustomerEmailUpdated':
        this.email = event.payload.newEmail;
        break;
      case 'CustomerSuspended':
        this.status = 'SUSPENDED';
        break;
    }

    this.version = event.version;
    this.uncommittedEvents.push(event);
  }

  getUncommittedEvents(): Event[] {
    return [...this.uncommittedEvents];
  }

  markEventsAsCommitted(): void {
    this.uncommittedEvents = [];
  }

  // Hydrate from events (for event sourcing)
  static fromEvents(customerId: string, events: Event[]): CustomerAggregate {
    const aggregate = new CustomerAggregate(customerId);
    
    events.forEach(event => {
      aggregate.applyEvent(event);
    });
    
    aggregate.markEventsAsCommitted();
    return aggregate;
  }
}

// Command handler service
class CommandHandler {
  private dynamoClient: DynamoDBClient;
  private eventBridgeClient: EventBridgeClient;
  private commandTable: string;
  private eventSourceName: string;

  constructor(commandTable: string, eventSourceName: string) {
    this.dynamoClient = new DynamoDBClient({});
    this.eventBridgeClient = new EventBridgeClient({});
    this.commandTable = commandTable;
    this.eventSourceName = eventSourceName;
  }

  async handleRegisterCustomerCommand(command: {
    customerId: string;
    email: string;
    name: string;
  }): Promise<void> {
    try {
      // Load existing aggregate (if any)
      const aggregate = new CustomerAggregate(command.customerId);
      
      // Execute command
      aggregate.registerCustomer(command.email, command.name);
      
      // Persist changes and publish events
      await this.saveAggregateAndPublishEvents(aggregate);
      
    } catch (error) {
      console.error('Failed to handle RegisterCustomer command:', error);
      throw error;
    }
  }

  async handleUpdateEmailCommand(command: {
    customerId: string;
    newEmail: string;
    expectedVersion: number;
  }): Promise<void> {
    try {
      // Load existing aggregate
      const aggregate = await this.loadAggregate(command.customerId);
      
      // Check optimistic concurrency
      if (aggregate.version !== command.expectedVersion) {
        throw new Error('Concurrency conflict: aggregate has been modified');
      }
      
      // Execute command
      aggregate.updateEmail(command.newEmail);
      
      // Persist changes and publish events
      await this.saveAggregateAndPublishEvents(aggregate);
      
    } catch (error) {
      console.error('Failed to handle UpdateEmail command:', error);
      throw error;
    }
  }

  private async loadAggregate(customerId: string): Promise<CustomerAggregate> {
    // In a full implementation, this would load events from event store
    // For this example, we'll create a new aggregate
    return new CustomerAggregate(customerId);
  }

  private async saveAggregateAndPublishEvents(aggregate: CustomerAggregate): Promise<void> {
    const events = aggregate.getUncommittedEvents();
    
    if (events.length === 0) {
      return;
    }

    // Use DynamoDB transaction to ensure atomicity
    const transactionItems = events.map(event => ({
      Put: {
        TableName: this.commandTable,
        Item: marshall({
          PK: `CUSTOMER#${event.aggregateId}`,
          SK: `EVENT#${event.version}`,
          eventId: event.eventId,
          eventType: event.eventType,
          payload: event.payload,
          timestamp: event.timestamp,
          version: event.version
        }),
        ConditionExpression: 'attribute_not_exists(PK)' // Ensure event doesn't already exist
      }
    }));

    // Save events to command store
    await this.dynamoClient.send(new TransactWriteItemsCommand({
      TransactItems: transactionItems
    }));

    // Publish events to EventBridge for read model updates
    await this.publishEvents(events);
    
    // Mark events as committed
    aggregate.markEventsAsCommitted();
  }

  private async publishEvents(events: Event[]): Promise<void> {
    const eventBridgeEvents = events.map(event => ({
      Source: this.eventSourceName,
      DetailType: event.eventType,
      Detail: JSON.stringify({
        eventId: event.eventId,
        aggregateId: event.aggregateId,
        payload: event.payload,
        timestamp: event.timestamp,
        version: event.version
      })
    }));

    await this.eventBridgeClient.send(new PutEventsCommand({
      Entries: eventBridgeEvents
    }));
  }
}

// Read model builder
class CustomerReadModelBuilder {
  private dynamoClient: DynamoDBClient;
  private readModelTable: string;

  constructor(readModelTable: string) {
    this.dynamoClient = new DynamoDBClient({});
    this.readModelTable = readModelTable;
  }

  async handleCustomerRegistered(event: Event): Promise<void> {
    const customerView = {
      customerId: event.aggregateId,
      email: event.payload.email,
      name: event.payload.name,
      status: 'ACTIVE',
      registrationDate: new Date(event.timestamp).toISOString(),
      lastUpdated: new Date(event.timestamp).toISOString(),
      version: event.version
    };

    await this.dynamoClient.send(new PutItemCommand({
      TableName: this.readModelTable,
      Item: marshall(customerView)
    }));
  }

  async handleCustomerEmailUpdated(event: Event): Promise<void> {
    await this.dynamoClient.send(new UpdateItemCommand({
      TableName: this.readModelTable,
      Key: marshall({ customerId: event.aggregateId }),
      UpdateExpression: 'SET email = :newEmail, lastUpdated = :timestamp, version = :version',
      ExpressionAttributeValues: marshall({
        ':newEmail': event.payload.newEmail,
        ':timestamp': new Date(event.timestamp).toISOString(),
        ':version': event.version
      }),
      ConditionExpression: 'version < :version' // Ensure we don't apply old events
    }));
  }

  async handleCustomerSuspended(event: Event): Promise<void> {
    await this.dynamoClient.send(new UpdateItemCommand({
      TableName: this.readModelTable,
      Key: marshall({ customerId: event.aggregateId }),
      UpdateExpression: 'SET #status = :status, suspensionReason = :reason, lastUpdated = :timestamp, version = :version',
      ExpressionAttributeNames: {
        '#status': 'status'
      },
      ExpressionAttributeValues: marshall({
        ':status': 'SUSPENDED',
        ':reason': event.payload.reason,
        ':timestamp': new Date(event.timestamp).toISOString(),
        ':version': event.version
      }),
      ConditionExpression: 'version < :version'
    }));
  }
}

// Lambda handlers
export const commandHandler = async (event: any) => {
  const commandHandler = new CommandHandler(
    process.env.COMMAND_TABLE!,
    process.env.EVENT_SOURCE_NAME!
  );

  try {
    switch (event.commandType) {
      case 'RegisterCustomer':
        await commandHandler.handleRegisterCustomerCommand(event.payload);
        break;
      case 'UpdateEmail':
        await commandHandler.handleUpdateEmailCommand(event.payload);
        break;
      default:
        throw new Error(`Unknown command type: ${event.commandType}`);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true })
    };
  } catch (error) {
    return {
      statusCode: 400,
      body: JSON.stringify({
        error: error.message
      })
    };
  }
};

export const readModelHandler = async (event: any) => {
  const readModelBuilder = new CustomerReadModelBuilder(
    process.env.READ_MODEL_TABLE!
  );

  try {
    for (const record of event.Records) {
      const eventDetail = JSON.parse(record.body);
      const eventData: Event = JSON.parse(eventDetail.detail);

      switch (eventData.eventType) {
        case 'CustomerRegistered':
          await readModelBuilder.handleCustomerRegistered(eventData);
          break;
        case 'CustomerEmailUpdated':
          await readModelBuilder.handleCustomerEmailUpdated(eventData);
          break;
        case 'CustomerSuspended':
          await readModelBuilder.handleCustomerSuspended(eventData);
          break;
      }
    }

    return { statusCode: 200 };
  } catch (error) {
    console.error('Read model update failed:', error);
    throw error; // This will trigger retry via SQS
  }
};

// Query service for read operations
class CustomerQueryService {
  private dynamoClient: DynamoDBClient;
  private readModelTable: string;

  constructor(readModelTable: string) {
    this.dynamoClient = new DynamoDBClient({});
    this.readModelTable = readModelTable;
  }

  async getCustomerById(customerId: string): Promise<any | null> {
    const response = await this.dynamoClient.send(new GetItemCommand({
      TableName: this.readModelTable,
      Key: marshall({ customerId })
    }));

    return response.Item ? unmarshall(response.Item) : null;
  }

  async getActiveCustomers(): Promise<any[]> {
    // Implementation would use GSI or scan with filter
    // This is a simplified placeholder
    return [];
  }

  async searchCustomersByEmail(emailPattern: string): Promise<any[]> {
    // Implementation would use ElasticSearch or similar
    // This is a simplified placeholder
    return [];
  }
}

export const queryHandler = async (event: any) => {
  const queryService = new CustomerQueryService(
    process.env.READ_MODEL_TABLE!
  );

  try {
    switch (event.queryType) {
      case 'GetCustomerById':
        const customer = await queryService.getCustomerById(event.customerId);
        return {
          statusCode: customer ? 200 : 404,
          body: JSON.stringify(customer)
        };
      
      case 'GetActiveCustomers':
        const activeCustomers = await queryService.getActiveCustomers();
        return {
          statusCode: 200,
          body: JSON.stringify(activeCustomers)
        };
        
      default:
        return {
          statusCode: 400,
          body: JSON.stringify({ error: 'Unknown query type' })
        };
    }
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: error.message })
    };
  }
};
````
