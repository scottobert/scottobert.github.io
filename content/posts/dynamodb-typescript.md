---
title: "DynamoDB with TypeScript: Type-Safe NoSQL Operations"
date: 2023-07-02T10:00:00-07:00
draft: false
categories: ["Cloud Computing", "Database Design"]
tags:
- AWS
- TypeScript
- DynamoDB
- NoSQL
- Database
- Development
series: "AWS and Typescript"
---

Working with NoSQL databases like DynamoDB can be challenging when it comes to maintaining type safety and data consistency. In this post, we'll explore how to build robust, type-safe DynamoDB operations using TypeScript, covering everything from basic CRUD operations to advanced patterns like single-table design and transaction handling.

{{< plantuml id="dynamodb-single-table" >}}
@startuml DynamoDB Single Table Design
!define RECTANGLE class

package "Single Table Design" {
  database "DynamoDB Table" as table {
    rectangle "Partition Key (PK)" as pk
    rectangle "Sort Key (SK)" as sk
    rectangle "GSI1PK" as gsi1pk
    rectangle "GSI1SK" as gsi1sk
  }
  
  rectangle "User Entity" as user {
    rectangle "PK: USER#123" as user_pk
    rectangle "SK: USER#123" as user_sk
    rectangle "GSI1PK: EMAIL#user_at_domain.com" as user_gsi1pk
    rectangle "Data: name, email, dept" as user_data
  }
  
  rectangle "Order Entity" as order {
    rectangle "PK: ORDER#456" as order_pk
    rectangle "SK: ORDER#456" as order_sk
    rectangle "GSI1PK: USER#123" as order_gsi1pk
    rectangle "GSI1SK: ORDER#2023-07-02" as order_gsi1sk
    rectangle "Data: items, total, status" as order_data
  }
  
  rectangle "Product Entity" as product {
    rectangle "PK: PRODUCT#789" as product_pk
    rectangle "SK: PRODUCT#789" as product_sk
    rectangle "GSI1PK: CATEGORY#electronics" as product_gsi1pk
    rectangle "Data: name, price, stock" as product_data
  }
}

table --> user : Store
table --> order : Store
table --> product : Store

note right of table
  • Single table for all entities
  • Composite keys for relationships
  • GSI for access patterns
  • Type-safe operations
end note

note bottom of user
  Access Patterns:
  • Get user by ID: PK = USER#id
  • Get user by email: GSI1PK = EMAIL#email
end note

note bottom of order
  Access Patterns:
  • Get order by ID: PK = ORDER#id
  • Get orders by user: GSI1PK = USER#id
end note
@enduml
{{< /plantuml >}}

## Why Type Safety Matters with DynamoDB

DynamoDB's flexible schema brings both opportunities and challenges:

- **Runtime Safety**: Prevent schema mismatches and data corruption at compile time
- **Developer Experience**: IntelliSense, autocomplete, and refactoring support
- **Single-Table Design**: Type safety becomes critical when multiple entities share the same table
- **Access Pattern Validation**: Ensure queries match your intended data access patterns
- **Relationship Integrity**: Maintain consistency across entity relationships

## Prerequisites

Essential tools and knowledge for type-safe DynamoDB development:

- **AWS SDK v3**: `@aws-sdk/client-dynamodb` and `@aws-sdk/lib-dynamodb`
- **DynamoDB Concepts**: Partition keys, sort keys, GSIs, and access patterns
- **Single-Table Design**: Understanding of NoSQL modeling principles
- **TypeScript**: Advanced type features like discriminated unions and type guards

## Type-Safe Entity Design

Create comprehensive, maintainable entity models using TypeScript's advanced type features:

```typescript
// src/types/entities.ts
export interface BaseEntity {
  pk: string;           // Partition Key
  sk: string;           // Sort Key
  gsi1pk?: string;      // Global Secondary Index 1 PK
  gsi1sk?: string;      // Global Secondary Index 1 SK
  entityType: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface User extends BaseEntity {
  entityType: 'USER';
  userId: string;
  email: string;
  name: string;
  department?: string;
  isActive: boolean;
  lastLoginAt?: string;
}

export interface Order extends BaseEntity {
  entityType: 'ORDER';
  orderId: string;
  userId: string;
  status: OrderStatus;
  totalAmount: number;
  currency: string;
  items: OrderItem[];
  shippingAddress: Address;
  placedAt: string;
  fulfillmentDate?: string;
}

export interface Product extends BaseEntity {
  entityType: 'PRODUCT';
  productId: string;
  name: string;
  description: string;
  price: number;
  currency: string;
  category: string;
  stockQuantity: number;
  isAvailable: boolean;
  tags: string[];
}

// Supporting types
export enum OrderStatus {
  PENDING = 'PENDING',
  CONFIRMED = 'CONFIRMED',
  SHIPPED = 'SHIPPED',
  DELIVERED = 'DELIVERED',
  CANCELLED = 'CANCELLED'
}

export interface OrderItem {
  productId: string;
  productName: string;
  quantity: number;
  unitPrice: number;
  totalPrice: number;
}

export interface Address {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

// Type guards for runtime safety
export const isUser = (entity: BaseEntity): entity is User => 
  entity.entityType === 'USER';

export const isOrder = (entity: BaseEntity): entity is Order => 
  entity.entityType === 'ORDER';

export const isProduct = (entity: BaseEntity): entity is Product => 
  entity.entityType === 'PRODUCT';

// Union type for type-safe entity handling
export type Entity = User | Order | Product;
```

## Repository Pattern Implementation

Build a robust, reusable repository base class:

```typescript
// src/repositories/base-repository.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { 
  DynamoDBDocumentClient, 
  PutCommand, 
  GetCommand, 
  UpdateCommand, 
  DeleteCommand,
  QueryCommand,
  BatchGetCommand
} from '@aws-sdk/lib-dynamodb';
import { BaseEntity } from '../types/entities';

export abstract class BaseRepository<T extends BaseEntity> {
  protected docClient: DynamoDBDocumentClient;
  protected tableName: string;

  constructor(tableName: string) {
    const dynamoClient = new DynamoDBClient({
      maxAttempts: 3,
      retryMode: 'adaptive'
    });
    
    this.docClient = DynamoDBDocumentClient.from(dynamoClient, {
      marshallOptions: {
        convertEmptyValues: false,
        removeUndefinedValues: true
      }
    });
    
    this.tableName = tableName;
  }

  async create(entity: Omit<T, 'createdAt' | 'updatedAt' | 'version'>): Promise<T> {
    const timestamp = new Date().toISOString();
    const entityWithMetadata = {
      ...entity,
      createdAt: timestamp,
      updatedAt: timestamp,
      version: 1
    } as T;

    try {
      await this.docClient.send(new PutCommand({
        TableName: this.tableName,
        Item: entityWithMetadata,
        ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)'
      }));

      return entityWithMetadata;
    } catch (error) {
      if (error.name === 'ConditionalCheckFailedException') {
        throw new Error(`Entity already exists: ${entity.pk}#${entity.sk}`);
      }
      throw error;
    }
  }

  async get(pk: string, sk: string): Promise<T | null> {
    const { Item } = await this.docClient.send(new GetCommand({
      TableName: this.tableName,
      Key: { pk, sk }
    }));

    return Item as T || null;
  }

  async update(
    pk: string, 
    sk: string, 
    updates: Partial<Omit<T, 'pk' | 'sk' | 'entityType' | 'createdAt'>>,
    expectedVersion?: number
  ): Promise<T> {
    const updateExpressions: string[] = [];
    const attributeNames: Record<string, string> = {};
    const attributeValues: Record<string, any> = {};

    // Build update expression dynamically
    Object.entries(updates).forEach(([key, value], index) => {
      if (key !== 'version') {
        updateExpressions.push(`#attr${index} = :val${index}`);
        attributeNames[`#attr${index}`] = key;
        attributeValues[`:val${index}`] = value;
      }
    });

    // Always update timestamp and version
    updateExpressions.push('#updatedAt = :updatedAt', '#version = #version + :inc');
    attributeNames['#updatedAt'] = 'updatedAt';
    attributeNames['#version'] = 'version';
    attributeValues[':updatedAt'] = new Date().toISOString();
    attributeValues[':inc'] = 1;

    let conditionExpression = 'attribute_exists(pk)';
    if (expectedVersion !== undefined) {
      conditionExpression += ' AND #version = :expectedVersion';
      attributeValues[':expectedVersion'] = expectedVersion;
    }

    try {
      const { Attributes } = await this.docClient.send(new UpdateCommand({
        TableName: this.tableName,
        Key: { pk, sk },
        UpdateExpression: `SET ${updateExpressions.join(', ')}`,
        ExpressionAttributeNames: attributeNames,
        ExpressionAttributeValues: attributeValues,
        ConditionExpression: conditionExpression,
        ReturnValues: 'ALL_NEW'
      }));

      return Attributes as T;
    } catch (error) {
      if (error.name === 'ConditionalCheckFailedException') {
        throw new Error(expectedVersion ? 'Version mismatch' : 'Entity not found');
      }
      throw error;
    }
  }

  async delete(pk: string, sk: string, expectedVersion?: number): Promise<void> {
    let conditionExpression = 'attribute_exists(pk)';
    const attributeValues: Record<string, any> = {};

    if (expectedVersion !== undefined) {
      conditionExpression += ' AND version = :expectedVersion';
      attributeValues[':expectedVersion'] = expectedVersion;
    }

    try {
      await this.docClient.send(new DeleteCommand({
        TableName: this.tableName,
        Key: { pk, sk },
        ConditionExpression: conditionExpression,
        ExpressionAttributeValues: Object.keys(attributeValues).length ? attributeValues : undefined
      }));
    } catch (error) {
      if (error.name === 'ConditionalCheckFailedException') {
        throw new Error(expectedVersion ? 'Version mismatch' : 'Entity not found');
      }
      throw error;
    }
  }

  async query(
    pkValue: string,
    skCondition?: {
      operator: 'begins_with' | 'between' | '=' | '<' | '<=' | '>' | '>=';
      value: string | [string, string];
    },
    options?: {
      indexName?: string;
      limit?: number;
      scanIndexForward?: boolean;
      exclusiveStartKey?: Record<string, any>;
    }
  ): Promise<{ items: T[]; lastEvaluatedKey?: Record<string, any> }> {
    let keyConditionExpression = 'pk = :pk';
    const attributeValues: Record<string, any> = { ':pk': pkValue };

    if (skCondition) {
      const { operator, value } = skCondition;
      
      if (operator === 'begins_with') {
        keyConditionExpression += ' AND begins_with(sk, :sk)';
        attributeValues[':sk'] = value;
      } else if (operator === 'between' && Array.isArray(value)) {
        keyConditionExpression += ' AND sk BETWEEN :sk1 AND :sk2';
        attributeValues[':sk1'] = value[0];
        attributeValues[':sk2'] = value[1];
      } else if (typeof value === 'string') {
        keyConditionExpression += ` AND sk ${operator} :sk`;
        attributeValues[':sk'] = value;
      }
    }

    const { Items, LastEvaluatedKey } = await this.docClient.send(new QueryCommand({
      TableName: this.tableName,
      IndexName: options?.indexName,
      KeyConditionExpression: keyConditionExpression,
      ExpressionAttributeValues: attributeValues,
      Limit: options?.limit,
      ScanIndexForward: options?.scanIndexForward,
      ExclusiveStartKey: options?.exclusiveStartKey
    }));

    return {
      items: Items as T[],
      lastEvaluatedKey: LastEvaluatedKey
    };
  }

  async batchGet(keys: Array<{ pk: string; sk: string }>): Promise<T[]> {
    if (keys.length === 0) return [];
    
    const batches = this.chunkArray(keys, 100);
    const results: T[] = [];

    for (const batch of batches) {
      const { Responses } = await this.docClient.send(new BatchGetCommand({
        RequestItems: {
          [this.tableName]: { Keys: batch }
        }
      }));

      if (Responses?.[this.tableName]) {
        results.push(...(Responses[this.tableName] as T[]));
      }
    }

    return results;
  }

  private chunkArray<U>(array: U[], chunkSize: number): U[][] {
    return Array.from({ length: Math.ceil(array.length / chunkSize) }, (_, i) =>
      array.slice(i * chunkSize, i * chunkSize + chunkSize)
    );
  }
}
```

## Specialized Repository Implementations

Create domain-specific repositories with tailored access patterns:

```typescript
// src/repositories/user-repository.ts
import { BaseRepository } from './base-repository';
import { User } from '../types/entities';

export class UserRepository extends BaseRepository<User> {
  async createUser(userData: {
    userId: string;
    email: string;
    name: string;
    department?: string;
  }): Promise<User> {
    return this.create({
      pk: `USER#${userData.userId}`,
      sk: `USER#${userData.userId}`,
      gsi1pk: `EMAIL#${userData.email}`,
      gsi1sk: `USER#${userData.userId}`,
      entityType: 'USER',
      userId: userData.userId,
      email: userData.email,
      name: userData.name,
      department: userData.department,
      isActive: true
    });
  }

  async getUserById(userId: string): Promise<User | null> {
    return this.get(`USER#${userId}`, `USER#${userId}`);
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const { items } = await this.query(
      `EMAIL#${email}`,
      undefined,
      { indexName: 'GSI1' }
    );
    return items[0] || null;
  }

  async updateUser(
    userId: string,
    updates: Partial<Pick<User, 'name' | 'department' | 'isActive' | 'lastLoginAt'>>,
    expectedVersion?: number
  ): Promise<User> {
    return this.update(`USER#${userId}`, `USER#${userId}`, updates, expectedVersion);
  }

  async getUsersByDepartment(department: string): Promise<User[]> {
    const { items } = await this.query(
      `DEPARTMENT#${department}`,
      undefined,
      { indexName: 'GSI2' }
    );
    return items;
  }
}
```

```typescript
// src/repositories/order-repository.ts
import { BaseRepository } from './base-repository';
import { Order, OrderStatus } from '../types/entities';

export class OrderRepository extends BaseRepository<Order> {
  async createOrder(orderData: {
    orderId: string;
    userId: string;
    totalAmount: number;
    currency: string;
    items: Order['items'];
    shippingAddress: Order['shippingAddress'];
  }): Promise<Order> {
    return this.create({
      pk: `ORDER#${orderData.orderId}`,
      sk: `ORDER#${orderData.orderId}`,
      gsi1pk: `USER#${orderData.userId}`,
      gsi1sk: `ORDER#${new Date().toISOString()}`,
      entityType: 'ORDER',
      orderId: orderData.orderId,
      userId: orderData.userId,
      status: OrderStatus.PENDING,
      totalAmount: orderData.totalAmount,
      currency: orderData.currency,
      items: orderData.items,
      shippingAddress: orderData.shippingAddress,
      placedAt: new Date().toISOString()
    });
  }

  async getOrderById(orderId: string): Promise<Order | null> {
    return this.get(`ORDER#${orderId}`, `ORDER#${orderId}`);
  }

  async getOrdersByUserId(
    userId: string,
    options?: { limit?: number; exclusiveStartKey?: Record<string, any> }
  ): Promise<{ orders: Order[]; lastEvaluatedKey?: Record<string, any> }> {
    const result = await this.query(
      `USER#${userId}`,
      { operator: 'begins_with', value: 'ORDER#' },
      { 
        indexName: 'GSI1',
        limit: options?.limit,
        scanIndexForward: false, // Most recent first
        exclusiveStartKey: options?.exclusiveStartKey
      }
    );

    return {
      orders: result.items,
      lastEvaluatedKey: result.lastEvaluatedKey
    };
  }

  async updateOrderStatus(
    orderId: string,
    status: OrderStatus,
    expectedVersion?: number
  ): Promise<Order> {
    const updates: Partial<Order> = { status };
    
    if (status === OrderStatus.DELIVERED) {
      updates.fulfillmentDate = new Date().toISOString();
    }

    return this.update(`ORDER#${orderId}`, `ORDER#${orderId}`, updates, expectedVersion);
  }

  async getOrdersByStatus(status: OrderStatus, limit?: number): Promise<Order[]> {
    const { items } = await this.query(
      `STATUS#${status}`,
      undefined,
      { indexName: 'GSI3', limit }
    );
    return items;
  }
}
```

## Transaction Management

Implement type-safe transaction operations for complex business logic:

```typescript
// src/services/transaction-service.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, TransactWriteCommand } from '@aws-sdk/lib-dynamodb';

export class TransactionService {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string) {
    this.docClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));
    this.tableName = tableName;
  }

  async executeTransaction(operations: TransactionOperation[]): Promise<void> {
    if (operations.length > 25) {
      throw new Error('DynamoDB transactions support maximum 25 operations');
    }

    const transactItems = operations.map(op => this.buildTransactionItem(op));

    await this.docClient.send(new TransactWriteCommand({
      TransactItems: transactItems
    }));
  }

  private buildTransactionItem(operation: TransactionOperation): any {
    const { type } = operation;
    
    switch (type) {
      case 'Put':
        return {
          Put: {
            TableName: this.tableName,
            Item: operation.item,
            ConditionExpression: operation.conditionExpression,
            ExpressionAttributeNames: operation.expressionAttributeNames,
            ExpressionAttributeValues: operation.expressionAttributeValues
          }
        };

      case 'Update':
        return {
          Update: {
            TableName: this.tableName,
            Key: operation.key,
            UpdateExpression: operation.updateExpression,
            ConditionExpression: operation.conditionExpression,
            ExpressionAttributeNames: operation.expressionAttributeNames,
            ExpressionAttributeValues: operation.expressionAttributeValues
          }
        };

      case 'Delete':
        return {
          Delete: {
            TableName: this.tableName,
            Key: operation.key,
            ConditionExpression: operation.conditionExpression
          }
        };

      case 'ConditionCheck':
        return {
          ConditionCheck: {
            TableName: this.tableName,
            Key: operation.key,
            ConditionExpression: operation.conditionExpression,
            ExpressionAttributeNames: operation.expressionAttributeNames,
            ExpressionAttributeValues: operation.expressionAttributeValues
          }
        };

      default:
        throw new Error(`Unsupported operation type: ${type}`);
    }
  }
}

export interface TransactionOperation {
  type: 'Put' | 'Update' | 'Delete' | 'ConditionCheck';
  key?: { pk: string; sk: string };
  item?: any;
  updateExpression?: string;
  conditionExpression?: string;
  expressionAttributeNames?: Record<string, string>;
  expressionAttributeValues?: Record<string, any>;
}

// Business logic example: Order fulfillment with inventory update
export async function fulfillOrder(
  transactionService: TransactionService,
  orderId: string,
  items: Array<{ productId: string; quantity: number }>,
  orderVersion: number
): Promise<void> {
  const operations: TransactionOperation[] = [
    // Update order status
    {
      type: 'Update',
      key: { pk: `ORDER#${orderId}`, sk: `ORDER#${orderId}` },
      updateExpression: 'SET #status = :status, #fulfilled = :fulfilled, version = version + :inc',
      conditionExpression: 'version = :expectedVersion',
      expressionAttributeNames: {
        '#status': 'status',
        '#fulfilled': 'fulfillmentDate'
      },
      expressionAttributeValues: {
        ':status': 'DELIVERED',
        ':fulfilled': new Date().toISOString(),
        ':expectedVersion': orderVersion,
        ':inc': 1
      }
    }
  ];

  // Add inventory updates for each item
  items.forEach(item => {
    operations.push({
      type: 'Update',
      key: { pk: `PRODUCT#${item.productId}`, sk: `PRODUCT#${item.productId}` },
      updateExpression: 'SET stockQuantity = stockQuantity - :qty, version = version + :inc',
      conditionExpression: 'stockQuantity >= :qty',
      expressionAttributeValues: {
        ':qty': item.quantity,
        ':inc': 1
      }
    });
  });

  await transactionService.executeTransaction(operations);
}
```

## Error Handling and Utilities

Create comprehensive error handling for robust DynamoDB operations:

```typescript
// src/utils/dynamodb-errors.ts
export class DynamoDBError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode: number,
    public retryable: boolean = false
  ) {
    super(message);
    this.name = 'DynamoDBError';
  }
}

export class EntityNotFoundError extends DynamoDBError {
  constructor(entityType: string, key: string) {
    super(`${entityType} not found: ${key}`, 'ENTITY_NOT_FOUND', 404);
  }
}

export class EntityAlreadyExistsError extends DynamoDBError {
  constructor(entityType: string, key: string) {
    super(`${entityType} already exists: ${key}`, 'ENTITY_ALREADY_EXISTS', 409);
  }
}

export class VersionMismatchError extends DynamoDBError {
  constructor(expected: number, actual?: number) {
    super(
      `Version mismatch. Expected ${expected}${actual ? `, got ${actual}` : ''}`,
      'VERSION_MISMATCH',
      409
    );
  }
}

export const handleDynamoDBError = (error: any): never => {
  const errorMap: Record<string, () => DynamoDBError> = {
    ConditionalCheckFailedException: () => new DynamoDBError(
      'Conditional check failed',
      'CONDITIONAL_CHECK_FAILED',
      409
    ),
    ProvisionedThroughputExceededException: () => new DynamoDBError(
      'Provisioned throughput exceeded',
      'THROUGHPUT_EXCEEDED',
      429,
      true
    ),
    ResourceNotFoundException: () => new DynamoDBError(
      'Table not found',
      'TABLE_NOT_FOUND',
      404
    ),
    TransactionCanceledException: () => new DynamoDBError(
      'Transaction cancelled',
      'TRANSACTION_CANCELLED',
      409
    ),
    ValidationException: () => new DynamoDBError(
      error.message,
      'VALIDATION_ERROR',
      400
    )
  };

  const errorHandler = errorMap[error.name];
  if (errorHandler) {
    throw errorHandler();
  }

  throw new DynamoDBError(
    error.message || 'Unknown DynamoDB error',
    'UNKNOWN_ERROR',
    500
  );
};
```

## Advanced Query Patterns

{{< plantuml id="dynamodb-query-patterns" >}}
@startuml DynamoDB Access Patterns
!define RECTANGLE class

package "Query Patterns" {
  rectangle "Primary Key Access" as pk {
    rectangle "GetItem" as get
    rectangle "PutItem" as put
    rectangle "UpdateItem" as update
    rectangle "DeleteItem" as delete
  }
  
  rectangle "Query Operations" as query {
    rectangle "Single Entity Type" as single
    rectangle "Related Entities" as related
    rectangle "Time-based Queries" as time
    rectangle "Status Filtering" as status
  }
  
  rectangle "Global Secondary Index" as gsi {
    rectangle "Alternative Access" as alt
    rectangle "Inverted Relationships" as invert
    rectangle "Sparse Index" as sparse
  }
  
  rectangle "Batch Operations" as batch {
    rectangle "BatchGet" as bget
    rectangle "BatchWrite" as bwrite
    rectangle "Transactions" as trans
  }
}

get --> single : Direct lookup
query --> related : One-to-many
query --> time : Sort by timestamp
gsi --> alt : Email lookup
gsi --> invert : User's orders
batch --> trans : Atomic operations

note right of pk
  • Fast, consistent performance
  • Single item operations
  • Strong consistency
end note

note right of query
  • Efficient range queries
  • Sort key conditions
  • Pagination support
end note

note right of gsi
  • Alternative query patterns
  • Eventually consistent
  • Sparse data support
end note
@enduml
{{< /plantuml >}}

Implement advanced query patterns and utilities:

```typescript
// src/services/query-service.ts
import { BaseRepository } from '../repositories/base-repository';
import { Entity, User, Order, isUser, isOrder } from '../types/entities';

export class QueryService {
  constructor(private repository: BaseRepository<Entity>) {}

  // Paginated queries with type safety
  async getPaginatedResults<T extends Entity>(
    queryFn: (lastKey?: Record<string, any>) => Promise<{ items: T[]; lastEvaluatedKey?: Record<string, any> }>,
    pageSize: number = 20
  ): Promise<{ items: T[]; nextToken?: string }> {
    const result = await queryFn();
    
    return {
      items: result.items.slice(0, pageSize),
      nextToken: result.lastEvaluatedKey ? 
        Buffer.from(JSON.stringify(result.lastEvaluatedKey)).toString('base64') : 
        undefined
    };
  }

  // Multi-entity type filtering
  async getEntitiesByType<T extends Entity>(
    pkValue: string,
    entityType: T['entityType'],
    typeGuard: (entity: Entity) => entity is T
  ): Promise<T[]> {
    const { items } = await this.repository.query(
      pkValue,
      { operator: 'begins_with', value: entityType }
    );

    return items.filter(typeGuard);
  }

  // Complex relationship queries
  async getUserWithOrders(userId: string): Promise<{
    user: User | null;
    orders: Order[];
    totalSpent: number;
  }> {
    // Get user data
    const user = await this.repository.get(`USER#${userId}`, `USER#${userId}`);
    
    if (!user || !isUser(user)) {
      return { user: null, orders: [], totalSpent: 0 };
    }

    // Get user's orders
    const { items } = await this.repository.query(
      `USER#${userId}`,
      { operator: 'begins_with', value: 'ORDER#' },
      { indexName: 'GSI1', scanIndexForward: false }
    );

    const orders = items.filter(isOrder);
    const totalSpent = orders.reduce((sum, order) => sum + order.totalAmount, 0);

    return { user, orders, totalSpent };
  }

  // Time-based range queries
  async getOrdersInDateRange(
    userId: string,
    startDate: string,
    endDate: string
  ): Promise<Order[]> {
    const { items } = await this.repository.query(
      `USER#${userId}`,
      { 
        operator: 'between', 
        value: [`ORDER#${startDate}`, `ORDER#${endDate}`] 
      },
      { indexName: 'GSI1' }
    );

    return items.filter(isOrder);
  }
}
```

## Testing Strategy

Implement comprehensive testing with proper mocking:

```typescript
// tests/repositories/user-repository.test.ts
import { UserRepository } from '../../src/repositories/user-repository';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';
import 'aws-sdk-client-mock-jest';

const mockDynamoClient = mockClient(DynamoDBDocumentClient);

describe('UserRepository', () => {
  let userRepository: UserRepository;

  beforeEach(() => {
    mockDynamoClient.reset();
    userRepository = new UserRepository('test-table');
  });

  describe('createUser', () => {
    it('creates user with proper key structure', async () => {
      mockDynamoClient.resolves({});

      const userData = {
        userId: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        department: 'Engineering'
      };

      const result = await userRepository.createUser(userData);

      expect(result.pk).toBe('USER#user-123');
      expect(result.sk).toBe('USER#user-123');
      expect(result.gsi1pk).toBe('EMAIL#test@example.com');
      expect(result.entityType).toBe('USER');
      expect(result.isActive).toBe(true);
      expect(result.version).toBe(1);
      expect(result.createdAt).toBeDefined();
    });

    it('handles creation conflicts gracefully', async () => {
      const error = new Error('Conditional check failed');
      error.name = 'ConditionalCheckFailedException';
      mockDynamoClient.rejects(error);

      const userData = {
        userId: 'user-123',
        email: 'test@example.com',
        name: 'Test User'
      };

      await expect(userRepository.createUser(userData)).rejects.toThrow(
        'Entity already exists'
      );
    });
  });

  describe('getUserByEmail', () => {
    it('returns user when found via GSI', async () => {
      const mockUser = {
        pk: 'USER#user-123',
        sk: 'USER#user-123',
        entityType: 'USER',
        userId: 'user-123',
        email: 'test@example.com',
        name: 'Test User',
        isActive: true,
        createdAt: '2023-07-02T10:00:00Z',
        updatedAt: '2023-07-02T10:00:00Z',
        version: 1
      };

      mockDynamoClient.resolves({ Items: [mockUser] });

      const result = await userRepository.getUserByEmail('test@example.com');

      expect(result).toEqual(mockUser);
      expect(mockDynamoClient).toHaveReceivedCommandWith('QueryCommand', {
        TableName: 'test-table',
        IndexName: 'GSI1',
        KeyConditionExpression: 'pk = :pk',
        ExpressionAttributeValues: { ':pk': 'EMAIL#test@example.com' }
      });
    });

    it('returns null when user not found', async () => {
      mockDynamoClient.resolves({ Items: [] });

      const result = await userRepository.getUserByEmail('nonexistent@example.com');

      expect(result).toBeNull();
    });
  });
});
```

## Infrastructure as Code

Define your DynamoDB table using AWS CDK:

```typescript
// infrastructure/database-stack.ts
import { Stack, StackProps, RemovalPolicy } from 'aws-cdk-lib';
import { Table, AttributeType, BillingMode, ProjectionType } from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';

export class DatabaseStack extends Stack {
  public readonly table: Table;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.table = new Table(this, 'MainTable', {
      tableName: 'app-main-table',
      partitionKey: { name: 'pk', type: AttributeType.STRING },
      sortKey: { name: 'sk', type: AttributeType.STRING },
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      removalPolicy: RemovalPolicy.RETAIN,
      
      // Global Secondary Index 1: For alternative access patterns
      globalSecondaryIndexes: [{
        indexName: 'GSI1',
        partitionKey: { name: 'gsi1pk', type: AttributeType.STRING },
        sortKey: { name: 'gsi1sk', type: AttributeType.STRING },
        projectionType: ProjectionType.ALL
      }, {
        indexName: 'GSI2',
        partitionKey: { name: 'gsi2pk', type: AttributeType.STRING },
        sortKey: { name: 'gsi2sk', type: AttributeType.STRING },
        projectionType: ProjectionType.ALL
      }]
    });
  }
}
```

## Conclusion

Building type-safe DynamoDB operations with TypeScript creates a robust foundation for scalable NoSQL applications. This approach provides:

- **Type Safety**: Compile-time guarantees for data shape consistency
- **Single-Table Design**: Efficient modeling with maintained type safety
- **Repository Pattern**: Clean separation of concerns and testable code
- **Transaction Support**: ACID compliance for complex business operations
- **Error Handling**: Graceful failure management with typed exceptions

Key benefits of this approach include:

1. **Reduced Runtime Errors**: TypeScript catches schema mismatches at compile time
2. **Improved Developer Experience**: IntelliSense and autocomplete for database operations
3. **Maintainable Code**: Clear interfaces and consistent patterns across the codebase
4. **Scalable Architecture**: Repository pattern supports growth and complexity
5. **Testing Confidence**: Comprehensive test coverage with proper mocking

The patterns demonstrated here support complex single-table designs while maintaining type safety throughout your application. The combination of strong typing, comprehensive error handling, and proper abstraction creates a maintainable architecture that scales with your needs.

In our next post, we'll explore **AWS WebSockets with TypeScript**, building real-time communication features that integrate seamlessly with the DynamoDB patterns established here.
