---
title: "API Design Patterns for Modern Applications"
date: 2021-09-26T11:00:00-07:00
draft: false
categories: ["Software Development", "Architecture and Design"]
tags:
- API Design
- REST
- GraphQL
- Architecture
- Best Practices
series: "Modern Development Practices"
---

Modern API design has evolved far beyond simple CRUD operations. Today's applications require APIs that are resilient, scalable, and developer-friendly while supporting diverse client needs and complex business workflows. This guide explores proven patterns that address these challenges.

## Foundational Design Principles

### API-First Development

Design your API before implementation to ensure consistency and usability:

```typescript
// Define API contract first
interface UserAPI {
  // Resource operations
  getUser(id: string): Promise<User>;
  updateUser(id: string, updates: Partial<User>): Promise<User>;
  deleteUser(id: string): Promise<void>;
  
  // Collection operations
  listUsers(filters: UserFilters, pagination: Pagination): Promise<PagedResult<User>>;
  searchUsers(query: SearchQuery): Promise<SearchResult<User>>;
  
  // Business operations
  activateUser(id: string): Promise<User>;
  deactivateUser(id: string): Promise<User>;
  resetUserPassword(id: string): Promise<void>;
}

// OpenAPI specification (generated or hand-written)
const userAPISpec = {
  openapi: '3.0.0',
  info: {
    title: 'User Management API',
    version: '1.0.0'
  },
  paths: {
    '/users/{id}': {
      get: {
        summary: 'Get user by ID',
        parameters: [
          {
            name: 'id',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' }
          }
        ],
        responses: {
          200: {
            description: 'User found',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/User' }
              }
            }
          },
          404: {
            description: 'User not found',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Error' }
              }
            }
          }
        }
      }
    }
  }
};
```

### Resource-Oriented Design

Structure APIs around resources, not actions:

```typescript
// Good: Resource-oriented endpoints
interface OrderAPI {
  // Orders resource
  createOrder(order: CreateOrderRequest): Promise<Order>;
  getOrder(orderId: string): Promise<Order>;
  updateOrder(orderId: string, updates: UpdateOrderRequest): Promise<Order>;
  cancelOrder(orderId: string): Promise<Order>;
  
  // Order items as sub-resource
  addOrderItem(orderId: string, item: OrderItem): Promise<OrderItem>;
  updateOrderItem(orderId: string, itemId: string, updates: Partial<OrderItem>): Promise<OrderItem>;
  removeOrderItem(orderId: string, itemId: string): Promise<void>;
  
  // Order status as resource state
  getOrderStatus(orderId: string): Promise<OrderStatus>;
  updateOrderStatus(orderId: string, status: OrderStatusUpdate): Promise<OrderStatus>;
}

// Avoid: Action-oriented endpoints
interface BadOrderAPI {
  processOrder(data: any): Promise<any>;
  doOrderCalculation(data: any): Promise<any>;
  performOrderValidation(data: any): Promise<any>;
}
```

## Advanced REST Patterns

### Hypermedia and HATEOAS

Include navigation links to make APIs self-discoverable:

```typescript
interface HypermediaResource {
  data: any;
  links: {
    self: { href: string };
    [relationship: string]: { href: string; method?: string };
  };
  meta?: {
    total?: number;
    page?: number;
    lastUpdated?: string;
  };
}

class OrderController {
  async getOrder(req: Request, res: Response): Promise<void> {
    const order = await this.orderService.findById(req.params.id);
    
    const response: HypermediaResource = {
      data: order,
      links: {
        self: { href: `/orders/${order.id}` },
        items: { href: `/orders/${order.id}/items` },
        customer: { href: `/customers/${order.customerId}` },
        ...(order.status === 'pending' && {
          cancel: { href: `/orders/${order.id}/cancel`, method: 'POST' },
          update: { href: `/orders/${order.id}`, method: 'PATCH' }
        }),
        ...(order.status === 'confirmed' && {
          ship: { href: `/orders/${order.id}/ship`, method: 'POST' },
          track: { href: `/orders/${order.id}/tracking` }
        })
      },
      meta: {
        lastUpdated: order.updatedAt.toISOString()
      }
    };
    
    res.json(response);
  }
}
```

### Advanced Query Patterns

Implement flexible querying capabilities:

```typescript
// Query builder for complex filtering
interface QueryBuilder {
  filter(field: string, operator: FilterOperator, value: any): QueryBuilder;
  sort(field: string, direction: 'asc' | 'desc'): QueryBuilder;
  include(relationships: string[]): QueryBuilder;
  page(number: number, size: number): QueryBuilder;
  fields(fieldList: string[]): QueryBuilder;
  build(): QueryParameters;
}

// Usage example
class UserController {
  async listUsers(req: Request, res: Response): Promise<void> {
    const query = new QueryBuilder()
      .filter('status', 'eq', 'active')
      .filter('lastLogin', 'gte', new Date('2023-01-01'))
      .sort('createdAt', 'desc')
      .include(['profile', 'preferences'])
      .page(req.query.page || 1, req.query.size || 20)
      .fields(['id', 'name', 'email', 'status'])
      .build();
    
    const result = await this.userService.findMany(query);
    
    res.json({
      data: result.items,
      pagination: {
        page: result.page,
        size: result.size,
        total: result.total,
        totalPages: Math.ceil(result.total / result.size)
      },
      links: {
        self: req.originalUrl,
        next: result.hasNext ? this.buildNextPageUrl(req, result.page + 1) : null,
        prev: result.hasPrev ? this.buildPrevPageUrl(req, result.page - 1) : null
      }
    });
  }
}

// Advanced search with full-text capabilities
interface SearchAPI {
  search(query: {
    q: string;                    // Full-text search
    filters?: Record<string, any>; // Structured filters
    facets?: string[];            // Aggregation facets
    highlight?: boolean;          // Highlight matches
    fuzzy?: boolean;             // Fuzzy matching
  }): Promise<SearchResult>;
}
```

### Content Negotiation and Versioning

Handle multiple API versions and content types:

```typescript
class ContentNegotiationMiddleware {
  static handle() {
    return (req: Request, res: Response, next: NextFunction) => {
      // API version negotiation
      const apiVersion = this.getAPIVersion(req);
      req.apiVersion = apiVersion;
      
      // Content type negotiation
      const acceptHeader = req.headers.accept;
      const supportedTypes = ['application/json', 'application/xml', 'application/hal+json'];
      const preferredType = this.negotiateContentType(acceptHeader, supportedTypes);
      
      if (!preferredType) {
        return res.status(406).json({
          error: 'Not Acceptable',
          supportedTypes
        });
      }
      
      req.preferredContentType = preferredType;
      next();
    };
  }
  
  private static getAPIVersion(req: Request): string {
    // Version from header
    if (req.headers['api-version']) {
      return req.headers['api-version'] as string;
    }
    
    // Version from Accept header
    const acceptHeader = req.headers.accept;
    const versionMatch = acceptHeader?.match(/application\/vnd\.api\.v(\d+)\+json/);
    if (versionMatch) {
      return versionMatch[1];
    }
    
    // Version from URL
    const urlMatch = req.url.match(/\/v(\d+)\//);
    if (urlMatch) {
      return urlMatch[1];
    }
    
    return '1'; // Default version
  }
}

// Version-specific controllers
class UserControllerV1 {
  async getUser(req: Request, res: Response): Promise<void> {
    const user = await this.userService.findById(req.params.id);
    res.json(this.transformUserV1(user));
  }
  
  private transformUserV1(user: User): any {
    return {
      id: user.id,
      name: user.fullName, // V1 used 'name' instead of separate first/last
      email: user.email
    };
  }
}

class UserControllerV2 {
  async getUser(req: Request, res: Response): Promise<void> {
    const user = await this.userService.findById(req.params.id);
    res.json(this.transformUserV2(user));
  }
  
  private transformUserV2(user: User): any {
    return {
      id: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      profile: user.profile // V2 includes profile data
    };
  }
}
```

## GraphQL Design Patterns

### Schema-First GraphQL Design

```typescript
// schema.graphql
type Query {
  user(id: ID!): User
  users(filter: UserFilter, pagination: PaginationInput): UserConnection
  searchUsers(query: String!): SearchResult
}

type Mutation {
  createUser(input: CreateUserInput!): CreateUserPayload
  updateUser(id: ID!, input: UpdateUserInput!): UpdateUserPayload
  deleteUser(id: ID!): DeleteUserPayload
}

type User {
  id: ID!
  firstName: String!
  lastName: String!
  email: String!
  profile: UserProfile
  orders(first: Int, after: String): OrderConnection
}

type UserConnection {
  edges: [UserEdge!]!
  pageInfo: PageInfo!
  totalCount: Int!
}

input UserFilter {
  status: UserStatus
  createdAfter: DateTime
  searchTerm: String
}

// Resolver implementation
class UserResolver {
  @Query()
  async user(@Arg('id') id: string): Promise<User> {
    return await this.userService.findById(id);
  }
  
  @Query()
  async users(
    @Arg('filter', { nullable: true }) filter: UserFilter,
    @Arg('pagination', { nullable: true }) pagination: PaginationInput
  ): Promise<UserConnection> {
    const result = await this.userService.findMany(filter, pagination);
    return this.transformToConnection(result);
  }
  
  @FieldResolver()
  async orders(
    @Root() user: User,
    @Arg('first', { defaultValue: 10 }) first: number,
    @Arg('after', { nullable: true }) after: string
  ): Promise<OrderConnection> {
    return await this.orderService.findByUserId(user.id, { first, after });
  }
}
```

### DataLoader for N+1 Problem

```typescript
import DataLoader from 'dataloader';

class DataLoaderFactory {
  createUserLoader(): DataLoader<string, User> {
    return new DataLoader<string, User>(
      async (userIds: readonly string[]) => {
        const users = await this.userService.findByIds([...userIds]);
        const userMap = new Map(users.map(user => [user.id, user]));
        return userIds.map(id => userMap.get(id) || new Error(`User not found: ${id}`));
      },
      {
        batch: true,
        cache: true,
        maxBatchSize: 100
      }
    );
  }
  
  createOrdersByUserLoader(): DataLoader<string, Order[]> {
    return new DataLoader<string, Order[]>(
      async (userIds: readonly string[]) => {
        const orders = await this.orderService.findByUserIds([...userIds]);
        const ordersByUser = new Map<string, Order[]>();
        
        orders.forEach(order => {
          const userOrders = ordersByUser.get(order.userId) || [];
          userOrders.push(order);
          ordersByUser.set(order.userId, userOrders);
        });
        
        return userIds.map(userId => ordersByUser.get(userId) || []);
      }
    );
  }
}

// Usage in resolver
class OrderResolver {
  @FieldResolver()
  async user(@Root() order: Order, @Ctx() context: GraphQLContext): Promise<User> {
    return await context.loaders.user.load(order.userId);
  }
}
```

## Error Handling Patterns

### Structured Error Responses

```typescript
interface APIError {
  code: string;
  message: string;
  details?: Record<string, any>;
  timestamp: string;
  requestId: string;
  path: string;
}

interface ValidationError extends APIError {
  code: 'VALIDATION_ERROR';
  fieldErrors: FieldError[];
}

interface FieldError {
  field: string;
  message: string;
  rejectedValue?: any;
}

class ErrorHandler {
  static handleAPIError(error: Error, req: Request, res: Response): void {
    const requestId = req.headers['x-request-id'] as string || generateRequestId();
    
    if (error instanceof ValidationError) {
      res.status(400).json({
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        fieldErrors: error.fieldErrors,
        timestamp: new Date().toISOString(),
        requestId,
        path: req.path
      });
    } else if (error instanceof NotFoundError) {
      res.status(404).json({
        code: 'RESOURCE_NOT_FOUND',
        message: error.message,
        timestamp: new Date().toISOString(),
        requestId,
        path: req.path
      });
    } else if (error instanceof BusinessRuleError) {
      res.status(422).json({
        code: 'BUSINESS_RULE_VIOLATION',
        message: error.message,
        details: error.details,
        timestamp: new Date().toISOString(),
        requestId,
        path: req.path
      });
    } else {
      // Internal server error
      res.status(500).json({
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
        timestamp: new Date().toISOString(),
        requestId,
        path: req.path
      });
    }
  }
}
```

## Rate Limiting and Throttling

### Advanced Rate Limiting Strategies

```typescript
interface RateLimitStrategy {
  isAllowed(key: string, request: Request): Promise<RateLimitResult>;
}

interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: Date;
  retryAfter?: number;
}

class TieredRateLimiter implements RateLimitStrategy {
  constructor(
    private redis: RedisClient,
    private tiers: RateLimitTier[]
  ) {}
  
  async isAllowed(key: string, request: Request): Promise<RateLimitResult> {
    const userTier = await this.getUserTier(request);
    const limits = this.tiers.find(t => t.name === userTier) || this.tiers[0];
    
    const windowStart = Math.floor(Date.now() / limits.windowMs) * limits.windowMs;
    const windowKey = `rate_limit:${key}:${windowStart}`;
    
    const current = await this.redis.incr(windowKey);
    if (current === 1) {
      await this.redis.expire(windowKey, Math.ceil(limits.windowMs / 1000));
    }
    
    const allowed = current <= limits.maxRequests;
    const resetTime = new Date(windowStart + limits.windowMs);
    
    return {
      allowed,
      remaining: Math.max(0, limits.maxRequests - current),
      resetTime,
      retryAfter: allowed ? undefined : Math.ceil((resetTime.getTime() - Date.now()) / 1000)
    };
  }
  
  private async getUserTier(request: Request): Promise<string> {
    const user = request.user;
    if (!user) return 'anonymous';
    
    // Check user subscription tier
    const subscription = await this.subscriptionService.getActiveSubscription(user.id);
    return subscription?.tier || 'basic';
  }
}

interface RateLimitTier {
  name: string;
  maxRequests: number;
  windowMs: number;
}

const rateLimitTiers: RateLimitTier[] = [
  { name: 'anonymous', maxRequests: 100, windowMs: 15 * 60 * 1000 }, // 100/15min
  { name: 'basic', maxRequests: 1000, windowMs: 15 * 60 * 1000 },    // 1000/15min
  { name: 'premium', maxRequests: 5000, windowMs: 15 * 60 * 1000 },  // 5000/15min
  { name: 'enterprise', maxRequests: 10000, windowMs: 15 * 60 * 1000 } // 10000/15min
];
```

## Documentation and Developer Experience

### Interactive API Documentation

```typescript
// Swagger/OpenAPI with rich examples
const apiDocumentation = {
  openapi: '3.0.0',
  info: {
    title: 'Modern API',
    version: '1.0.0',
    description: 'Comprehensive API with rich examples and interactive documentation'
  },
  servers: [
    { url: 'https://api.example.com/v1', description: 'Production' },
    { url: 'https://staging-api.example.com/v1', description: 'Staging' },
    { url: 'http://localhost:3000/v1', description: 'Development' }
  ],
  paths: {
    '/users': {
      post: {
        summary: 'Create a new user',
        requestBody: {
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/CreateUserRequest' },
              examples: {
                basic: {
                  summary: 'Basic user creation',
                  value: {
                    firstName: 'John',
                    lastName: 'Doe',
                    email: 'john.doe@example.com'
                  }
                },
                withProfile: {
                  summary: 'User with profile information',
                  value: {
                    firstName: 'Jane',
                    lastName: 'Smith',
                    email: 'jane.smith@example.com',
                    profile: {
                      bio: 'Software engineer passionate about clean code',
                      location: 'San Francisco, CA',
                      website: 'https://janesmith.dev'
                    }
                  }
                }
              }
            }
          }
        },
        responses: {
          201: {
            description: 'User created successfully',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/User' },
                examples: {
                  created: {
                    summary: 'Newly created user',
                    value: {
                      id: 'user_1234567890',
                      firstName: 'John',
                      lastName: 'Doe',
                      email: 'john.doe@example.com',
                      createdAt: '2023-01-15T10:30:00Z',
                      status: 'active'
                    }
                  }
                }
              }
            },
            headers: {
              'Location': {
                description: 'URL of the created user',
                schema: { type: 'string' }
              }
            }
          }
        }
      }
    }
  }
};

// SDK generation for multiple languages
class SDKGenerator {
  generateTypeScript(spec: OpenAPISpec): string {
    // Generate TypeScript client code
    return `
      export class APIClient {
        constructor(private baseURL: string, private apiKey: string) {}
        
        async createUser(user: CreateUserRequest): Promise<User> {
          const response = await fetch(\`\${this.baseURL}/users\`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': \`Bearer \${this.apiKey}\`
            },
            body: JSON.stringify(user)
          });
          
          if (!response.ok) {
            throw new APIError(await response.json());
          }
          
          return await response.json();
        }
      }
    `;
  }
}
```

## Conclusion

Modern API design requires balancing multiple concerns: performance, usability, maintainability, and evolution. The patterns explored here provide a foundation for building APIs that can grow with your application while providing excellent developer experience.

Key takeaways:
- Design your API contract first, before implementation
- Use consistent patterns for similar operations
- Implement comprehensive error handling and rate limiting
- Provide rich documentation with examples
- Plan for versioning and evolution from the start

Next in this series, we'll explore microservices communication patterns that build upon these API design principles to create resilient distributed systems.
