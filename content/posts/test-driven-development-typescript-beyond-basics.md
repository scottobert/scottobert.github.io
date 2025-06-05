---
title: "Test-Driven Development in TypeScript: Beyond the Basics"
date: 2021-08-15T09:00:00-07:00
draft: false
categories: ["Software Development", "Testing"]
tags:
- TypeScript
- Testing
- TDD
- Development
- Best Practices
series: "Modern Development Practices"
---

Test-Driven Development (TDD) has evolved significantly with modern TypeScript tooling and frameworks. While most developers understand the basic red-green-refactor cycle, mastering TDD in TypeScript requires understanding advanced patterns, effective mocking strategies, and leveraging the type system for better test design.

## Beyond Basic TDD: Advanced Patterns

### Type-Driven Test Design

TypeScript's type system provides unique opportunities to improve test design. Instead of just testing implementation details, we can use types to guide our test structure and ensure comprehensive coverage:

```typescript
// Define clear interfaces for testability
interface UserRepository {
  findById(id: string): Promise<User | null>;
  save(user: User): Promise<User>;
  delete(id: string): Promise<void>;
}

interface EmailService {
  sendWelcomeEmail(user: User): Promise<void>;
}

// The service under test
class UserService {
  constructor(
    private userRepo: UserRepository,
    private emailService: EmailService
  ) {}

  async createUser(userData: CreateUserRequest): Promise<User> {
    // Implementation details
  }
}
```

This approach makes dependencies explicit and testable while the type system prevents many runtime errors during testing.

### Property-Based Testing with TypeScript

Move beyond example-based tests to property-based testing using libraries like `fast-check`:

```typescript
import fc from 'fast-check';

describe('UserValidator', () => {
  it('should validate email format for any string input', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const result = UserValidator.isValidEmail(input);
        if (result) {
          expect(input).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
        }
        return true;
      })
    );
  });

  it('should handle edge cases in user data', () => {
    const userDataArbitrary = fc.record({
      name: fc.string({ minLength: 1, maxLength: 100 }),
      age: fc.integer({ min: 0, max: 150 }),
      email: fc.emailAddress()
    });

    fc.assert(
      fc.property(userDataArbitrary, (userData) => {
        const result = UserValidator.validate(userData);
        expect(result.isValid).toBe(true);
      })
    );
  });
});
```

### Advanced Mocking Strategies

Effective mocking in TypeScript goes beyond simple jest.fn(). Create type-safe mocks that evolve with your interfaces:

```typescript
type MockType<T> = {
  [P in keyof T]?: jest.MockedFunction<T[P]>;
};

function createMockRepository(): MockType<UserRepository> {
  return {
    findById: jest.fn(),
    save: jest.fn(),
    delete: jest.fn()
  };
}

describe('UserService', () => {
  let userService: UserService;
  let mockUserRepo: MockType<UserRepository>;
  let mockEmailService: MockType<EmailService>;

  beforeEach(() => {
    mockUserRepo = createMockRepository();
    mockEmailService = { sendWelcomeEmail: jest.fn() };
    userService = new UserService(
      mockUserRepo as UserRepository,
      mockEmailService as EmailService
    );
  });

  it('should save user and send welcome email', async () => {
    const userData = { name: 'John', email: 'john@example.com' };
    const savedUser = { id: '123', ...userData };
    
    mockUserRepo.save?.mockResolvedValue(savedUser);
    mockEmailService.sendWelcomeEmail?.mockResolvedValue();

    const result = await userService.createUser(userData);

    expect(mockUserRepo.save).toHaveBeenCalledWith(
      expect.objectContaining(userData)
    );
    expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith(savedUser);
    expect(result).toEqual(savedUser);
  });
});
```

## Testing Async Patterns

### Testing Complex Async Flows

Modern applications involve complex async operations. Structure tests to handle these patterns effectively:

```typescript
describe('OrderProcessingService', () => {
  it('should handle concurrent order processing', async () => {
    const orders = Array.from({ length: 5 }, (_, i) => 
      createTestOrder({ id: `order-${i}` })
    );

    // Start all processing concurrently
    const processingPromises = orders.map(order => 
      orderService.processOrder(order)
    );

    const results = await Promise.allSettled(processingPromises);

    // Verify all succeeded
    results.forEach((result, index) => {
      expect(result.status).toBe('fulfilled');
      if (result.status === 'fulfilled') {
        expect(result.value.status).toBe('PROCESSED');
      }
    });

    // Verify side effects
    expect(mockPaymentService.charge).toHaveBeenCalledTimes(5);
    expect(mockInventoryService.reserve).toHaveBeenCalledTimes(5);
  });
});
```

### Testing Error Boundaries

Design tests that verify error handling and recovery:

```typescript
describe('Resilient Service Operations', () => {
  it('should retry on transient failures', async () => {
    mockExternalService.processRequest
      .mockRejectedValueOnce(new TransientError('Network timeout'))
      .mockRejectedValueOnce(new TransientError('Service unavailable'))
      .mockResolvedValue({ success: true });

    const result = await resilientService.processWithRetry(testData);

    expect(result.success).toBe(true);
    expect(mockExternalService.processRequest).toHaveBeenCalledTimes(3);
  });

  it('should fail fast on permanent errors', async () => {
    mockExternalService.processRequest
      .mockRejectedValue(new PermanentError('Invalid credentials'));

    await expect(
      resilientService.processWithRetry(testData)
    ).rejects.toThrow('Invalid credentials');

    expect(mockExternalService.processRequest).toHaveBeenCalledTimes(1);
  });
});
```

## Integration Testing Strategies

### Database Integration Tests

For TypeScript applications using ORMs, create focused integration tests:

```typescript
describe('User Repository Integration', () => {
  let repository: UserRepository;
  let testDb: TestDatabase;

  beforeAll(async () => {
    testDb = await TestDatabase.create();
    repository = new TypeORMUserRepository(testDb.connection);
  });

  afterAll(async () => {
    await testDb.cleanup();
  });

  beforeEach(async () => {
    await testDb.clearTables(['users']);
  });

  it('should persist and retrieve user data correctly', async () => {
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      preferences: { theme: 'dark', notifications: true }
    };

    const savedUser = await repository.save(userData);
    expect(savedUser.id).toBeDefined();

    const retrievedUser = await repository.findById(savedUser.id);
    expect(retrievedUser).toMatchObject(userData);
    expect(retrievedUser?.preferences).toEqual(userData.preferences);
  });
});
```

### API Integration Tests

Test your TypeScript APIs with type-safe request/response validation:

```typescript
import request from 'supertest';
import { app } from '../src/app';

describe('User API Integration', () => {
  it('should create and return user with correct types', async () => {
    const userData = {
      name: 'Jane Doe',
      email: 'jane@example.com'
    };

    const response = await request(app)
      .post('/users')
      .send(userData)
      .expect(201);

    // Type-safe response validation
    const createdUser: User = response.body;
    expect(createdUser.id).toMatch(/^user-[a-z0-9]+$/);
    expect(createdUser.name).toBe(userData.name);
    expect(createdUser.email).toBe(userData.email);
    expect(createdUser.createdAt).toBeDefined();
  });
});
```

## Test Organization and Maintenance

### Hierarchical Test Structure

Organize tests to reflect your domain model and make them easier to maintain:

```typescript
describe('User Management Domain', () => {
  describe('User Creation', () => {
    describe('with valid data', () => {
      it('should create user successfully');
      it('should send welcome email');
      it('should log creation event');
    });

    describe('with invalid data', () => {
      it('should reject missing email');
      it('should reject invalid email format');
      it('should reject duplicate email');
    });
  });

  describe('User Updates', () => {
    describe('profile updates', () => {
      it('should update allowed fields');
      it('should preserve read-only fields');
    });
  });
});
```

### Test Data Management

Create maintainable test data factories:

```typescript
class UserTestDataBuilder {
  private user: Partial<User> = {};

  withName(name: string): this {
    this.user.name = name;
    return this;
  }

  withEmail(email: string): this {
    this.user.email = email;
    return this;
  }

  withRole(role: UserRole): this {
    this.user.role = role;
    return this;
  }

  build(): User {
    return {
      id: this.user.id || generateUserId(),
      name: this.user.name || 'Test User',
      email: this.user.email || 'test@example.com',
      role: this.user.role || UserRole.STANDARD,
      createdAt: new Date(),
      ...this.user
    };
  }
}

// Usage in tests
const testUser = new UserTestDataBuilder()
  .withName('Admin User')
  .withRole(UserRole.ADMIN)
  .build();
```

## Performance and Scalability Testing

### Testing Performance Characteristics

Include performance assertions in your test suite:

```typescript
describe('Performance Requirements', () => {
  it('should process large datasets efficiently', async () => {
    const largeDataset = Array.from({ length: 1000 }, (_, i) => 
      createTestRecord(i)
    );

    const startTime = performance.now();
    const results = await dataProcessor.processAll(largeDataset);
    const endTime = performance.now();

    expect(endTime - startTime).toBeLessThan(1000); // 1 second max
    expect(results).toHaveLength(1000);
    expect(results.every(r => r.processed)).toBe(true);
  });
});
```

## Conclusion

Advanced TDD in TypeScript leverages the type system to create more robust, maintainable tests. By combining property-based testing, sophisticated mocking strategies, and comprehensive integration testing, you can build confidence in your codebase while maintaining development velocity.

The key is to treat your tests as first-class citizens in your codebase—they should be as well-designed, type-safe, and maintainable as your production code. This investment pays dividends in reduced debugging time, easier refactoring, and higher-quality software.

Next in this series, we'll explore how to automate code quality enforcement through gates and continuous integration, building on the solid testing foundation we've established here.
