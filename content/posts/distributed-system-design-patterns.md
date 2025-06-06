---
title: "Distributed System Design Patterns in AWS"
date: 2021-02-07T09:00:00-05:00
tags: ["AWS", "Distributed Systems", "Microservices", "Patterns", "Resilience"]
series: "Cloud Architecture Patterns"
---

Distributed systems present unique challenges that require thoughtful application of proven design patterns to achieve reliability, scalability, and maintainability. Unlike monolithic applications where components communicate through in-process method calls, distributed systems must handle network partitions, variable latency, and partial failures as fundamental aspects of their operation. The patterns that emerge from these constraints form the foundation of robust cloud architectures, particularly when implemented using AWS's managed services ecosystem.

{{< plantuml id="circuit-breaker" >}}
@startuml Circuit Breaker Pattern
!define AWSPuml https://raw.githubusercontent.com/awslabs/aws-icons-for-plantuml/v14.0/dist
!include AWSPuml/AWSCommon.puml
!include AWSPuml/Compute/Lambda.puml
!include AWSPuml/Database/DynamoDBTable.puml
!include AWSPuml/ApplicationIntegration/APIGateway.puml
!include AWSPuml/ApplicationIntegration/SimpleQueueServiceQueue.puml
!include AWSPuml/ApplicationIntegration/SimpleNotificationServiceTopic.puml

skinparam BackgroundColor transparent
skinparam componentStyle rectangle
skinparam defaultTextAlignment center

package "Circuit Breaker Pattern Implementation" {
  component "API Gateway" as api #LightBlue
  component "Lambda Function" as lambda #LightBlue
  component "Circuit Breaker State" as state #Orange
  database "DynamoDB" as dynamodb #LightGreen
  component "External Service" as external #Pink
  queue "Fallback Queue" as fallbackQueue #LightYellow
  component "SNS Notification" as notification #LightCyan
}

note right of state
States:

- Closed: Normal operation
- Open: Failing fast
- Half-Open: Testing recovery
end note

api --> lambda : 1. Client Request
lambda --> state : 2. Check circuit state
state --> dynamodb : 3. Read/Update state
state -> external : 4a. If Closed/Half-Open: Call service
state --> fallbackQueue : 4b. If Open: Use fallback
external --> state : 5. Update success/failure count
state --> notification : 6. Circuit state change notification

note bottom of lambda
Tracks:

- Failure count
- Error threshold
- Reset timeout
- Last failure timestamp
end note

@enduml
{{< /plantuml >}}

The Circuit Breaker pattern addresses one of the most common failure modes in distributed systems: cascading failures caused by unhealthy dependencies. When a downstream service becomes unresponsive, continuing to send requests not only wastes resources but can propagate the failure upstream. A circuit breaker monitors failure rates and response times, automatically switching to an open state when thresholds are exceeded. AWS Application Load Balancer's health checking mechanisms provide a managed implementation of this pattern, automatically removing unhealthy targets from rotation and gradually reintroducing them as they recover.

Implementing circuit breakers at the application level using AWS Lambda provides fine-grained control over failure detection and recovery strategies. By maintaining circuit state in ElastiCache or DynamoDB, multiple Lambda instances can coordinate their behavior, ensuring consistent responses to downstream failures. The key insight is that circuit breakers should fail fast, providing immediate feedback rather than consuming resources on requests likely to fail. This rapid failure detection prevents resource exhaustion and provides clearer signal to monitoring systems about the nature of system degradation.

```typescript
// Circuit Breaker implementation using DynamoDB for state management
import { DynamoDBClient, GetItemCommand, PutItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

interface CircuitBreakerState {
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  failureCount: number;
  lastFailureTime: number;
  nextAttemptTime: number;
}

class DistributedCircuitBreaker {
  private client: DynamoDBClient;
  private tableName: string;
  private failureThreshold: number;
  private timeout: number;

  constructor(tableName: string, failureThreshold = 5, timeout = 60000) {
    this.client = new DynamoDBClient({});
    this.tableName = tableName;
    this.failureThreshold = failureThreshold;
    this.timeout = timeout;
  }

  async execute<T>(serviceKey: string, operation: () => Promise<T>): Promise<T> {
    const state = await this.getState(serviceKey);
    
    if (state.state === 'OPEN') {
      if (Date.now() < state.nextAttemptTime) {
        throw new Error('Circuit breaker is OPEN');
      }
      // Transition to HALF_OPEN for retry attempt
      await this.setState(serviceKey, { ...state, state: 'HALF_OPEN' });
    }

    try {
      const result = await operation();
      
      if (state.state === 'HALF_OPEN' || state.failureCount > 0) {
        // Reset on success
        await this.setState(serviceKey, {
          state: 'CLOSED',
          failureCount: 0,
          lastFailureTime: 0,
          nextAttemptTime: 0
        });
      }
      
      return result;
    } catch (error) {
      await this.recordFailure(serviceKey, state);
      throw error;
    }
  }

  private async getState(serviceKey: string): Promise<CircuitBreakerState> {
    try {
      const response = await this.client.send(new GetItemCommand({
        TableName: this.tableName,
        Key: marshall({ serviceKey })
      }));

      if (response.Item) {
        return unmarshall(response.Item) as CircuitBreakerState;
      }
    } catch (error) {
      // Handle DynamoDB errors gracefully
    }

    return {
      state: 'CLOSED',
      failureCount: 0,
      lastFailureTime: 0,
      nextAttemptTime: 0
    };
  }

  private async setState(serviceKey: string, state: CircuitBreakerState): Promise<void> {
    await this.client.send(new PutItemCommand({
      TableName: this.tableName,
      Item: marshall({ serviceKey, ...state })
    }));
  }

  private async recordFailure(serviceKey: string, currentState: CircuitBreakerState): Promise<void> {
    const newFailureCount = currentState.failureCount + 1;
    const now = Date.now();
    
    const newState: CircuitBreakerState = {
      state: newFailureCount >= this.failureThreshold ? 'OPEN' : 'CLOSED',
      failureCount: newFailureCount,
      lastFailureTime: now,
      nextAttemptTime: newFailureCount >= this.failureThreshold ? now + this.timeout : 0
    };

    await this.setState(serviceKey, newState);
  }
}

// Usage in Lambda function
export const handler = async (event: any) => {
  const circuitBreaker = new DistributedCircuitBreaker('circuit-breaker-state');
  
  try {
    const result = await circuitBreaker.execute('external-api', async () => {
      // Call to external service that might fail
      const response = await fetch('https://api.example.com/data');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      return response.json();
    });
    
    return { statusCode: 200, body: JSON.stringify(result) };
  } catch (error) {
    return { 
      statusCode: 503, 
      body: JSON.stringify({ error: 'Service temporarily unavailable' })
    };
  }
};
```

The Bulkhead pattern isolates system resources to prevent failures in one area from affecting others. In cloud architectures, this manifests as separate execution environments, data stores, and network paths for different system components. AWS accounts provide natural bulkheads, isolating blast radius at the infrastructure level. Within a single account, separate VPCs, subnets, and security groups create network-level isolation. At the application level, separate Lambda function sets, DynamoDB tables, and SQS queues ensure that high-traffic or failure-prone operations don't impact critical system functions.

{{< plantuml id="bulkhead-pattern" >}}
@startuml Bulkhead Pattern
!define AWSPuml "https://raw.githubusercontent.com/awslabs/aws-icons-for-plantuml/v14.0/dist"
!include AWSPuml/AWSCommon.puml
!include AWSPuml/Compute/Lambda.puml
!include AWSPuml/NetworkingContentDelivery/VPC.puml
!include AWSPuml/SecurityIdentityCompliance/WAF.puml
!include AWSPuml/General/Traditionalserver.puml
!include AWSPuml/Database/DynamoDBTable.puml
!include AWSPuml/ApplicationIntegration/SimpleQueueServiceQueue.puml

skinparam BackgroundColor transparent
skinparam defaultTextAlignment center

package "API Layer" {
  [API Gateway Rate Limiter] as api
}

package "Critical Services" {
  [Payment Processing] as payment #LightGreen
  [User Authentication] as auth #LightGreen
  database "User Data" as userDb #LightGreen
  queue "Critical Events Queue" as criticalQueue
  note right of payment
  Dedicated resources
  Higher provisioned capacity
  Lower concurrency limits
  end note
}

package "Standard Services" {
  [Product Catalog] as catalog #Yellow
  [Order History] as orderHistory #Yellow
  database "Product Data" as productDb #Yellow
  queue "Standard Events Queue" as standardQueue
}

package "Non-critical Services" {
  [Analytics] as analytics #LightSalmon
  [Recommendation Engine] as recommendations #LightSalmon
  database "Analytics Data" as analyticsDb #LightSalmon
  queue "Batch Processing Queue" as batchQueue
  note right of analytics
  Auto-scaling resources
  Lower priority
  Can be throttled under load
  end note
}

api -down-> payment : Rate limited
api -down-> auth : Rate limited
api -down-> catalog
api -down-> orderHistory
api -down-> analytics : Lower priority
api -down-> recommendations : Lower priority

payment -down-> userDb
auth -down-> userDb
payment -down-> criticalQueue
auth -down-> criticalQueue

catalog -down-> productDb
orderHistory -down-> productDb
catalog -down-> standardQueue
orderHistory -down-> standardQueue

analytics -down-> analyticsDb
recommendations -down-> analyticsDb
analytics -down-> batchQueue
recommendations -down-> batchQueue

note bottom of api
<b>Bulkhead Pattern:</b>
Isolates components to contain failures
and prioritizes resource allocation
end note

@enduml
{{< /plantuml >}}

Resource isolation extends beyond just compute and storage to include operational concerns like monitoring, alerting, and deployment pipelines. Separate CloudWatch log groups and metric namespaces prevent noisy components from obscuring critical signals. Independent deployment pipelines ensure that updates to experimental features don't risk core system stability. The economic aspect of bulkheads in AWS reflects the ability to apply different cost optimization strategies to different system components, using spot instances for batch processing while maintaining reserved capacity for latency-sensitive operations.

The Saga pattern coordinates long-running business processes that span multiple services without requiring distributed transactions. Traditional two-phase commit protocols don't scale well in cloud environments due to their blocking nature and assumption of reliable, low-latency communication. Sagas break complex operations into smaller, compensatable steps, using either choreography or orchestration to coordinate the overall process. AWS Step Functions provides a managed orchestration engine that handles state management, error handling, and retry logic for saga implementations.

Choreographed sagas rely on event-driven communication, where each service publishes events about its activities and subscribes to events relevant to its responsibilities. EventBridge facilitates this pattern by providing reliable event delivery and content-based routing. The distributed nature of choreographed sagas makes them resilient to individual service failures but can make the overall process flow difficult to understand and debug. Orchestrated sagas centralize the coordination logic, making the process more explicit but creating a potential single point of failure in the orchestrator.

Compensation logic in saga implementations must be carefully designed to handle partial failures and maintain business invariants. Not all operations can be truly reversed, particularly those involving external systems or real-world effects. Semantic compensation often involves recording the need for human intervention or implementing business policies that account for the complexity of distributed rollback scenarios. The stateful nature of saga coordination requires durable storage that survives individual service failures, making DynamoDB or RDS appropriate choices for maintaining saga state.

{{< plantuml id="saga-pattern" >}}
@startuml Saga Pattern
!define AWSPuml "https://raw.githubusercontent.com/awslabs/aws-icons-for-plantuml/v14.0/dist"
!include AWSPuml/AWSCommon.puml
!include AWSPuml/ApplicationIntegration/StepFunctions.puml
!include AWSPuml/Compute/Lambda.puml
!include AWSPuml/Database/DynamoDBTable.puml

skinparam BackgroundColor transparent
skinparam defaultTextAlignment center
skinparam sequenceArrowThickness 2
skinparam sequenceGroupBorderThickness 2

box "Order Processing Saga" #LightBlue
participant "Step Functions\nOrchestrator" as sfn
participant "Payment\nService" as payment
participant "Inventory\nService" as inventory
participant "Shipping\nService" as shipping
database "DynamoDB\nSaga State" as db
end box

note over sfn, db
<b>Orchestrated Saga Pattern</b>
Each transaction has a corresponding compensation
end note

sfn -> sfn : Start Order Saga
sfn -> payment : Reserve Payment
activate payment
payment -> payment : Process Payment
payment -> db : Record Payment Reserved
payment -> sfn : Payment Confirmation
deactivate payment

alt Success Path
sfn -> inventory : Reserve Inventory
activate inventory
inventory -> inventory : Check Stock
inventory -> db : Record Inventory Reserved
inventory -> sfn : Inventory Reserved
deactivate inventory

sfn -> shipping : Create Shipping Order
activate shipping
shipping -> shipping : Schedule Delivery
shipping -> db : Record Shipping Created
shipping -> sfn : Shipping Confirmed
deactivate shipping

sfn -> sfn : Order Confirmed
else Failure at Inventory Step
sfn -> inventory : Reserve Inventory
activate inventory
inventory -> inventory : Check Stock
inventory -> sfn : Insufficient Stock
deactivate inventory

sfn -> payment : Compensation: Release Payment
activate payment
payment -> payment : Refund Payment
payment -> db : Record Payment Released
payment -> sfn : Payment Released
deactivate payment

sfn -> sfn : Order Failed
else Failure at Shipping Step
sfn -> shipping : Create Shipping Order
activate shipping
shipping -> shipping : Schedule Delivery
shipping -> sfn : Delivery Unavailable
deactivate shipping

sfn -> inventory : Compensation: Release Inventory
activate inventory
inventory -> inventory : Return Items to Stock
inventory -> db : Record Inventory Released
inventory -> sfn : Inventory Released
deactivate inventory

sfn -> payment : Compensation: Release Payment
activate payment
payment -> payment : Refund Payment
payment -> db : Record Payment Released
payment -> sfn : Payment Released
deactivate payment

sfn -> sfn : Order Failed
end
@enduml
{{< /plantuml >}}

```typescript
// Saga pattern implementation using AWS Step Functions and Lambda
import { SFNClient, StartExecutionCommand } from '@aws-sdk/client-sfn';
import { DynamoDBClient, PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';

interface OrderSagaState {
  orderId: string;
  customerId: string;
  amount: number;
  step: 'STARTED' | 'PAYMENT_RESERVED' | 'INVENTORY_RESERVED' | 'COMPLETED' | 'COMPENSATING' | 'FAILED';
  compensationNeeded: string[];
}

// Step Functions State Machine Definition (JSON)
const orderSagaStateMachine = {
  "Comment": "Order processing saga with compensation",
  "StartAt": "ReservePayment",
  "States": {
    "ReservePayment": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:reservePayment",
      "Retry": [{ "ErrorEquals": ["States.TaskFailed"], "IntervalSeconds": 2, "MaxAttempts": 3 }],
      "Catch": [{ "ErrorEquals": ["States.ALL"], "Next": "CompensatePayment" }],
      "Next": "ReserveInventory"
    },
    "ReserveInventory": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:reserveInventory",
      "Retry": [{ "ErrorEquals": ["States.TaskFailed"], "IntervalSeconds": 2, "MaxAttempts": 3 }],
      "Catch": [{ "ErrorEquals": ["States.ALL"], "Next": "CompensateInventory" }],
      "Next": "ConfirmOrder"
    },
    "ConfirmOrder": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:confirmOrder",
      "End": true
    },
    "CompensateInventory": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:compensateInventory",
      "Next": "CompensatePayment"
    },
    "CompensatePayment": {
      "Type": "Task",
      "Resource": "arn:aws:lambda:region:account:function:compensatePayment",
      "Next": "OrderFailed"
    },
    "OrderFailed": {
      "Type": "Fail",
      "Cause": "Order processing failed"
    }
  }
};

// Lambda function for payment reservation step
export const reservePaymentHandler = async (event: OrderSagaState) => {
  const dynamoClient = new DynamoDBClient({});
  
  try {
    // Simulate payment service call
    await callPaymentService(event.customerId, event.amount);
    
    // Update saga state
    await dynamoClient.send(new UpdateItemCommand({
      TableName: 'OrderSagaState',
      Key: marshall({ orderId: event.orderId }),
      UpdateExpression: 'SET #step = :step, #compensation = list_append(#compensation, :action)',
      ExpressionAttributeNames: {
        '#step': 'step',
        '#compensation': 'compensationNeeded'
      },
      ExpressionAttributeValues: marshall({
        ':step': 'PAYMENT_RESERVED',
        ':action': ['RELEASE_PAYMENT']
      })
    }));

    return { ...event, step: 'PAYMENT_RESERVED' };
  } catch (error) {
    // Payment reservation failed
    throw new Error(`Payment reservation failed: ${error.message}`);
  }
};

// Lambda function for inventory reservation step
export const reserveInventoryHandler = async (event: OrderSagaState) => {
  const dynamoClient = new DynamoDBClient({});
  
  try {
    // Simulate inventory service call
    await callInventoryService(event.orderId);
    
    // Update saga state
    await dynamoClient.send(new UpdateItemCommand({
      TableName: 'OrderSagaState',
      Key: marshall({ orderId: event.orderId }),
      UpdateExpression: 'SET #step = :step, #compensation = list_append(#compensation, :action)',
      ExpressionAttributeNames: {
        '#step': 'step',
        '#compensation': 'compensationNeeded'
      },
      ExpressionAttributeValues: marshall({
        ':step': 'INVENTORY_RESERVED',
        ':action': ['RELEASE_INVENTORY']
      })
    }));

    return { ...event, step: 'INVENTORY_RESERVED' };
  } catch (error) {
    throw new Error(`Inventory reservation failed: ${error.message}`);
  }
};

// Compensation function for payment
export const compensatePaymentHandler = async (event: OrderSagaState) => {
  try {
    await releasePaymentReservation(event.customerId, event.amount);
    return { ...event, step: 'COMPENSATING' };
  } catch (error) {
    // Log compensation failure for manual intervention
    console.error(`Failed to compensate payment for order ${event.orderId}:`, error);
    throw error;
  }
};

// Helper functions (would be implemented based on actual services)
async function callPaymentService(customerId: string, amount: number): Promise<void> {
  // Implementation would call actual payment service
  if (Math.random() < 0.1) throw new Error('Payment service unavailable');
}

async function callInventoryService(orderId: string): Promise<void> {
  // Implementation would call actual inventory service
  if (Math.random() < 0.15) throw new Error('Insufficient inventory');
}

async function releasePaymentReservation(customerId: string, amount: number): Promise<void> {
  // Implementation would release payment hold
}
```

The Ambassador pattern encapsulates cross-cutting concerns like service discovery, load balancing, and protocol translation in a separate component that acts as a proxy for external communications. In AWS environments, this pattern often manifests through API Gateway, which provides authentication, rate limiting, and protocol transformation for backend services. The ambassador handles the complexity of service-to-service communication, allowing business logic to focus on domain concerns rather than infrastructure details.

Network-level ambassadors using AWS App Mesh provide sophisticated traffic management capabilities, including canary deployments, circuit breaking, and observability features. By deploying ambassadors as sidecars using ECS or EKS, applications gain these capabilities without code changes. The abstraction provided by ambassadors also facilitates testing by allowing mock services to be substituted transparently during development and integration testing phases.

The Strangler Fig pattern enables gradual migration from legacy systems by incrementally routing traffic to new implementations while maintaining backward compatibility. AWS's traffic management capabilities make this pattern particularly effective for cloud migrations. Route 53 weighted routing can gradually shift traffic percentages, while Application Load Balancer path-based routing can migrate individual features independently. The key to successful strangler fig implementations is maintaining interface compatibility during the transition period, often requiring facade services that translate between old and new data models.

Event sourcing and event-driven architectures support strangler fig migrations by providing a durable record of business events that can be replayed against new system implementations. This approach allows new systems to be validated against historical data without affecting production traffic. Kinesis Data Streams or EventBridge can serve as the event backbone, ensuring that both old and new systems receive the same business events during the transition period.

The Scatter-Gather pattern distributes requests across multiple services and aggregates responses, commonly used for search scenarios or when combining data from multiple sources. Lambda's concurrent execution model aligns well with this pattern, allowing multiple requests to be processed simultaneously without thread management complexity. The challenge lies in handling variable response times and partial failures while maintaining acceptable user experience. Implementing timeouts and fallback values ensures that slow or failed requests don't block the overall response.

{{< plantuml id="scatter-gather-pattern" >}}
@startuml Scatter-Gather Pattern
!define AWSPuml "https://raw.githubusercontent.com/awslabs/aws-icons-for-plantuml/v14.0/dist"
!include AWSPuml/AWSCommon.puml
!include AWSPuml/Compute/Lambda.puml
!include AWSPuml/ApplicationIntegration/APIGateway.puml
!include AWSPuml/Database/DynamoDB.puml
!include AWSPuml/Storage/SimpleStorageService.puml
!include AWSPuml/MachineLearning/ElasticInference.puml
!include AWSPuml/ApplicationIntegration/EventBridge.puml
!include AWSPuml/ManagementGovernance/CloudWatch.puml

skinparam BackgroundColor transparent
skinparam defaultTextAlignment center
skinparam sequenceArrowThickness 2
skinparam sequenceGroupBorderThickness 2

actor "Client" as client
participant "API Gateway" as api
participant "Aggregator\nLambda" as aggregator
participant "Product Search\nService" as products
participant "User History\nService" as history
participant "Recommendations\nService" as recommendations
participant "External API\nService" as external
collections "Results\nCollector" as results

api -> aggregator : Search Request
activate aggregator

note right of aggregator
<b>Scatter Phase:</b>
Send parallel requests with timeouts
end note

par
aggregator -> products : Query Products
activate products
else
aggregator -> history : Query User History
activate history
else
aggregator -> recommendations : Get Recommendations
activate recommendations
else
aggregator -> external : External API Call
activate external
end

products --> aggregator : Product Results (200ms)
deactivate products

history --> aggregator : History Results (150ms)
deactivate history

recommendations --> aggregator : Recommendation Results (300ms)
deactivate recommendations

alt Successful case
external --> aggregator : External API Results (180ms)
deactivate external
else Timeout/Failure case
aggregator -> aggregator : Timeout after 400ms
note right of aggregator
External service too slow
Use fallback results
end note
end

note right of aggregator
<b>Gather Phase:</b>
Combine results, handle missing data
end note

loop For each result set
aggregator -> results : Add to Combined Results
activate results
results -> results : Sort by Relevance
results -> results : Remove Duplicates
results -> aggregator : Processed Results
deactivate results
end

aggregator -> api : Aggregated Response
deactivate aggregator

api -> client : Search Results

note bottom of aggregator
Handles:

- Service failures
- Timeouts
- Partial results
- Priority merging
end note

@enduml
{{< /plantuml >}}

DynamoDB's parallel scan capabilities provide infrastructure-level support for scatter-gather patterns when querying large datasets. By distributing scan operations across multiple segments and aggregating results, applications can achieve higher throughput than sequential scanning would allow. The eventual consistency model of DynamoDB requires careful consideration of read consistency requirements in scatter-gather scenarios.

Observability in distributed systems requires correlation of activities across service boundaries, typically through distributed tracing and correlation identifiers. AWS X-Ray provides managed distributed tracing that automatically captures service maps and latency distributions. Implementing correlation IDs that flow through request chains enables log correlation across services, making it possible to understand complex distributed operations. CloudWatch Insights queries can correlate logs across multiple services using these correlation identifiers, providing end-to-end visibility into distributed operations.

The performance characteristics of distributed systems differ fundamentally from monolithic applications due to network latency and serialization overhead. Designing for network efficiency often involves batching operations, using compression, and minimizing round trips. AWS services like SQS batch operations and DynamoDB batch writes provide infrastructure support for efficient distributed operations. Understanding the latency characteristics of different AWS regions and availability zones helps inform service placement decisions that minimize communication overhead.

Error handling in distributed systems must account for the complexity of partial failures and network partitions. Implementing idempotency ensures that retry operations don't cause unintended side effects. Using exponential backoff with jitter prevents thundering herd problems when multiple clients retry simultaneously. DynamoDB's conditional writes and SQS's exactly-once processing provide infrastructure-level support for idempotent operations, reducing the complexity of implementing these patterns at the application level.
