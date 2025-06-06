---
title: "Real-time Data Synchronization: Using DynamoDB Streams and Lambda to Keep OpenSearch Indexes Current"
date: 2025-06-06T09:00:00-05:00
draft: false
categories: ["serverless", "data-engineering", "cloud-computing"]
tags: ["DynamoDB", "Lambda", "OpenSearch", "AWS", "real-time", "search", "TypeScript", "streams"]
---

Building modern applications often requires the ability to perform full-text searches with fuzzy matching capabilities on data that's primarily stored in NoSQL databases like DynamoDB. While DynamoDB excels at fast key-based lookups and can handle massive scale, it lacks the sophisticated search capabilities that applications need for features like autocomplete, typo-tolerant search, and complex text analysis. OpenSearch (the open-source fork of Elasticsearch) provides these advanced search capabilities, but keeping it synchronized with your primary data store presents unique challenges.

The combination of DynamoDB Streams and AWS Lambda offers an elegant solution for maintaining real-time synchronization between your transactional database and search index. This architectural pattern enables you to leverage DynamoDB's performance and scalability for your primary data operations while providing rich search experiences through OpenSearch, all while maintaining data consistency and proper ordering of updates.

{{< plantuml >}}
@startuml DynamoDB to OpenSearch Sync Architecture

skinparam rectangle {
    BackgroundColor lightblue
    BorderColor darkblue
}

skinparam database {
    BackgroundColor lightgreen
    BorderColor darkgreen
}

skinparam queue {
    BackgroundColor lightyellow
    BorderColor orange
}

left to right direction

rectangle "Application Layer" as app {
  rectangle "Client Application" as client
}

rectangle "Data Layer" as data {
  database "DynamoDB\nTable" as dynamodb
  database "OpenSearch\nCluster" as opensearch
}

rectangle "Processing Layer" as processing {
  rectangle "Stream Processor\nLambda" as streamProcessor
  queue "Dead Letter\nQueue" as dlq
}

client --> dynamodb : "Write Operations\n(PUT, UPDATE, DELETE)"
dynamodb --> streamProcessor : "DynamoDB Stream\nEvents with\nSequenceNumber"
streamProcessor --> opensearch : "Index/Update/Delete\nDocuments"
streamProcessor --> dlq : "Failed Events\nfor Retry"

note right of streamProcessor
  Processes events in order using SequenceNumber
  Handles INSERT, MODIFY, REMOVE events
  Implements retry logic with exponential backoff
  Transforms DynamoDB items to OpenSearch documents
end note

@enduml
{{< /plantuml >}}

## Understanding DynamoDB Streams and Event Ordering

DynamoDB Streams capture data modification events in your DynamoDB tables in near real-time. When you enable a stream on a table, DynamoDB writes a stream record whenever an application creates, updates, or deletes items in that table. Each stream record appears exactly once in the stream, and the records appear in the same sequence as the actual modifications to the DynamoDB table.

The critical aspect for maintaining data consistency is understanding how DynamoDB Streams handle ordering through the SequenceNumber. Each stream record contains a SequenceNumber that determines the order in which the events were written to the stream. This sequence number is crucial because it ensures that if multiple updates happen to the same item in rapid succession, they are processed in the correct order to maintain consistency between your DynamoDB table and OpenSearch index.

### SequenceNumber Properties and Ordering

SequenceNumbers in DynamoDB Streams have specific characteristics that are essential to understand for proper event processing:

- **String Format**: SequenceNumbers are strings with a length between 21 and 40 characters that can be compared lexicographically to determine order
- **Shard-Level Uniqueness**: Each SequenceNumber is unique per partition key within a shard, ensuring deterministic ordering for records affecting the same item
- **Lexicographic Ordering**: You can compare SequenceNumbers using standard string comparison operators to determine chronological order
- **Partition Key Grouping**: Events for the same partition key are guaranteed to be processed in order within a single shard

However, there's an important nuance to understand about ordering guarantees. DynamoDB Streams only guarantee ordering at the shard level, not across the entire stream. This means that events for different partition keys might be processed out of order relative to each other, but events for the same partition key will always be processed in the correct sequence. For most applications, this shard-level ordering is sufficient because it ensures that updates to individual records are processed correctly.

## Implementing the Lambda Stream Processor

The Lambda function that processes DynamoDB stream events serves as the bridge between your primary data store and search index. This function must handle three types of events: INSERT (when new items are added), MODIFY (when existing items are updated), and REMOVE (when items are deleted). Each event type requires different handling in OpenSearch to maintain synchronization.

Here's a robust implementation of a stream processor using AWS SDK v3:

```typescript
import { DynamoDBStreamEvent, DynamoDBRecord, Context } from 'aws-lambda';
import { OpenSearchClient, IndexCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/client-opensearch';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';

interface ProductDocument {
  id: string;
  name: string;
  description: string;
  category: string;
  price: number;
  tags: string[];
  searchText: string;
  lastModified: string;
  sequenceNumber: string;
}

interface ProcessingState {
  lastProcessedSequence: string;
  timestamp: string;
}

class StreamProcessor {
  private openSearchClient: OpenSearchClient;
  private sqsClient: SQSClient;
  private dynamoClient: DynamoDBDocumentClient;
  private deadLetterQueueUrl: string;
  private openSearchIndexName: string;
  private stateTableName: string;

  constructor() {
    this.openSearchClient = new OpenSearchClient({
      region: process.env.AWS_REGION,
      endpoint: process.env.OPENSEARCH_ENDPOINT,
    });
    
    this.sqsClient = new SQSClient({ region: process.env.AWS_REGION });
    this.dynamoClient = DynamoDBDocumentClient.from(new DynamoDBClient({ 
      region: process.env.AWS_REGION 
    }));
    this.deadLetterQueueUrl = process.env.DEAD_LETTER_QUEUE_URL!;
    this.openSearchIndexName = process.env.OPENSEARCH_INDEX_NAME!;
    this.stateTableName = process.env.PROCESSING_STATE_TABLE_NAME!;
  }

  async processRecord(record: DynamoDBRecord): Promise<void> {
    const eventName = record.eventName;
    const sequenceNumber = record.dynamodb?.SequenceNumber;
    const itemKey = this.extractItemKey(record);
    
    if (!sequenceNumber) {
      throw new Error('Missing SequenceNumber in stream record');
    }

    // Check if this record should be processed based on sequence ordering
    const shouldProcess = await this.shouldProcessRecord(itemKey, sequenceNumber);
    if (!shouldProcess) {
      console.log(`Skipping out-of-order record for key ${itemKey}, sequence ${sequenceNumber}`);
      return;
    }

    try {
      switch (eventName) {
        case 'INSERT':
          await this.handleInsert(record, sequenceNumber);
          break;
        case 'MODIFY':
          await this.handleModify(record, sequenceNumber);
          break;
        case 'REMOVE':
          await this.handleRemove(record, sequenceNumber);
          break;
        default:
          console.warn(`Unknown event type: ${eventName}`);
      }

      // Update the last processed sequence for this item
      await this.updateLastProcessedSequence(itemKey, sequenceNumber);
    } catch (error) {
      console.error(`Failed to process record with sequence ${sequenceNumber}:`, error);
      throw error;
    }
  }

  private extractItemKey(record: DynamoDBRecord): string {
    // Extract the primary key from the record to group sequences per item
    const keys = record.dynamodb?.Keys;
    if (!keys) {
      throw new Error('Missing Keys in stream record');
    }
    
    // Create a composite key from all primary key attributes
    const keyParts = Object.entries(keys).map(([attr, value]) => {
      const val = value.S || value.N || value.B || JSON.stringify(value);
      return `${attr}:${val}`;
    });
    
    return keyParts.join('#');
  }

  private async shouldProcessRecord(itemKey: string, sequenceNumber: string): Promise<boolean> {
    try {
      const response = await this.dynamoClient.send(new GetCommand({
        TableName: this.stateTableName,
        Key: { itemKey }
      }));

      if (!response.Item) {
        // First time processing this item
        return true;
      }      const lastProcessedSequence = response.Item.lastProcessedSequence;
      
      // Compare sequence numbers (they are strings that can be compared lexicographically)
      // SequenceNumbers maintain ordering within a shard for a given partition key
      return this.compareSequenceNumbers(sequenceNumber, lastProcessedSequence) > 0;
    } catch (error) {
      console.error(`Error checking processing state for ${itemKey}:`, error);
      // On error, allow processing to continue but log the issue
      return true;
    }
  }
  private compareSequenceNumbers(seq1: string, seq2: string): number {
    // SequenceNumbers are strings that can be compared lexicographically
    // They are unique per partition-key within a shard and maintain ordering
    if (seq1 < seq2) return -1;
    if (seq1 > seq2) return 1;
    return 0;
  }

  private async updateLastProcessedSequence(itemKey: string, sequenceNumber: string): Promise<void> {
    try {
      await this.dynamoClient.send(new PutCommand({
        TableName: this.stateTableName,
        Item: {
          itemKey,
          lastProcessedSequence: sequenceNumber,
          timestamp: new Date().toISOString()
        }
      }));
    } catch (error) {
      console.error(`Failed to update processing state for ${itemKey}:`, error);
      // Don't throw here as the main operation succeeded
    }
  }
  private async handleInsert(record: DynamoDBRecord, sequenceNumber: string): Promise<void> {
    const newImage = record.dynamodb?.NewImage;
    if (!newImage) return;

    const document = this.transformToSearchDocument(newImage, sequenceNumber);
    
    const command = new IndexCommand({
      index: this.openSearchIndexName,
      id: document.id,
      body: document,
      refresh: 'wait_for', // Ensure document is immediately searchable
    });

    await this.executeWithRetry(() => this.openSearchClient.send(command));
  }

  private async handleModify(record: DynamoDBRecord, sequenceNumber: string): Promise<void> {
    const newImage = record.dynamodb?.NewImage;
    if (!newImage) return;

    const document = this.transformToSearchDocument(newImage, sequenceNumber);
    
    // Check if we have a newer version already indexed
    const existingDoc = await this.getExistingDocument(document.id);
    if (existingDoc && this.compareSequenceNumbers(sequenceNumber, existingDoc.sequenceNumber) <= 0) {
      console.log(`Skipping update for ${document.id} - newer version already indexed`);
      return;
    }
    
    // Use update with doc_as_upsert to handle cases where document might not exist
    const command = new UpdateCommand({
      index: this.openSearchIndexName,
      id: document.id,
      body: {
        doc: document,
        doc_as_upsert: true,
      },
      refresh: 'wait_for',
    });

    await this.executeWithRetry(() => this.openSearchClient.send(command));
  }

  private async handleRemove(record: DynamoDBRecord, sequenceNumber: string): Promise<void> {
    const oldImage = record.dynamodb?.OldImage;
    if (!oldImage?.id?.S) return;

    const documentId = oldImage.id.S;
    
    // Check if we have a newer version that was created after this delete
    const existingDoc = await this.getExistingDocument(documentId);
    if (existingDoc && this.compareSequenceNumbers(sequenceNumber, existingDoc.sequenceNumber) < 0) {
      console.log(`Skipping delete for ${documentId} - newer version exists`);
      return;
    }

    const command = new DeleteCommand({
      index: this.openSearchIndexName,
      id: documentId,
      refresh: 'wait_for',
    });

    try {
      await this.executeWithRetry(() => this.openSearchClient.send(command));
    } catch (error: any) {
      // Ignore 404 errors for delete operations as the document might already be gone
      if (error.statusCode !== 404) {
        throw error;
      }
    }
  }

  private async getExistingDocument(id: string): Promise<ProductDocument | null> {
    try {
      const response = await this.openSearchClient.send({
        method: 'GET',
        path: `/${this.openSearchIndexName}/_doc/${id}`,
      });
      
      return response.body._source || null;
    } catch (error: any) {
      if (error.statusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  private transformToSearchDocument(dynamoImage: any, sequenceNumber: string): ProductDocument {
    // Create a searchable text field combining multiple attributes
    const searchableFields = [
      dynamoImage.name?.S || '',
      dynamoImage.description?.S || '',
      dynamoImage.category?.S || '',
      ...(dynamoImage.tags?.SS || [])
    ];

    return {
      id: dynamoImage.id.S,
      name: dynamoImage.name?.S || '',
      description: dynamoImage.description?.S || '',
      category: dynamoImage.category?.S || '',
      price: dynamoImage.price?.N ? parseFloat(dynamoImage.price.N) : 0,
      tags: dynamoImage.tags?.SS || [],
      searchText: searchableFields.join(' ').toLowerCase(),
      lastModified: new Date().toISOString(),
      sequenceNumber: sequenceNumber, // Store the sequence number for ordering checks
    };
  }

  private async executeWithRetry<T>(operation: () => Promise<T>, maxRetries = 3): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error: any) {
        lastError = error;
        
        if (attempt === maxRetries) break;
        
        // Exponential backoff with jitter
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000) + Math.random() * 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    throw lastError!;
  }

  private async sendToDeadLetterQueue(record: DynamoDBRecord, error: Error): Promise<void> {
    const message = {
      record,
      error: error.message,
      timestamp: new Date().toISOString(),
      sequenceNumber: record.dynamodb?.SequenceNumber,
    };

    const command = new SendMessageCommand({
      QueueUrl: this.deadLetterQueueUrl,
      MessageBody: JSON.stringify(message),
    });

    await this.sqsClient.send(command);
  }
}

export const handler = async (event: DynamoDBStreamEvent, context: Context): Promise<void> => {
  const processor = new StreamProcessor();
  const failures: any[] = [];
  // Sort records by sequence number within each shard to ensure proper ordering
  const sortedRecords = event.Records.sort((a, b) => {
    const seqA = a.dynamodb?.SequenceNumber || '';
    const seqB = b.dynamodb?.SequenceNumber || '';
    
    // Compare sequence numbers lexicographically for proper ordering
    return seqA.localeCompare(seqB);
  });

  // Process records sequentially to maintain ordering per shard
  for (const record of sortedRecords) {
    try {
      await processor.processRecord(record);
    } catch (error: any) {
      console.error(`Failed to process record ${record.dynamodb?.SequenceNumber}:`, error);
      await processor.sendToDeadLetterQueue(record, error);
      failures.push({
        itemIdentifier: record.dynamodb?.Keys,
        errorCode: error.name,
        errorMessage: error.message,
        sequenceNumber: record.dynamodb?.SequenceNumber,
      });
    }
  }

  // If there were failures, throw an error with details
  // This will cause Lambda to retry the entire batch
  if (failures.length > 0) {
    throw new Error(`Failed to process ${failures.length} records: ${JSON.stringify(failures)}`);
  }
};
```

## Critical Considerations for SequenceNumber Handling

The SequenceNumber in DynamoDB stream records is not just a timestamp or incrementing counter—it's a string value that represents the precise order of writes within a shard. Understanding how to properly handle these sequence numbers is crucial for maintaining data consistency, especially when dealing with rapid updates to the same item or when implementing custom retry mechanisms.

When Lambda processes stream events, it automatically handles the complexity of checkpointing and resuming from the correct position using these sequence numbers. However, there are scenarios where you need to be particularly careful. If your Lambda function fails partway through processing a batch of records, Lambda will retry the entire batch starting from the earliest unprocessed sequence number. This means your processing logic must be idempotent—running the same operation multiple times should produce the same result.

For OpenSearch operations, achieving idempotency requires careful consideration of how you structure your index operations. Using the DynamoDB item's primary key as the OpenSearch document ID ensures that repeated index operations will update the same document rather than creating duplicates. Additionally, including a version field or timestamp in your documents can help you implement optimistic concurrency control if needed.

One common pitfall occurs when developers attempt to implement custom batching or reordering of stream events based on their own logic rather than trusting DynamoDB's sequence numbers. This approach almost invariably leads to race conditions and data inconsistencies. The sequence number provides the authoritative ordering within each shard, and any custom reordering should only be done with extreme caution and thorough testing.

## Advanced Error Handling and Recovery Strategies

Production systems require sophisticated error handling strategies that go beyond simple retry logic. Network timeouts, OpenSearch cluster unavailability, and temporary capacity constraints are common issues that your stream processor must handle gracefully without losing data or breaking the synchronization between your stores.

The implementation above includes a dead letter queue pattern for handling records that consistently fail to process. This pattern is essential because DynamoDB Streams have a 24-hour retention period—if a record cannot be processed within that window, it will be lost forever. By sending failed records to a dead letter queue, you create an opportunity for manual intervention or automated recovery processes to handle these edge cases.

When implementing retry logic, consider the nature of different types of errors. Transient network errors or temporary capacity constraints should be retried with exponential backoff, while authentication errors or malformed data should be sent directly to the dead letter queue since retrying won't resolve these issues. The retry strategy should also consider the Lambda function's execution time limits—complex retry logic that takes too long might cause the function to timeout and restart, leading to duplicate processing.

For scenarios where you need guaranteed exactly-once processing semantics, consider implementing a custom deduplication mechanism using a separate DynamoDB table to track processed sequence numbers. While this adds complexity, it can be necessary for financial or other critical applications where duplicate processing could have serious consequences.

## Optimizing OpenSearch Performance and Index Design

The design of your OpenSearch index significantly impacts both the performance of your synchronization process and the quality of your search results. When designing your index mapping, consider how your data will be searched and optimize the field types and analyzers accordingly. Text fields that will be used for fuzzy matching should use appropriate analyzers that can handle stemming, synonyms, and phonetic matching.

```typescript
const indexMapping = {
  mappings: {
    properties: {
      id: { type: 'keyword' },
      name: {
        type: 'text',
        analyzer: 'standard',
        fields: {
          keyword: { type: 'keyword' },
          suggest: {
            type: 'completion',
            analyzer: 'simple',
          }
        }
      },
      description: {
        type: 'text',
        analyzer: 'english',
      },
      searchText: {
        type: 'text',
        analyzer: 'standard',
        search_analyzer: 'fuzzy_search_analyzer',
      },
      category: { type: 'keyword' },
      price: { type: 'double' },
      tags: { type: 'keyword' },
      lastModified: { type: 'date' },
    }
  },
  settings: {
    analysis: {
      analyzer: {
        fuzzy_search_analyzer: {
          tokenizer: 'standard',
          filter: ['lowercase', 'asciifolding', 'fuzzy_filter']
        }
      },
      filter: {
        fuzzy_filter: {
          type: 'phonetic',
          encoder: 'soundex'
        }
      }
    }
  }
};
```

Bulk operations can significantly improve the performance of your synchronization process when handling high-volume updates. Instead of sending individual index requests for each stream record, consider accumulating changes and using OpenSearch's bulk API. However, be careful to balance batch size with latency requirements—larger batches are more efficient but increase the time between when data changes in DynamoDB and when it becomes searchable in OpenSearch.

## Monitoring and Observability

Effective monitoring is essential for maintaining a reliable real-time synchronization system. Key metrics to track include the age of the oldest unprocessed stream record (stream lag), the rate of processing errors, OpenSearch indexing latency, and the Lambda function's duration and memory usage. CloudWatch custom metrics can provide insights into your application-specific concerns, such as the number of documents processed per minute or the average time between DynamoDB writes and OpenSearch availability.

Set up alarms for critical conditions such as stream lag exceeding acceptable thresholds, error rates climbing above normal levels, or dead letter queue messages accumulating. These early warning systems allow you to address issues before they impact user experience. Consider implementing health check endpoints that can verify the synchronization status by comparing record counts or checksums between DynamoDB and OpenSearch.

Distributed tracing using AWS X-Ray can provide valuable insights into the end-to-end flow of data through your system, helping you identify bottlenecks and optimize performance. Correlation IDs that flow from the initial DynamoDB write through the stream processing to the final OpenSearch indexing can help you trace individual requests and debug issues.

## Testing Strategies for Stream Processing

Testing real-time data synchronization systems presents unique challenges because of their asynchronous, event-driven nature. Unit tests should cover the core transformation logic and error handling scenarios, while integration tests need to verify the end-to-end flow from DynamoDB writes to OpenSearch updates. Consider using tools like LocalStack or DynamoDB Local to create reproducible test environments that don't require AWS resources.

Event ordering tests are particularly important because race conditions and ordering issues often only manifest under high load or specific timing conditions. Create tests that simulate rapid updates to the same DynamoDB item and verify that the final state in OpenSearch matches the expected result. Use controlled delays and forced failures to test your error handling and recovery mechanisms.

Load testing should simulate realistic traffic patterns and include scenarios such as sudden spikes in write volume, temporary OpenSearch unavailability, and Lambda cold starts. These tests help you understand the system's behavior under stress and identify capacity planning requirements.

## Common Pitfalls and Best Practices

Many teams underestimate the complexity of maintaining consistency between different data stores with different consistency models and performance characteristics. DynamoDB provides strong consistency for reads immediately after writes within the same region, but DynamoDB Streams operate on an eventually consistent model. This means there can be a delay between when data is written to DynamoDB and when the corresponding stream event is generated, though this delay is typically measured in milliseconds.

Another common mistake is assuming that stream events will always contain complete item data. Depending on your stream view type configuration, you might only receive the changed attributes rather than the full item. When using KEYS_ONLY or OLD_IMAGE view types, you'll need to implement additional logic to fetch the current item state from DynamoDB before updating OpenSearch.

Schema evolution presents ongoing challenges in real-time synchronization systems. When you add new fields to your DynamoDB items, you need to ensure that your Lambda function can handle both old and new record formats gracefully. Similarly, changes to your OpenSearch mapping might require reindexing existing data, which needs to be coordinated carefully to avoid search downtime.

Resource limits and quotas can cause subtle issues that only appear under load. DynamoDB Streams have limits on the number of concurrent Lambda executions per shard, and OpenSearch clusters have limits on indexing throughput and concurrent requests. Design your system with these limits in mind and implement appropriate backpressure mechanisms to handle traffic spikes gracefully.

The combination of DynamoDB Streams and Lambda provides a powerful foundation for real-time data synchronization, enabling you to build systems that leverage the strengths of both transactional and search-optimized data stores. Success requires careful attention to ordering semantics, robust error handling, and thorough testing, but the result is a scalable architecture that can support sophisticated search experiences while maintaining data consistency and high availability.
