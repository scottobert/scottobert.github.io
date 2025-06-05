---
title: "Real-time Processing Architectures"
date: 2021-04-11T09:00:00-05:00
categories: ["Cloud Computing", "Data Engineering"]
tags: ["AWS", "Real-time", "Kinesis", "Lambda", "Stream Processing", "Architecture"]
series: "Cloud Architecture Patterns"
---

Real-time processing architectures address the fundamental challenge of extracting actionable insights from continuously flowing data streams while maintaining low latency and high throughput requirements. Unlike batch processing systems that operate on static datasets with relaxed timing constraints, real-time systems must process events as they arrive, often within milliseconds or seconds of generation. This temporal sensitivity introduces unique design considerations around event ordering, backpressure handling, and state management that distinguish real-time architectures from their batch-oriented counterparts.

The evolution from traditional batch processing to real-time streaming reflects the changing nature of modern business requirements where delayed insights often lose their value. Financial trading systems require microsecond response times to capitalize on market opportunities. Fraud detection systems must identify suspicious patterns before transactions complete. Recommendation engines need to incorporate user behavior in real-time to maximize engagement. These use cases share the common requirement that data processing latency directly impacts business value, making architectural decisions about streaming infrastructure critical to organizational success.

AWS Kinesis Data Streams provides the foundational infrastructure for real-time data ingestion, offering managed scaling and durability guarantees that simplify the operational overhead of stream processing systems. The shard-based partitioning model enables horizontal scaling by distributing records across multiple shards based on partition keys, allowing different parts of the data stream to be processed independently. Understanding the relationship between partition key selection and shard distribution becomes critical for achieving balanced throughput and avoiding hot sharding scenarios that can bottleneck entire processing pipelines.

The ordered delivery guarantees within individual shards provide the consistency foundation necessary for stateful stream processing operations. Applications that require global ordering across all records must use single-shard streams, accepting throughput limitations in exchange for ordering guarantees. More commonly, applications design around partition-level ordering by carefully selecting partition keys that align with business requirements. User-based partitioning ensures that events for individual users arrive in order, enabling session-based analytics and sequential pattern detection.

```typescript
// Real-time stream processing pipeline using Kinesis and Lambda
import { KinesisClient, PutRecordCommand, PutRecordsCommand } from '@aws-sdk/client-kinesis';
import { DynamoDBClient, PutItemCommand, UpdateItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

interface StreamEvent {
  eventId: string;
  userId: string;
  eventType: string;
  timestamp: number;
  data: any;
}

interface UserSession {
  userId: string;
  sessionId: string;
  startTime: number;
  lastActivity: number;
  events: StreamEvent[];
  aggregates: {
    pageViews: number;
    purchases: number;
    totalSpent: number;
  };
}

class RealTimeStreamProcessor {
  private kinesisClient: KinesisClient;
  private dynamoClient: DynamoDBClient;
  private streamName: string;
  private sessionTable: string;

  constructor(streamName: string, sessionTable: string) {
    this.kinesisClient = new KinesisClient({});
    this.dynamoClient = new DynamoDBClient({});
    this.streamName = streamName;
    this.sessionTable = sessionTable;
  }

  async publishEvent(event: StreamEvent): Promise<void> {
    try {
      const record = {
        Data: JSON.stringify(event),
        PartitionKey: event.userId, // Ensures ordering per user
        ExplicitHashKey: undefined
      };

      await this.kinesisClient.send(new PutRecordCommand({
        StreamName: this.streamName,
        ...record
      }));
    } catch (error) {
      console.error('Failed to publish event to Kinesis:', error);
      throw error;
    }
  }

  async publishBatch(events: StreamEvent[]): Promise<void> {
    try {
      const records = events.map(event => ({
        Data: JSON.stringify(event),
        PartitionKey: event.userId
      }));

      // Kinesis supports up to 500 records per batch
      const batchSize = 500;
      for (let i = 0; i < records.length; i += batchSize) {
        const batch = records.slice(i, i + batchSize);
        
        await this.kinesisClient.send(new PutRecordsCommand({
          StreamName: this.streamName,
          Records: batch
        }));
      }
    } catch (error) {
      console.error('Failed to publish batch to Kinesis:', error);
      throw error;
    }
  }

  async processStreamEvent(kinesisRecord: any): Promise<void> {
    try {
      // Decode the event from Kinesis record
      const eventData = JSON.parse(
        Buffer.from(kinesisRecord.data, 'base64').toString('utf-8')
      );
      const event: StreamEvent = eventData;

      // Update user session with new event
      await this.updateUserSession(event);

      // Check for real-time alerts or triggers
      await this.checkRealTimeRules(event);

      // Update real-time analytics
      await this.updateRealTimeMetrics(event);

    } catch (error) {
      console.error('Failed to process stream event:', error);
      // In production, would send to DLQ for retry
      throw error;
    }
  }

  private async updateUserSession(event: StreamEvent): Promise<void> {
    const sessionTimeout = 30 * 60 * 1000; // 30 minutes
    const now = Date.now();

    try {
      // Get current session
      const response = await this.dynamoClient.send(new GetItemCommand({
        TableName: this.sessionTable,
        Key: marshall({ userId: event.userId })
      }));

      let session: UserSession;

      if (response.Item) {
        session = unmarshall(response.Item) as UserSession;
        
        // Check if session has expired
        if (now - session.lastActivity > sessionTimeout) {
          // Start new session
          session = this.createNewSession(event.userId, now);
        }
      } else {
        // Create new session
        session = this.createNewSession(event.userId, now);
      }

      // Update session with new event
      session.lastActivity = now;
      session.events.push(event);

      // Update aggregates based on event type
      this.updateSessionAggregates(session, event);

      // Save updated session
      await this.dynamoClient.send(new PutItemCommand({
        TableName: this.sessionTable,
        Item: marshall(session)
      }));

    } catch (error) {
      console.error('Failed to update user session:', error);
      throw error;
    }
  }

  private createNewSession(userId: string, timestamp: number): UserSession {
    return {
      userId,
      sessionId: `${userId}-${timestamp}`,
      startTime: timestamp,
      lastActivity: timestamp,
      events: [],
      aggregates: {
        pageViews: 0,
        purchases: 0,
        totalSpent: 0
      }
    };
  }

  private updateSessionAggregates(session: UserSession, event: StreamEvent): void {
    switch (event.eventType) {
      case 'page_view':
        session.aggregates.pageViews++;
        break;
      case 'purchase':
        session.aggregates.purchases++;
        session.aggregates.totalSpent += event.data.amount || 0;
        break;
    }
  }

  private async checkRealTimeRules(event: StreamEvent): Promise<void> {
    // Example: Fraud detection for large purchases
    if (event.eventType === 'purchase' && event.data.amount > 1000) {
      await this.triggerFraudAlert(event);
    }

    // Example: Personalization trigger
    if (event.eventType === 'product_view') {
      await this.updatePersonalizationModel(event.userId, event.data.productId);
    }
  }

  private async triggerFraudAlert(event: StreamEvent): Promise<void> {
    // Implementation would send alert to fraud detection system
    console.log(`Fraud alert triggered for user ${event.userId}, amount: ${event.data.amount}`);
  }

  private async updatePersonalizationModel(userId: string, productId: string): Promise<void> {
    // Implementation would update ML model or recommendation cache
    console.log(`Updating personalization for user ${userId}, product ${productId}`);
  }

  private async updateRealTimeMetrics(event: StreamEvent): Promise<void> {
    // Update real-time dashboards and metrics
    // Implementation would publish to CloudWatch or custom metrics system
  }
}

// Lambda function for processing Kinesis stream records
export const kinesisStreamProcessor = async (event: any) => {
  const processor = new RealTimeStreamProcessor(
    process.env.KINESIS_STREAM_NAME!,
    process.env.SESSION_TABLE_NAME!
  );

  const results = await Promise.allSettled(
    event.Records.map(async (record: any) => {
      try {
        await processor.processStreamEvent(record.kinesis);
        return { recordId: record.eventID, result: 'Ok' };
      } catch (error) {
        console.error(`Failed to process record ${record.eventID}:`, error);
        return { recordId: record.eventID, result: 'ProcessingFailed' };
      }
    })
  );

  // Return processing results for Kinesis to handle retries
  return {
    records: results.map(result => 
      result.status === 'fulfilled' 
        ? result.value 
        : { recordId: 'unknown', result: 'ProcessingFailed' }
    )
  };
};

// Real-time analytics aggregator using sliding windows
class SlidingWindowAnalytics {
  private windowSize: number;
  private slideInterval: number;
  private metrics: Map<string, number[]> = new Map();

  constructor(windowSizeMs: number, slideIntervalMs: number) {
    this.windowSize = windowSizeMs;
    this.slideInterval = slideIntervalMs;
    
    // Clean up old data periodically
    setInterval(() => this.cleanup(), this.slideInterval);
  }

  addMetric(metricName: string, value: number, timestamp: number = Date.now()): void {
    if (!this.metrics.has(metricName)) {
      this.metrics.set(metricName, []);
    }

    const values = this.metrics.get(metricName)!;
    values.push(timestamp, value); // Store timestamp and value pairs
  }

  getAverage(metricName: string): number {
    const values = this.getValuesInWindow(metricName);
    if (values.length === 0) return 0;
    
    return values.reduce((sum, val) => sum + val, 0) / values.length;
  }

  getSum(metricName: string): number {
    const values = this.getValuesInWindow(metricName);
    return values.reduce((sum, val) => sum + val, 0);
  }

  getCount(metricName: string): number {
    return this.getValuesInWindow(metricName).length;
  }

  private getValuesInWindow(metricName: string): number[] {
    const data = this.metrics.get(metricName);
    if (!data) return [];

    const now = Date.now();
    const windowStart = now - this.windowSize;
    const values: number[] = [];

    // Data is stored as [timestamp1, value1, timestamp2, value2, ...]
    for (let i = 0; i < data.length; i += 2) {
      const timestamp = data[i];
      const value = data[i + 1];
      
      if (timestamp >= windowStart) {
        values.push(value);
      }
    }

    return values;
  }

  private cleanup(): void {
    const now = Date.now();
    const windowStart = now - this.windowSize;

    for (const [metricName, data] of this.metrics.entries()) {
      const cleanedData: number[] = [];
      
      for (let i = 0; i < data.length; i += 2) {
        const timestamp = data[i];
        const value = data[i + 1];
        
        if (timestamp >= windowStart) {
          cleanedData.push(timestamp, value);
        }
      }
      
      this.metrics.set(metricName, cleanedData);
    }
  }
}

// Real-time event processor with sliding window analytics
export const realTimeAnalyticsHandler = async (event: StreamEvent) => {
  const analytics = new SlidingWindowAnalytics(
    5 * 60 * 1000, // 5 minute window
    30 * 1000      // 30 second slide interval
  );

  // Process the event and update metrics
  analytics.addMetric('events_per_minute', 1);
  
  if (event.eventType === 'purchase') {
    analytics.addMetric('revenue_per_minute', event.data.amount || 0);
    analytics.addMetric('purchases_per_minute', 1);
  }

  // Get current metrics
  const currentMetrics = {
    eventsPerMinute: analytics.getSum('events_per_minute'),
    revenuePerMinute: analytics.getSum('revenue_per_minute'),
    purchasesPerMinute: analytics.getSum('purchases_per_minute'),
    averageOrderValue: analytics.getAverage('revenue_per_minute')
  };

  // Check for anomalies or alerts
  if (currentMetrics.eventsPerMinute > 1000) {
    console.warn('High event volume detected:', currentMetrics.eventsPerMinute);
  }

  return {
    statusCode: 200,
    body: JSON.stringify({
      processed: true,
      metrics: currentMetrics
    })
  };
};
```
