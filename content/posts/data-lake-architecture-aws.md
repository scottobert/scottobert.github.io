---
title: "Data Lake Architecture with AWS"
date: 2021-03-21T09:00:00-05:00
categories: ["Cloud Computing", "Data Engineering"]
tags: ["AWS", "Data Lake", "S3", "Glue", "Athena", "Data Architecture"]
series: "Cloud Architecture Patterns"
---

Data lake architectures represent a fundamental departure from traditional data warehousing approaches, embracing schema-on-read principles and polyglot storage strategies that accommodate the velocity, variety, and volume characteristics of modern data ecosystems. Unlike data warehouses that require upfront schema definition and ETL processes to conform data to predefined structures, data lakes preserve raw data in its native format while providing flexible analysis capabilities that adapt to evolving analytical requirements. AWS provides a comprehensive suite of services that enable sophisticated data lake implementations while managing the operational complexity traditionally associated with big data platforms.

The conceptual foundation of data lakes rests on the principle of storing data in its most granular, unprocessed form while providing multiple access patterns and analytical interfaces. This approach recognizes that data value often emerges through unexpected correlations and analytical approaches that weren't anticipated during initial collection. By preserving complete fidelity of source data, data lakes enable retrospective analysis using new techniques and tools as they become available, avoiding the irreversible information loss that occurs in traditional ETL pipelines.

Amazon S3 serves as the foundational storage layer for most AWS data lake architectures, providing virtually unlimited capacity with multiple storage classes optimized for different access patterns and cost profiles. The object storage model aligns naturally with data lake principles by supporting flexible schemas and enabling direct access from multiple analytical tools without requiring data movement. S3's lifecycle management capabilities automatically transition data between storage classes based on access patterns, optimizing costs while maintaining availability for active analysis workloads.

The organization of data within S3 requires careful consideration of partitioning strategies that balance query performance with storage efficiency. Time-based partitioning naturally aligns with many analytical workloads while enabling lifecycle policies that automatically archive older data. Geographic or categorical partitioning can optimize queries that filter on specific dimensions. The key insight is that partitioning decisions should reflect the most common query patterns while avoiding over-partitioning that creates excessive metadata overhead or under-partitioning that forces full dataset scans for selective queries.

```typescript
// Data Lake ETL Pipeline using AWS Glue and S3
import { GlueClient, StartJobRunCommand, GetJobRunCommand } from '@aws-sdk/client-glue';
import { S3Client, PutObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { AthenaClient, StartQueryExecutionCommand, GetQueryExecutionCommand } from '@aws-sdk/client-athena';

interface DataLakeConfig {
  rawDataBucket: string;
  processedDataBucket: string;
  glueDatabaseName: string;
  athenaResultsBucket: string;
}

interface PartitionStrategy {
  type: 'date' | 'category' | 'hash';
  columns: string[];
  format: string;
}

class DataLakeOrchestrator {
  private s3Client: S3Client;
  private glueClient: GlueClient;
  private athenaClient: AthenaClient;
  private config: DataLakeConfig;

  constructor(config: DataLakeConfig) {
    this.s3Client = new S3Client({});
    this.glueClient = new GlueClient({});
    this.athenaClient = new AthenaClient({});
    this.config = config;
  }

  async ingestRawData(data: any[], dataSource: string, timestamp: Date): Promise<string> {
    const partitionPath = this.generatePartitionPath(timestamp, dataSource);
    const s3Key = `${partitionPath}/data-${Date.now()}.json`;
    
    try {
      // Convert data to newline-delimited JSON format for efficient processing
      const ndjsonData = data.map(record => JSON.stringify(record)).join('\n');
      
      await this.s3Client.send(new PutObjectCommand({
        Bucket: this.config.rawDataBucket,
        Key: s3Key,
        Body: ndjsonData,
        ContentType: 'application/x-ndjson',
        Metadata: {
          'data-source': dataSource,
          'ingestion-timestamp': timestamp.toISOString(),
          'record-count': data.length.toString()
        }
      }));

      // Trigger Glue crawler to update schema if needed
      await this.updateGlueCatalog(dataSource, partitionPath);
      
      return s3Key;
    } catch (error) {
      console.error('Failed to ingest raw data:', error);
      throw error;
    }
  }

  async processData(jobName: string, inputPath: string, outputPath: string): Promise<string> {
    try {
      const jobRunResponse = await this.glueClient.send(new StartJobRunCommand({
        JobName: jobName,
        Arguments: {
          '--INPUT_PATH': inputPath,
          '--OUTPUT_PATH': outputPath,
          '--enable-metrics': '',
          '--enable-continuous-cloudwatch-log': 'true'
        }
      }));

      const jobRunId = jobRunResponse.JobRunId!;
      
      // Wait for job completion
      await this.waitForJobCompletion(jobName, jobRunId);
      
      return jobRunId;
    } catch (error) {
      console.error('Glue job execution failed:', error);
      throw error;
    }
  }

  private async waitForJobCompletion(jobName: string, jobRunId: string): Promise<void> {
    const maxWaitTime = 30 * 60 * 1000; // 30 minutes
    const pollInterval = 30 * 1000; // 30 seconds
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const jobStatus = await this.glueClient.send(new GetJobRunCommand({
        JobName: jobName,
        RunId: jobRunId
      }));

      const state = jobStatus.JobRun?.JobRunState;
      
      if (state === 'SUCCEEDED') {
        return;
      } else if (state === 'FAILED' || state === 'STOPPED') {
        throw new Error(`Glue job ${jobRunId} failed with state: ${state}`);
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Glue job ${jobRunId} timeout after 30 minutes`);
  }

  async queryData(sql: string): Promise<any[]> {
    try {
      const queryResponse = await this.athenaClient.send(new StartQueryExecutionCommand({
        QueryString: sql,
        QueryExecutionContext: {
          Database: this.config.glueDatabaseName
        },
        ResultConfiguration: {
          OutputLocation: `s3://${this.config.athenaResultsBucket}/query-results/`
        }
      }));

      const queryExecutionId = queryResponse.QueryExecutionId!;
      
      // Wait for query completion
      await this.waitForQueryCompletion(queryExecutionId);
      
      // Fetch results
      return await this.getQueryResults(queryExecutionId);
    } catch (error) {
      console.error('Athena query failed:', error);
      throw error;
    }
  }

  private async waitForQueryCompletion(queryExecutionId: string): Promise<void> {
    const maxWaitTime = 10 * 60 * 1000; // 10 minutes
    const pollInterval = 5 * 1000; // 5 seconds
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitTime) {
      const queryStatus = await this.athenaClient.send(new GetQueryExecutionCommand({
        QueryExecutionId: queryExecutionId
      }));

      const state = queryStatus.QueryExecution?.Status?.State;
      
      if (state === 'SUCCEEDED') {
        return;
      } else if (state === 'FAILED' || state === 'CANCELLED') {
        const reason = queryStatus.QueryExecution?.Status?.StateChangeReason;
        throw new Error(`Query ${queryExecutionId} failed: ${reason}`);
      }

      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Query ${queryExecutionId} timeout after 10 minutes`);
  }

  private async getQueryResults(queryExecutionId: string): Promise<any[]> {
    // Implementation would use Athena GetQueryResults API
    // This is a simplified placeholder
    return [];
  }

  private generatePartitionPath(timestamp: Date, dataSource: string): string {
    const year = timestamp.getFullYear();
    const month = String(timestamp.getMonth() + 1).padStart(2, '0');
    const day = String(timestamp.getDate()).padStart(2, '0');
    const hour = String(timestamp.getHours()).padStart(2, '0');
    
    return `source=${dataSource}/year=${year}/month=${month}/day=${day}/hour=${hour}`;
  }

  private async updateGlueCatalog(dataSource: string, partitionPath: string): Promise<void> {
    // Trigger Glue crawler or add partition directly
    // Implementation depends on your Glue catalog strategy
  }

  async createOptimizedTable(tableName: string, schema: any, partitionStrategy: PartitionStrategy): Promise<void> {
    const createTableSQL = this.generateCreateTableSQL(tableName, schema, partitionStrategy);
    await this.queryData(createTableSQL);
  }

  private generateCreateTableSQL(tableName: string, schema: any, partitionStrategy: PartitionStrategy): string {
    const columns = Object.entries(schema)
      .map(([name, type]) => `${name} ${type}`)
      .join(',\n  ');

    const partitionColumns = partitionStrategy.columns
      .map(col => `${col} string`)
      .join(',\n  ');

    return `
      CREATE TABLE ${tableName} (
        ${columns}
      )
      PARTITIONED BY (
        ${partitionColumns}
      )
      STORED AS PARQUET
      LOCATION 's3://${this.config.processedDataBucket}/${tableName}/'
      TBLPROPERTIES (
        'has_encrypted_data'='false',
        'parquet.compress'='SNAPPY'
      )
    `;
  }
}

// Lambda function for data processing orchestration
export const dataLakeOrchestratorHandler = async (event: {
  action: 'ingest' | 'process' | 'query';
  data?: any;
  jobName?: string;
  sql?: string;
}) => {
  const config: DataLakeConfig = {
    rawDataBucket: process.env.RAW_DATA_BUCKET!,
    processedDataBucket: process.env.PROCESSED_DATA_BUCKET!,
    glueDatabaseName: process.env.GLUE_DATABASE!,
    athenaResultsBucket: process.env.ATHENA_RESULTS_BUCKET!
  };

  const orchestrator = new DataLakeOrchestrator(config);

  try {
    switch (event.action) {
      case 'ingest':
        if (!event.data) {
          throw new Error('Data is required for ingestion');
        }
        const s3Key = await orchestrator.ingestRawData(
          event.data,
          'api-events',
          new Date()
        );
        return {
          statusCode: 200,
          body: JSON.stringify({ message: 'Data ingested successfully', s3Key })
        };

      case 'process':
        if (!event.jobName) {
          throw new Error('Job name is required for processing');
        }
        const jobRunId = await orchestrator.processData(
          event.jobName,
          `s3://${config.rawDataBucket}/`,
          `s3://${config.processedDataBucket}/`
        );
        return {
          statusCode: 200,
          body: JSON.stringify({ message: 'Processing started', jobRunId })
        };

      case 'query':
        if (!event.sql) {
          throw new Error('SQL is required for querying');
        }
        const results = await orchestrator.queryData(event.sql);
        return {
          statusCode: 200,
          body: JSON.stringify({ results })
        };

      default:
        return {
          statusCode: 400,
          body: JSON.stringify({ error: 'Invalid action' })
        };
    }
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Data lake operation failed',
        message: error.message
      })
    };
  }
};

// Data quality validation pipeline
class DataQualityValidator {
  async validateDataQuality(tableName: string, rules: any[]): Promise<{
    passed: boolean;
    violations: any[];
  }> {
    const violations: any[] = [];

    for (const rule of rules) {
      const checkResult = await this.executeQualityCheck(tableName, rule);
      if (!checkResult.passed) {
        violations.push({
          rule: rule.name,
          description: rule.description,
          violationCount: checkResult.violationCount,
          examples: checkResult.examples
        });
      }
    }

    return {
      passed: violations.length === 0,
      violations
    };
  }

  private async executeQualityCheck(tableName: string, rule: any): Promise<{
    passed: boolean;
    violationCount: number;
    examples: any[];
  }> {
    // Implementation would execute data quality checks using Athena
    // This is a simplified placeholder
    return {
      passed: Math.random() > 0.1, // 90% pass rate for demo
      violationCount: Math.floor(Math.random() * 10),
      examples: []
    };
  }
}
