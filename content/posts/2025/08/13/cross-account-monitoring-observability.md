---
title: "Cross-Account Monitoring and Observability: Building Enterprise-Grade Visibility Across AWS Accounts"
date: 2025-08-13T09:00:00-07:00
draft: false
categories: ["Cloud Computing", "AWS"]
tags:
- AWS
- CloudWatch
- X-Ray
- Monitoring
- Observability
- Cross-Account
- Config
- Cost Management
series: "AWS Cross-Account Patterns"
url: "/posts/cross-account-monitoring-observability/"
---

{{< image src="/posts/2025/08/13/cross-account-monitoring-observability.png" alt="Meme showing a person looking at multiple monitors with different AWS account dashboards" width="600" caption="When you realize you need to check 47 different CloudWatch dashboards to understand one transaction" >}}

The alert fires at 3 AM. Your critical e-commerce platform is down, customers are complaining, and revenue is bleeding. You race to your laptop and immediately hit the wall that haunts every enterprise AWS architect: monitoring fragmentation. The API Gateway logs live in the production account, Lambda functions span three different accounts, and database metrics hide in yet another. Forty-seven browser tabs later, you're still piecing together the puzzle while your application burns.

Sound familiar? You're experiencing what I call "visibility debt" - the hidden cost of multi-account architectures that nobody talks about in those pristine architectural diagrams. Most enterprises using AWS multi-account setups struggle with this exact problem: excellent security boundaries that inadvertently create monitoring blind spots.

**The Problem**: Traditional monitoring approaches break down in multi-account environments. You end up with isolated visibility islands instead of comprehensive observability, making troubleshooting a nightmare and preventing proactive issue detection.

**The Solution**: Cross-account monitoring and observability patterns that centralize data collection while preserving security boundaries. This approach gives you the "single pane of glass" visibility you need without compromising on the isolation benefits that drove you to multi-account architecture in the first place.

In this guide, you'll learn how to build enterprise-grade monitoring that spans AWS accounts, enabling your team to troubleshoot issues in minutes instead of hours. We'll cover everything from basic cross-account CloudWatch dashboards to advanced distributed tracing aggregation and automated compliance reporting.

## Why Cross-Account Monitoring Matters

Before diving into implementation details, let's understand why traditional monitoring approaches fail in multi-account environments and why this pattern has become essential for enterprise AWS architectures.

### The Multi-Account Monitoring Challenge

Modern enterprises typically organize their AWS infrastructure across multiple accounts for several reasons: environment separation (dev/staging/prod), business unit isolation, compliance requirements, and blast radius containment. While this provides excellent security and organizational benefits, it creates significant monitoring challenges.

Consider a typical e-commerce application architecture: your API Gateway and Lambda functions live in the production account, your shared databases are in a data services account, your CI/CD pipeline runs in a DevOps account, and your monitoring team operates from a central security account. When investigating performance issues, your team needs to jump between four different AWS consoles, each with its own CloudWatch dashboards, logs, and metrics.

### Business Impact of Poor Cross-Account Visibility

The cost of monitoring fragmentation extends beyond operational inconvenience. When an investigation requires data from four accounts, the time cost is not the querying — it is the context switching, the re-authentication, and the manual correlation of timestamps across consoles that each default to a different time range. The more damaging effect is on detection rather than resolution: alarms configured per-account cannot express a condition that spans accounts, so the failure modes that matter most in a distributed system are the ones nobody has an alarm for.

The improvement after centralising is mostly about removing that manual correlation step. Measure it for yourself before and after — time-to-first-relevant-dashboard during an incident is a more honest metric than MTTR, and it is the one this work actually moves.

## Architecture Overview

Cross-account monitoring architecture involves centralizing observability data from multiple AWS accounts into unified dashboards and analytics platforms. **Central Monitoring Account** serves as the aggregation point for metrics, logs, and traces from distributed source accounts. **Cross-account IAM roles** provide secure access for data collection and visualization. **Resource sharing mechanisms** enable consolidated views while maintaining proper access controls and data governance.

{{< plantuml id="cross-account-monitoring-architecture" >}}
@startuml
!theme aws-orange
title Cross-Account Monitoring and Observability Architecture

cloud "Central Monitoring Account (111111111111)" as MonitoringAccount {
  rectangle "CloudWatch\nCross-Account Dashboard" as Dashboard
  rectangle "X-Ray Service Map\nAggregation" as XRayAgg
  rectangle "Centralized\nLog Analytics" as LogAnalytics
  rectangle "Config Aggregator" as ConfigAgg
  rectangle "Cost and Billing\nConsolidation" as CostAgg
}

cloud "Production Account (222222222222)" as ProdAccount {
  rectangle "Application Services" as ProdServices
  rectangle "CloudWatch Metrics" as ProdMetrics
  rectangle "X-Ray Traces" as ProdXRay
  rectangle "CloudWatch Logs" as ProdLogs
  rectangle "Config Rules" as ProdConfig
}

cloud "Development Account (333333333333)" as DevAccount {
  rectangle "Application Services" as DevServices
  rectangle "CloudWatch Metrics" as DevMetrics
  rectangle "X-Ray Traces" as DevXRay
  rectangle "CloudWatch Logs" as DevLogs
  rectangle "Config Rules" as DevConfig
}

cloud "Staging Account (444444444444)" as StagingAccount {
  rectangle "Application Services" as StagingServices
  rectangle "CloudWatch Metrics" as StagingMetrics
  rectangle "X-Ray Traces" as StagingXRay
  rectangle "CloudWatch Logs" as StagingLogs
  rectangle "Config Rules" as StagingConfig
}

ProdMetrics --> Dashboard : "Cross-Account\nMetrics Sharing"
DevMetrics --> Dashboard : "Cross-Account\nMetrics Sharing"
StagingMetrics --> Dashboard : "Cross-Account\nMetrics Sharing"

ProdXRay --> XRayAgg : "Trace Data\nAggregation"
DevXRay --> XRayAgg : "Trace Data\nAggregation"
StagingXRay --> XRayAgg : "Trace Data\nAggregation"

ProdLogs --> LogAnalytics : "Log Stream\nForwarding"
DevLogs --> LogAnalytics : "Log Stream\nForwarding"
StagingLogs --> LogAnalytics : "Log Stream\nForwarding"

ProdConfig --> ConfigAgg : "Compliance\nAggregation"
DevConfig --> ConfigAgg : "Compliance\nAggregation"
StagingConfig --> ConfigAgg : "Compliance\nAggregation"

note right of Dashboard
  Unified view across
  all environments and
  business units
end note

note left of ConfigAgg
  Centralized compliance
  and governance reporting
end note
@enduml
{{< /plantuml >}}

## Step 1: Setting Up Cross-Account CloudWatch Dashboards

Before building anything custom, use the service AWS provides for exactly this. **CloudWatch cross-account observability** links source accounts to a monitoring account through Observability Access Manager (OAM), and once linked, metrics, logs and traces from the source accounts appear in the monitoring account's own CloudWatch and X-Ray consoles. No aggregation Lambdas, no scheduled copying, no duplicated data.

The monitoring account creates a **sink**; each source account creates a **link** to it:

```typescript
import * as oam from 'aws-cdk-lib/aws-oam';

// In the MONITORING account
const sink = new oam.CfnSink(this, 'ObservabilitySink', {
  name: 'central-observability-sink',
  policy: {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: '*',
      Resource: '*',
      Action: ['oam:CreateLink', 'oam:UpdateLink'],
      Condition: {
        // Only accounts in our organisation may attach.
        'ForAllValues:StringEquals': {
          'oam:ResourceTypes': [
            'AWS::CloudWatch::Metric',
            'AWS::Logs::LogGroup',
            'AWS::XRay::Trace'
          ]
        },
        StringEquals: { 'aws:PrincipalOrgID': 'o-abc123example' }
      }
    }]
  }
});
```

```typescript
// In each SOURCE account
new oam.CfnLink(this, 'ObservabilityLink', {
  sinkIdentifier: 'arn:aws:oam:us-east-1:111111111111:sink/abcd1234-...',
  labelTemplate: '$AccountName',
  resourceTypes: [
    'AWS::CloudWatch::Metric',
    'AWS::Logs::LogGroup',
    'AWS::XRay::Trace'
  ]
});
```

That is the whole setup. A monitoring account can link up to 100,000 source accounts, and the data stays in the source account — you are granting read access, not copying anything, so there is no duplicate ingestion cost.

Reach for the role-based approach below only when OAM does not fit: accounts outside your organisation, a partition or region where OAM is unavailable, or a case where you need the data physically in the monitoring account (long-term log retention in a dedicated account, for instance). The two approaches compose — most real setups use OAM for interactive investigation and log forwarding for retention.

### The role-based alternative

Create IAM roles in source accounts that allow the monitoring account to access CloudWatch data:

```typescript
// monitoring-role-policy.json - Cross-account CloudWatch access policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DescribeAlarmsForMetric",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

Create the cross-account trust relationship:

```typescript
// monitoring-trust-policy.json - Trust policy for monitoring account
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:role/CrossAccountMonitoringRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-monitoring-external-id"
        }
      }
    }
  ]
}
```

Deploy the monitoring infrastructure using AWS CDK:

```typescript
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface CrossAccountMonitoringProps extends cdk.StackProps {
  sourceAccounts: string[];
  externalId: string;
}

export class CrossAccountMonitoringStack extends cdk.Stack {
  public readonly monitoringRole: iam.Role;
  public readonly crossAccountDashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: CrossAccountMonitoringProps) {
    super(scope, id, props);

    // CloudWatch does not assume a role to render a dashboard, so trusting
    // `cloudwatch.amazonaws.com` here produces a role nothing can ever use.
    // Two different mechanisms are in play:
    //
    //  * For a human browsing a cross-account dashboard, the *console user's*
    //    own identity assumes a role in the source account, and that role must
    //    be named `CloudWatch-CrossAccountSharingRole` -- the console looks it
    //    up by that exact name.
    //  * For automation (the aggregation Lambda later in this post), the
    //    compute's execution role assumes the source-account role.
    //
    // This role is the automation case, so it is trusted by the workloads that
    // will use it, not by a service principal.
    this.monitoringRole = new iam.Role(this, 'CrossAccountMonitoringRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Role used by monitoring-account automation to read source accounts',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchReadOnlyAccess')
      ]
    });

    // Add policy to assume roles in source accounts
    this.monitoringRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:AssumeRole'],
      resources: props.sourceAccounts.map(account => 
        `arn:aws:iam::${account}:role/MonitoringSourceRole`
      ),
      conditions: {
        'StringEquals': {
          'sts:ExternalId': props.externalId
        }
      }
    }));

    // Create cross-account dashboard
    this.crossAccountDashboard = new cloudwatch.Dashboard(this, 'CrossAccountDashboard', {
      dashboardName: 'cross-account-application-monitoring',
      widgets: this.createDashboardWidgets(props.sourceAccounts)
    });
  }

  private createDashboardWidgets(sourceAccounts: string[]): cloudwatch.IWidget[] {
    const widgets: cloudwatch.IWidget[] = [];

    sourceAccounts.forEach((accountId, index) => {
      // Lambda function metrics across accounts
      widgets.push(new cloudwatch.GraphWidget({
        title: `Lambda Functions - Account ${accountId}`,
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/Lambda',
            metricName: 'Duration',
            statistic: 'Average',
            account: accountId
          }),
          new cloudwatch.Metric({
            namespace: 'AWS/Lambda',
            metricName: 'Errors',
            statistic: 'Sum',
            account: accountId
          })
        ],
        width: 12,
        height: 6
      }));

      // API Gateway metrics across accounts
      widgets.push(new cloudwatch.GraphWidget({
        title: `API Gateway - Account ${accountId}`,
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/ApiGateway',
            metricName: 'Count',
            statistic: 'Sum',
            account: accountId
          }),
          new cloudwatch.Metric({
            namespace: 'AWS/ApiGateway',
            metricName: '4XXError',
            statistic: 'Sum',
            account: accountId
          })
        ],
        width: 12,
        height: 6
      }));
    });

    return widgets;
  }
}
```

Create and deploy the source account monitoring roles:

```typescript
export class SourceAccountMonitoringStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    monitoringAccountId: string;
    externalId: string;
  }) {
    super(scope, id, props);

    // The name matters if you want the CloudWatch console's cross-account
    // dashboard picker to work: it assumes a role called exactly
    // `CloudWatch-CrossAccountSharingRole` in the source account. A role under
    // any other name is reachable by your own automation but invisible to the
    // console.
    //
    // Note also that an external ID is the wrong tool here. External IDs exist
    // to stop the confused-deputy problem when a *third party* assumes your
    // role on your behalf. Between two accounts you own, it adds a shared
    // secret to manage and buys nothing; the account principal is the control.
    const monitoringSourceRole = new iam.Role(this, 'MonitoringSourceRole', {
      roleName: 'CloudWatch-CrossAccountSharingRole',
      assumedBy: new iam.AccountPrincipal(props?.monitoringAccountId || ''),
      description: 'Allows monitoring account to access CloudWatch data'
    });

    monitoringSourceRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchReadOnlyAccess')
    );

    // Additional permissions for enhanced monitoring
    monitoringSourceRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'xray:GetServiceGraph',
        'xray:GetTraceSummaries',
        'xray:BatchGetTraces',
        'xray:GetTimeSeriesServiceStatistics',
        'config:GetComplianceDetailsByConfigRule',
        'config:GetConfigRuleEvaluationStatus'
      ],
      resources: ['*']
    }));
  }
}
```

## Step 2: Implementing X-Ray Cross-Account Trace Aggregation

AWS X-Ray provides distributed tracing capabilities that can aggregate trace data across multiple accounts, enabling end-to-end visibility into request flows that span account boundaries. This aggregation is crucial for understanding performance bottlenecks and dependencies in multi-account architectures.

Configure X-Ray service linking between accounts:

With cross-account observability enabled, X-Ray traces from linked source accounts already appear in the monitoring account's service map — there is nothing to aggregate. The code below is for the cases OAM does not cover, and it also fixes an API name that is easy to get wrong: **there is no `GetServiceMap` operation in X-Ray.** The service map is retrieved with [`GetServiceGraph`](https://docs.aws.amazon.com/xray/latest/api/API_GetServiceGraph.html), and the corresponding IAM action is `xray:GetServiceGraph`.

```typescript
import { XRayClient, GetServiceGraphCommand } from '@aws-sdk/client-xray';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';

export interface XRayAggregationConfig {
  sourceAccounts: Array<{
    accountId: string;
    roleArn: string;
    region: string;
  }>;
  aggregationAccountId: string;
}

export class CrossAccountXRayAggregator {
  private readonly stsClient: STSClient;
  private readonly aggregationConfig: XRayAggregationConfig;

  constructor(config: XRayAggregationConfig) {
    this.stsClient = new STSClient({ region: 'us-east-1' });
    this.aggregationConfig = config;
  }

  async aggregateServiceMaps(): Promise<void> {
    console.log('Starting cross-account X-Ray service map aggregation');

    const aggregatedServiceMap = {
      services: new Map(),
      edges: new Map()
    };

    for (const sourceAccount of this.aggregationConfig.sourceAccounts) {
      try {
        const xrayClient = await this.createCrossAccountXRayClient(sourceAccount);
        const serviceMap = await this.getServiceMapFromAccount(xrayClient, sourceAccount.accountId);
        
        this.mergeServiceMap(aggregatedServiceMap, serviceMap, sourceAccount.accountId);
        
        console.log(`Successfully retrieved service map from account ${sourceAccount.accountId}`);
      } catch (error) {
        console.error(`Failed to retrieve service map from account ${sourceAccount.accountId}:`, error);
      }
    }

    await this.publishAggregatedServiceMap(aggregatedServiceMap);
  }

  private async createCrossAccountXRayClient(sourceAccount: {
    accountId: string;
    roleArn: string;
    region: string;
  }): Promise<XRayClient> {
    const assumeRoleCommand = new AssumeRoleCommand({
      RoleArn: sourceAccount.roleArn,
      RoleSessionName: `xray-aggregation-${Date.now()}`
    });

    const assumedRole = await this.stsClient.send(assumeRoleCommand);
    
    if (!assumedRole.Credentials) {
      throw new Error(`Failed to assume role in account ${sourceAccount.accountId}`);
    }

    return new XRayClient({
      region: sourceAccount.region,
      credentials: {
        accessKeyId: assumedRole.Credentials.AccessKeyId!,
        secretAccessKey: assumedRole.Credentials.SecretAccessKey!,
        sessionToken: assumedRole.Credentials.SessionToken!
      }
    });
  }

  private async getServiceMapFromAccount(
    xrayClient: XRayClient, 
    accountId: string
  ): Promise<any> {
    const endTime = new Date();
    const startTime = new Date(endTime.getTime() - (60 * 60 * 1000)); // Last hour

    // GetServiceGraph takes only a time window -- `TimeRangeType` belongs to
    // GetTraceSummaries and is rejected here. The operation is also paginated,
    // so a single call can silently truncate a large service graph.
    const services: unknown[] = [];
    let nextToken: string | undefined;

    do {
      const response = await xrayClient.send(new GetServiceGraphCommand({
        StartTime: startTime,
        EndTime: endTime,
        NextToken: nextToken
      }));

      services.push(...(response.Services ?? []));
      nextToken = response.NextToken;
    } while (nextToken);

    return { services, accountId };
  }

  private mergeServiceMap(aggregatedMap: any, sourceMap: any, accountId: string): void {
    // Add account context to service names to avoid conflicts
    sourceMap.services.forEach((service: any) => {
      const serviceKey = `${service.Name}-${accountId}`;
      aggregatedMap.services.set(serviceKey, {
        ...service,
        AccountId: accountId,
        CrossAccountService: true
      });
    });
  }

  private async publishAggregatedServiceMap(aggregatedMap: any): Promise<void> {
    // Publish aggregated service map to centralized storage or dashboard
    console.log('Publishing aggregated service map:', {
      totalServices: aggregatedMap.services.size,
      accounts: this.aggregationConfig.sourceAccounts.map(a => a.accountId)
    });

    // Implementation would store this in CloudWatch custom metrics, 
    // DynamoDB, or other centralized storage for dashboard consumption
  }
}
```

Deploy the X-Ray aggregation infrastructure:

```typescript
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';

export class XRayAggregationStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Lambda function for X-Ray aggregation
    const xrayAggregatorFunction = new lambda.Function(this, 'XRayAggregatorFunction', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda/xray-aggregator'),
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        SOURCE_ACCOUNTS: JSON.stringify([
          { accountId: '222222222222', roleArn: 'arn:aws:iam::222222222222:role/XRaySourceRole', region: 'us-east-1' },
          { accountId: '333333333333', roleArn: 'arn:aws:iam::333333333333:role/XRaySourceRole', region: 'us-east-1' }
        ])
      }
    });

    // Grant permissions to assume roles in source accounts
    xrayAggregatorFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:AssumeRole'],
      resources: [
        'arn:aws:iam::222222222222:role/XRaySourceRole',
        'arn:aws:iam::333333333333:role/XRaySourceRole'
      ]
    }));

    // Schedule regular aggregation
    const aggregationSchedule = new events.Rule(this, 'XRayAggregationSchedule', {
      schedule: events.Schedule.rate(cdk.Duration.minutes(15)),
      description: 'Trigger X-Ray cross-account aggregation every 15 minutes'
    });

    aggregationSchedule.addTarget(new events_targets.LambdaFunction(xrayAggregatorFunction));
  }
}
```

## Step 3: Centralized Logging with Cross-Account Log Streams

Centralized logging aggregates log data from multiple AWS accounts into a unified platform for analysis, alerting, and compliance reporting. This pattern enables comprehensive log correlation and analysis across distributed systems.

Set up cross-account log destination in the central monitoring account:

```typescript
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kinesis from 'aws-cdk-lib/aws-kinesis';
import * as kinesisfirehose from 'aws-cdk-lib/aws-kinesisfirehose';
import * as s3 from 'aws-cdk-lib/aws-s3';

export class CentralizedLoggingStack extends cdk.Stack {
  public readonly logDestination: logs.CrossAccountDestination;
  public readonly logAnalyticsS3Bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    sourceAccounts: string[];
  }) {
    super(scope, id, props);

    // S3 bucket for centralized log storage
    this.logAnalyticsS3Bucket = new s3.Bucket(this, 'LogAnalyticsS3Bucket', {
      bucketName: `centralized-logs-${this.account}-${this.region}`,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      // Versioning is deliberately off. Log objects are append-only and never
      // rewritten, so versions accumulate nothing but cost -- and with a
      // 7-year expiration and no `noncurrentVersionExpiration`, noncurrent
      // versions would sit there unmanaged.
      lifecycleRules: [{
        id: 'log-retention-policy',
        enabled: true,
        transitions: [{
          storageClass: s3.StorageClass.INFREQUENT_ACCESS,
          transitionAfter: cdk.Duration.days(30)
        }, {
          storageClass: s3.StorageClass.GLACIER,
          transitionAfter: cdk.Duration.days(90)
        }],
        expiration: cdk.Duration.days(2555) // 7 years retention
      }]
    });

    // Kinesis stream for log processing
    const logStream = new kinesis.Stream(this, 'CentralizedLogStream', {
      streamName: 'centralized-logs-stream',
      shardCount: 2,
      retentionPeriod: cdk.Duration.days(7)
    });

    // Firehose for S3 delivery.
    //
    // Two things to watch here. `AmazonKinesisFirehoseFullAccess` is an
    // administrative policy for principals that *manage* Firehose -- it is not
    // what the delivery stream needs to write to one bucket, and attaching it
    // hands the role far more than the job requires. `grantWrite` below is
    // sufficient on its own.
    //
    // Also note the L2 API changed when `aws-kinesisfirehose` graduated out of
    // alpha: the prop is `destination` (singular, not `destinations: []`), and
    // the S3 destination class is `S3Bucket` (not `S3Destination`).
    const logDeliveryRole = new iam.Role(this, 'LogDeliveryRole', {
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
      description: 'Firehose delivery role, scoped to the log bucket only'
    });

    this.logAnalyticsS3Bucket.grantWrite(logDeliveryRole);

    const firehoseDeliveryStream = new kinesisfirehose.DeliveryStream(this, 'LogDeliveryStream', {
      deliveryStreamName: 'centralized-logs-delivery',
      source: new kinesisfirehose.KinesisStreamSource(logStream),
      destination: new kinesisfirehose.S3Bucket(this.logAnalyticsS3Bucket, {
        role: logDeliveryRole,
        // Hive-style partitioning so Athena can prune by date.
        dataOutputPrefix: 'year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/',
        errorOutputPrefix: 'errors/',
        compression: kinesisfirehose.Compression.GZIP,
        bufferingInterval: cdk.Duration.minutes(5),
        bufferingSize: cdk.Size.mebibytes(5)
      })
    });

    // IAM role CloudWatch Logs assumes to write into the Kinesis stream.
    const logDestinationRole = new iam.Role(this, 'LogDestinationRole', {
      assumedBy: new iam.ServicePrincipal('logs.amazonaws.com'),
      description: 'Role for cross-account log destination'
    });

    logStream.grantWrite(logDestinationRole);

    // The construct for `AWS::Logs::Destination` is `CrossAccountDestination`.
    // There is no `logs.LogDestination` or `logs.LogDestinationPolicy` class.
    this.logDestination = new logs.CrossAccountDestination(this, 'CrossAccountLogDestination', {
      destinationName: 'cross-account-centralized-logs',
      targetArn: logStream.streamArn,
      role: logDestinationRole
    });

    // The destination policy is attached to the destination itself, and it
    // must name a resource -- a statement without one grants nothing.
    (props?.sourceAccounts ?? []).forEach(accountId => {
      this.logDestination.addToPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        principals: [new iam.AccountPrincipal(accountId)],
        actions: ['logs:PutSubscriptionFilter'],
        resources: [this.logDestination.destinationArn]
      }));
    });
  }
}
```

Configure log forwarding in source accounts:

```typescript
// Requires: import * as events from 'aws-cdk-lib/aws-events';
//           import * as events_targets from 'aws-cdk-lib/aws-events-targets';
export class SourceAccountLoggingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    centralLoggingDestinationArn: string;
    logGroupNames: string[];
  }) {
    super(scope, id, props);

    // CDK's `SubscriptionFilter` L2 needs an `ILogSubscriptionDestination`, and
    // there is no L2 for "a destination ARN owned by another account", so drop
    // to the L1 resource. (`logs.LogDestination.fromLogDestinationArn` does not
    // exist.)
    props?.logGroupNames?.forEach((logGroupName, index) => {
      new logs.CfnSubscriptionFilter(this, `CrossAccountSubscriptionFilter${index}`, {
        logGroupName: logGroupName,
        destinationArn: props.centralLoggingDestinationArn,
        filterPattern: '',   // empty string = forward every event
        // `replace('/', '-')` with a string argument only replaces the FIRST
        // occurrence, so `/aws/lambda/foo` becomes `-aws/lambda/foo`. Use a
        // global regex.
        filterName: `cross-account-filter-${logGroupName.replace(/\//g, '-')}`
      });
    });

    // Before you subscribe everything, two hard constraints:
    //
    //  * A log group accepts at most two subscription filters. If something
    //    else already consumes these groups, adding this one fails.
    //  * Subscribing *every* log group includes the log group of the
    //    forwarding infrastructure itself. The auto-subscription function
    //    below logs each group it subscribes, those logs get forwarded, and
    //    you have built a feedback loop that bills by the GB. Exclude the
    //    monitoring plumbing explicitly.

    // Lambda that subscribes new log groups as they are created.
    //
    // Note the SDK import. AWS SDK v2 (`require('aws-sdk')`) is not bundled in
    // the Node.js 18 and later managed runtimes and reached end of support in
    // 2025 -- code written against it fails at runtime with
    // "Cannot find module 'aws-sdk'". Use the v3 modular clients, which are
    // present in the runtime.
    const autoSubscriptionFunction = new lambda.Function(this, 'AutoSubscriptionFunction', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
        const { CloudWatchLogsClient, PutSubscriptionFilterCommand } =
          require('@aws-sdk/client-cloudwatch-logs');

        const client = new CloudWatchLogsClient({});

        // Never subscribe the forwarding plumbing to itself.
        const EXCLUDED = [/^\\/aws\\/lambda\\/.*AutoSubscription/, /^\\/aws\\/kinesisfirehose\\//];

        exports.handler = async (event) => {
          const logGroupName = event?.detail?.requestParameters?.logGroupName;

          if (event?.detail?.eventName !== 'CreateLogGroup' || !logGroupName) {
            return { handled: false };
          }

          if (EXCLUDED.some((pattern) => pattern.test(logGroupName))) {
            console.log('Skipping excluded log group:', logGroupName);
            return { handled: false };
          }

          await client.send(new PutSubscriptionFilterCommand({
            logGroupName,
            filterName: 'cross-account-filter-' + logGroupName.replace(/\\//g, '-'),
            filterPattern: '',
            destinationArn: process.env.DESTINATION_ARN
          }));

          console.log('Created subscription filter for log group:', logGroupName);
          return { handled: true };
        };
      `),
      environment: {
        DESTINATION_ARN: props?.centralLoggingDestinationArn || ''
      }
    });

    // Grant permissions to manage subscription filters
    autoSubscriptionFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:PutSubscriptionFilter',
        'logs:DeleteSubscriptionFilter',
        'logs:DescribeSubscriptionFilters'
      ],
      resources: [`arn:aws:logs:${this.region}:${this.account}:log-group:*`]
    }));

    // The function needs a trigger. CreateLogGroup is a CloudTrail management
    // event, so it arrives on the default event bus only when a trail is
    // capturing write events in this account and region.
    new events.Rule(this, 'NewLogGroupRule', {
      eventPattern: {
        source: ['aws.logs'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['logs.amazonaws.com'],
          eventName: ['CreateLogGroup']
        }
      },
      targets: [new events_targets.LambdaFunction(autoSubscriptionFunction)]
    });
  }
}
```

## Step 4: AWS Config Aggregators for Compliance

AWS Config aggregators provide centralized compliance monitoring and governance across multiple accounts. This capability enables organizations to maintain consistent security postures and regulatory compliance across their multi-account architectures.

Set up a configuration aggregator in the central monitoring account:

```typescript
import * as config from 'aws-cdk-lib/aws-config';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';

export class ConfigAggregatorStack extends cdk.Stack {
  public readonly configAggregator: config.ConfigurationAggregator;
  public readonly complianceReportsBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    sourceAccounts: Array<{
      accountId: string;
      regions: string[];
    }>;
    organizationId?: string;
  }) {
    super(scope, id, props);

    // S3 bucket for compliance reports
    this.complianceReportsBucket = new s3.Bucket(this, 'ComplianceReportsBucket', {
      bucketName: `config-compliance-reports-${this.account}-${this.region}`,
      versioned: true,
      lifecycleRules: [{
        id: 'compliance-report-retention',
        enabled: true,
        expiration: cdk.Duration.days(2555) // 7 years retention for compliance
      }]
    });

    // The managed policy is `service-role/AWS_ConfigRole` -- note the
    // underscore. `service-role/ConfigRole` does not exist and the stack fails
    // at deploy time with NoSuchEntity.
    //
    // For an *organization* aggregator you want
    // `service-role/AWSConfigRoleForOrganizations` instead, which is what
    // grants the organizations:* reads below.
    const configAggregatorRole = new iam.Role(this, 'ConfigAggregatorRole', {
      roleName: 'AWSConfigRoleForConfigurationAggregator',
      assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          props?.organizationId
            ? 'service-role/AWSConfigRoleForOrganizations'
            : 'service-role/AWS_ConfigRole'
        )
      ]
    });

    // Grant permissions to access source accounts
    configAggregatorRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'organizations:DescribeAccount',
        'organizations:DescribeOrganization',
        'organizations:ListAccounts',
        'organizations:ListAWSServiceAccessForOrganization'
      ],
      resources: ['*']
    }));

    // Create configuration aggregator
    if (props?.organizationId) {
      // Organization-based aggregator (recommended for AWS Organizations).
      //
      // Two prerequisites the template cannot express: this stack must be
      // deployed in the organization's management account or in an account
      // registered as a Config *delegated administrator*, and trusted access
      // for `config.amazonaws.com` must be enabled for the organization. Miss
      // either and creation fails with OrganizationAccessDeniedException.
      this.configAggregator = new config.ConfigurationAggregator(this, 'OrganizationConfigAggregator', {
        configurationAggregatorName: 'organization-config-aggregator',
        organizationAggregationSource: {
          roleArn: configAggregatorRole.roleArn,
          allAwsRegions: true
        }
      });
    } else {
      // Account-based aggregator
      const accountAggregationSources = props?.sourceAccounts?.map(account => ({
        accountIds: [account.accountId],
        awsRegions: account.regions,
        allAwsRegions: false
      })) || [];

      this.configAggregator = new config.ConfigurationAggregator(this, 'AccountConfigAggregator', {
        configurationAggregatorName: 'cross-account-config-aggregator',
        accountAggregationSources: accountAggregationSources
      });
    }

    // Config rules for compliance monitoring.
    //
    // Important scoping caveat: `config.ManagedRule` creates an
    // `AWS::Config::ConfigRule`, which evaluates only the account it is
    // deployed into. Creating these here gives you rules for the *monitoring*
    // account, not org-wide coverage -- the aggregator collects results, it
    // does not deploy rules.
    //
    // To evaluate every account, deploy the rules from the management or
    // delegated-admin account as `AWS::Config::OrganizationConfigRule`, or use
    // a conformance pack, and let this aggregator collect the findings.
    this.createComplianceRules();
  }

  private createComplianceRules(): void {
    // Root access key check
    new config.ManagedRule(this, 'RootAccessKeyCheck', {
      configRuleName: 'root-access-key-check',
      identifier: config.ManagedRuleIdentifiers.ROOT_ACCESS_KEY_CHECK,
      description: 'Checks whether the root user access key is available'
    });

    // S3 bucket SSL requests only
    new config.ManagedRule(this, 'S3BucketSslRequestsOnly', {
      configRuleName: 's3-bucket-ssl-requests-only',
      identifier: config.ManagedRuleIdentifiers.S3_BUCKET_SSL_REQUESTS_ONLY,
      description: 'Checks whether S3 buckets have policies that require requests to use SSL'
    });

    // IAM password policy
    new config.ManagedRule(this, 'IamPasswordPolicy', {
      configRuleName: 'iam-password-policy',
      identifier: config.ManagedRuleIdentifiers.IAM_PASSWORD_POLICY,
      description: 'Checks whether the account password policy meets specified requirements',
      inputParameters: {
        RequireUppercaseCharacters: 'true',
        RequireLowercaseCharacters: 'true',
        RequireNumbers: 'true',
        RequireSymbols: 'true',
        MinimumPasswordLength: '14',
        PasswordReusePrevention: '24',
        MaxPasswordAge: '90'
      }
    });

    // CloudTrail enabled
    new config.ManagedRule(this, 'CloudTrailEnabled', {
      configRuleName: 'cloudtrail-enabled',
      identifier: config.ManagedRuleIdentifiers.CLOUD_TRAIL_ENABLED,
      description: 'Checks whether AWS CloudTrail is enabled'
    });
  }
}
```

Create a compliance reporting system:

```typescript
import {
  ConfigServiceClient,
  DescribeAggregateComplianceByConfigRulesCommand
} from '@aws-sdk/client-config-service';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';

export interface ComplianceReportConfig {
  aggregatorName: string;
  reportBucket: string;
  emailRecipients: string[];
  region: string;
}

export class ComplianceReportGenerator {
  private readonly configClient: ConfigServiceClient;
  private readonly s3Client: S3Client;
  private readonly sesClient: SESClient;
  private readonly config: ComplianceReportConfig;

  constructor(config: ComplianceReportConfig) {
    this.config = config;
    this.configClient = new ConfigServiceClient({ region: config.region });
    this.s3Client = new S3Client({ region: config.region });
    this.sesClient = new SESClient({ region: config.region });
  }

  async generateComplianceReport(): Promise<void> {
    console.log('Generating cross-account compliance report');

    const complianceData = await this.getAggregateComplianceData();
    const report = this.formatComplianceReport(complianceData);
    
    const reportKey = `compliance-reports/${new Date().toISOString().split('T')[0]}/compliance-report.json`;
    
    await this.uploadReportToS3(report, reportKey);
    await this.sendComplianceNotification(report);
    
    console.log('Compliance report generated and distributed successfully');
  }

  // `GetAggregateComplianceDetailsByConfigRule` requires `AccountId` and
  // `AwsRegion` -- both are mandatory, so calling it with only the aggregator
  // and rule name fails validation. That also makes it the wrong API for an
  // org-wide rollup: you would have to enumerate every account/region pair.
  //
  // `DescribeAggregateComplianceByConfigRules` is the API that answers
  // "which rules are non-compliant anywhere in the aggregator", and it
  // paginates, which matters -- the details API caps a page at 50 results, so
  // an unpaginated `.length` silently under-reports the violation count.
  private async getAggregateComplianceData(): Promise<any[]> {
    const complianceResults: any[] = [];
    let nextToken: string | undefined;

    do {
      const response = await this.configClient.send(
        new DescribeAggregateComplianceByConfigRulesCommand({
          ConfigurationAggregatorName: this.config.aggregatorName,
          Filters: { ComplianceType: 'NON_COMPLIANT' },
          NextToken: nextToken
        })
      );

      for (const item of response.AggregateComplianceByConfigRules ?? []) {
        complianceResults.push({
          ruleName: item.ConfigRuleName,
          accountId: item.AccountId,
          region: item.AwsRegion,
          complianceType: item.Compliance?.ComplianceType,
          nonCompliantResourceCount:
            item.Compliance?.ComplianceContributorCount?.CappedCount ?? 0,
          countIsCapped:
            item.Compliance?.ComplianceContributorCount?.CapExceeded ?? false
        });
      }

      nextToken = response.NextToken;
    } while (nextToken);

    return complianceResults;
  }

  private formatComplianceReport(complianceData: any[]): any {
    const totalNonCompliant = complianceData.reduce(
      (sum, rule) => sum + rule.nonCompliantResourceCount, 0
    );
    const accountSummary = new Map<string, any>();

    complianceData.forEach(rule => {
      if (!accountSummary.has(rule.accountId)) {
        accountSummary.set(rule.accountId, {
          accountId: rule.accountId,
          nonCompliantRules: [],
          totalNonCompliant: 0
        });
      }

      const account = accountSummary.get(rule.accountId);
      account.nonCompliantRules.push({
        ruleName: rule.ruleName,
        region: rule.region,
        resourceCount: rule.nonCompliantResourceCount,
        countIsCapped: rule.countIsCapped
      });
      account.totalNonCompliant += rule.nonCompliantResourceCount;
    });

    return {
      generatedAt: new Date().toISOString(),
      summary: {
        totalRulesEvaluated: complianceData.length,
        totalNonCompliantResources: totalNonCompliant,
        accountsWithViolations: accountSummary.size
      },
      ruleDetails: complianceData,
      accountSummary: Array.from(accountSummary.values())
    };
  }

  private async uploadReportToS3(report: any, key: string): Promise<void> {
    const command = new PutObjectCommand({
      Bucket: this.config.reportBucket,
      Key: key,
      Body: JSON.stringify(report, null, 2),
      ContentType: 'application/json'
    });

    await this.s3Client.send(command);
    console.log(`Compliance report uploaded to S3: s3://${this.config.reportBucket}/${key}`);
  }

  private async sendComplianceNotification(report: any): Promise<void> {
    const subject = `Cross-Account Compliance Report - ${new Date().toDateString()}`;
    const body = this.generateEmailBody(report);

    for (const recipient of this.config.emailRecipients) {
      try {
        const command = new SendEmailCommand({
          Source: 'compliance-reports@yourcompany.com',
          Destination: {
            ToAddresses: [recipient]
          },
          Message: {
            Subject: { Data: subject },
            Body: {
              Html: { Data: body }
            }
          }
        });

        await this.sesClient.send(command);
        console.log(`Compliance notification sent to ${recipient}`);
      } catch (error) {
        console.error(`Failed to send notification to ${recipient}:`, error);
      }
    }
  }

  private generateEmailBody(report: any): string {
    return `
      <html>
        <body>
          <h2>Cross-Account Compliance Report</h2>
          <p><strong>Generated:</strong> ${report.generatedAt}</p>
          
          <h3>Summary</h3>
          <ul>
            <li>Total Rules Evaluated: ${report.summary.totalRulesEvaluated}</li>
            <li>Total Non-Compliant Resources: ${report.summary.totalNonCompliantResources}</li>
            <li>Accounts with Violations: ${report.summary.accountsWithViolations}</li>
          </ul>
          
          <h3>Account Details</h3>
          ${report.accountSummary.map((account: any) => `
            <h4>Account: ${account.accountId}</h4>
            <ul>
              <li>Non-Compliant Resources: ${account.totalNonCompliant}</li>
              <li>Rules with Violations: ${account.nonCompliantRules.length}</li>
            </ul>
          `).join('')}
          
          <p>For detailed compliance information, please check the AWS Config console or the full report in S3.</p>
        </body>
      </html>
    `;
  }
}
```

## Step 5: Cost and Billing Consolidation

Cost and billing consolidation provides unified visibility into spending across multiple AWS accounts, enabling better cost management, allocation, and optimization decisions. This pattern is essential for organizations that need to track costs across different business units, projects, or environments.

Set up cost and billing consolidation using AWS Cost and Usage Reports:

```typescript
import * as cur from 'aws-cdk-lib/aws-cur';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as athena from 'aws-cdk-lib/aws-athena';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';

export class CostBillingConsolidationStack extends cdk.Stack {
  public readonly costReportsBucket: s3.Bucket;
  public readonly costDatabase: glue.CfnDatabase;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // S3 bucket for Cost and Usage Reports
    this.costReportsBucket = new s3.Bucket(this, 'CostReportsBucket', {
      bucketName: `aws-cost-reports-${this.account}-${this.region}`,
      versioned: true,
      lifecycleRules: [{
        id: 'cost-report-retention',
        enabled: true,
        transitions: [{
          storageClass: s3.StorageClass.INFREQUENT_ACCESS,
          transitionAfter: cdk.Duration.days(30)
        }],
        expiration: cdk.Duration.days(1095) // 3 years retention
      }]
    });

    // Create Cost and Usage Report.
    //
    // Two constraints that will stop this stack cold: the CUR API is only
    // available in us-east-1, so this stack must be deployed there regardless
    // of where the bucket lives; and a CUR covering every member account can
    // only be created from the organization's management account.
    const costReport = new cur.ReportDefinition(this, 'CrossAccountCostReport', {
      reportName: 'cross-account-cost-usage-report',
      timeUnit: cur.TimeUnit.DAILY,
      format: cur.Format.PARQUET,
      compression: cur.Compression.PARQUET,
      additionalSchemaElements: [
        cur.AdditionalSchemaElement.RESOURCES
      ],
      s3Bucket: this.costReportsBucket,
      s3Prefix: 'cost-reports/',
      s3Region: this.region,
      additionalArtifacts: [
        cur.AdditionalArtifact.ATHENA
      ],
      refreshClosedReports: true,
      reportVersioning: cur.ReportVersioning.OVERWRITE_REPORT
    });

    // Glue and Athena have no stable L2 constructs in `aws-cdk-lib`: the Glue
    // L2 lives in the separate `@aws-cdk/aws-glue-alpha` package, and Athena
    // has L1 only. `new glue.Database(...)` and `new athena.WorkGroup(...)`
    // do not compile against `aws-cdk-lib` -- use the Cfn resources.
    this.costDatabase = new glue.CfnDatabase(this, 'CostAnalyticsDatabase', {
      catalogId: this.account,
      databaseInput: {
        name: 'cost_analytics_db',
        description: 'Database for cross-account cost and usage analysis'
      }
    });

    const costAnalyticsWorkgroup = new athena.CfnWorkGroup(this, 'CostAnalyticsWorkgroup', {
      name: 'cost-analytics-workgroup',
      description: 'Workgroup for cross-account cost analysis queries',
      workGroupConfiguration: {
        resultConfiguration: {
          outputLocation: `s3://${this.costReportsBucket.bucketName}/athena-results/`,
          encryptionConfiguration: { encryptionOption: 'SSE_S3' }
        },
        // A hard cap is worth setting on a workgroup that queries CUR data --
        // one unpartitioned query over years of reports can scan terabytes.
        bytesScannedCutoffPerQuery: 10 * 1024 * 1024 * 1024,  // 10 GiB
        enforceWorkGroupConfiguration: true
      }
    });

    this.createCostAnalyticsResources();
  }

  private createCostAnalyticsResources(): void {
    // Lambda function for cost analysis automation
    const costAnalysisFunction = new lambda.Function(this, 'CostAnalysisFunction', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda/cost-analysis'),
      timeout: cdk.Duration.minutes(15),
      memorySize: 1024,
      environment: {
        COST_DATABASE: 'cost_analytics_db',
        COST_REPORTS_BUCKET: this.costReportsBucket.bucketName
      }
    });

    // Grant permissions for cost analysis
    this.costReportsBucket.grantRead(costAnalysisFunction);
    costAnalysisFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'athena:StartQueryExecution',
        'athena:GetQueryResults',
        'athena:GetQueryExecution'
      ],
      resources: [
        `arn:aws:athena:${this.region}:${this.account}:workgroup/cost-analytics-workgroup`
      ]
    }));

    // Athena reads table metadata through Glue and needs catalog, database and
    // table ARNs -- granting only `glue:GetTable` on the table is not enough.
    costAnalysisFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['glue:GetDatabase', 'glue:GetTable', 'glue:GetPartitions'],
      resources: [
        `arn:aws:glue:${this.region}:${this.account}:catalog`,
        `arn:aws:glue:${this.region}:${this.account}:database/cost_analytics_db`,
        `arn:aws:glue:${this.region}:${this.account}:table/cost_analytics_db/*`
      ]
    }));

    // Athena writes results to S3 as the caller, so the function needs write
    // access to the results prefix as well as read access to the reports.
    this.costReportsBucket.grantWrite(costAnalysisFunction, 'athena-results/*');

    // Schedule daily cost analysis
    const costAnalysisSchedule = new events.Rule(this, 'CostAnalysisSchedule', {
      schedule: events.Schedule.rate(cdk.Duration.days(1)),
      description: 'Daily cross-account cost analysis'
    });

    costAnalysisSchedule.addTarget(new events_targets.LambdaFunction(costAnalysisFunction));
  }
}
```

Create a cost analysis and alerting system:

```typescript
import {
  AthenaClient,
  StartQueryExecutionCommand,
  GetQueryExecutionCommand,
  GetQueryResultsCommand
} from '@aws-sdk/client-athena';
import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

export interface CostAnalysisConfig {
  costDatabase: string;
  costTable: string;
  athenaWorkgroup: string;
  alertThresholds: {
    dailySpendThreshold: number;
    monthlySpendThreshold: number;
    accountSpendThreshold: number;
  };
  snsTopicArn: string;
}

export class CrossAccountCostAnalyzer {
  private cachedHeaders?: string[];
  private readonly athenaClient: AthenaClient;
  private readonly snsClient: SNSClient;
  private readonly config: CostAnalysisConfig;

  constructor(config: CostAnalysisConfig) {
    this.config = config;
    this.athenaClient = new AthenaClient({ region: 'us-east-1' });
    this.snsClient = new SNSClient({ region: 'us-east-1' });
  }

  async analyzeCrossAccountCosts(): Promise<void> {
    console.log('Starting cross-account cost analysis');

    try {
      const dailyCosts = await this.getDailyCostsByAccount();
      const monthlyCosts = await this.getMonthlyCostsByAccount();
      const topServices = await this.getTopServicesBySpend();

      const analysis = {
        generatedAt: new Date().toISOString(),
        dailyCosts,
        monthlyCosts,
        topServices,
        alerts: this.generateCostAlerts(dailyCosts, monthlyCosts)
      };

      await this.publishCostAnalysis(analysis);
      
      if (analysis.alerts.length > 0) {
        await this.sendCostAlert(analysis.alerts);
      }

      console.log('Cross-account cost analysis completed successfully');
    } catch (error) {
      console.error('Cost analysis failed:', error);
      throw error;
    }
  }

  private async executeQuery(query: string): Promise<any[]> {
    // No `ResultConfiguration` here: the workgroup already defines an output
    // location, and overriding it with a hardcoded bucket that does not exist
    // fails every query. Let the workgroup own it.
    const startResponse = await this.athenaClient.send(
      new StartQueryExecutionCommand({
        QueryString: query,
        WorkGroup: this.config.athenaWorkgroup
      })
    );

    const queryExecutionId = startResponse.QueryExecutionId!;

    // Poll for the terminal state rather than sleeping a fixed interval. A
    // 10-second sleep is both too long for a fast query and far too short for
    // a slow one -- and because a FAILED query still returns an empty result
    // set, a fixed sleep turns a broken query into "zero costs this month".
    await this.waitForQuery(queryExecutionId);

    // GetQueryResults pages at 1,000 rows.
    const rows: any[] = [];
    let nextToken: string | undefined;

    do {
      const resultsResponse = await this.athenaClient.send(
        new GetQueryResultsCommand({
          QueryExecutionId: queryExecutionId,
          NextToken: nextToken
        })
      );

      rows.push(...this.parseQueryResults(resultsResponse.ResultSet, nextToken === undefined));
      nextToken = resultsResponse.NextToken;
    } while (nextToken);

    return rows;
  }

  private async waitForQuery(queryExecutionId: string): Promise<void> {
    const deadline = Date.now() + 5 * 60 * 1000;
    let delay = 500;

    while (Date.now() < deadline) {
      const { QueryExecution } = await this.athenaClient.send(
        new GetQueryExecutionCommand({ QueryExecutionId: queryExecutionId })
      );

      const state = QueryExecution?.Status?.State;

      if (state === 'SUCCEEDED') return;
      if (state === 'FAILED' || state === 'CANCELLED') {
        throw new Error(
          `Athena query ${state}: ${QueryExecution?.Status?.StateChangeReason ?? 'no reason given'}`
        );
      }

      await new Promise(resolve => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, 5000);
    }

    throw new Error(`Athena query ${queryExecutionId} did not finish within 5 minutes`);
  }

  // Athena includes the header row only in the FIRST page of results, so a
  // paginated read must not strip row 0 from subsequent pages.
  private parseQueryResults(resultSet: any, isFirstPage: boolean): any[] {
    if (!resultSet?.Rows?.length) {
      return [];
    }

    const headers = (this.cachedHeaders ??= resultSet.Rows[0].Data.map(
      (col: any) => col.VarCharValue
    ));
    const rows = isFirstPage ? resultSet.Rows.slice(1) : resultSet.Rows;

    return rows.map((row: any) => {
      const rowData: any = {};
      row.Data.forEach((col: any, index: number) => {
        rowData[headers[index]] = col.VarCharValue;
      });
      return rowData;
    });
  }

  // Always constrain the partition columns. The CUR table is partitioned by
  // year and month; filtering only on `line_item_usage_start_date` makes
  // Athena scan every partition you have ever written -- years of data, at
  // $5/TB, to answer a question about last week. In a cost-optimisation
  // pipeline that is a particularly bad bug, because the query bill is
  // invisible in the report it produces.
  private async getDailyCostsByAccount(): Promise<any[]> {
    const query = `
      SELECT
        line_item_usage_account_id as account_id,
        date_trunc('day', line_item_usage_start_date) as usage_date,
        SUM(line_item_unblended_cost) as daily_cost
      FROM ${this.config.costDatabase}.${this.config.costTable}
      WHERE year = CAST(year(current_date) AS varchar)
        AND month = CAST(month(current_date) AS varchar)
        AND line_item_usage_start_date >= current_date - interval '7' day
        AND line_item_line_item_type NOT IN ('Tax', 'Credit', 'Refund')
      GROUP BY line_item_usage_account_id, date_trunc('day', line_item_usage_start_date)
      ORDER BY daily_cost DESC
    `;

    return await this.executeQuery(query);
  }

  private async getMonthlyCostsByAccount(): Promise<any[]> {
    const query = `
      SELECT 
        line_item_usage_account_id as account_id,
        date_trunc('month', line_item_usage_start_date) as month,
        SUM(line_item_unblended_cost) as monthly_cost
      FROM ${this.config.costDatabase}.${this.config.costTable}
      WHERE line_item_usage_start_date >= date_trunc('month', current_date - interval '2' month)
      GROUP BY line_item_usage_account_id, date_trunc('month', line_item_usage_start_date)
      ORDER BY monthly_cost DESC
    `;

    return await this.executeQuery(query);
  }

  private async getTopServicesBySpend(): Promise<any[]> {
    const query = `
      SELECT 
        line_item_product_code as service,
        line_item_usage_account_id as account_id,
        SUM(line_item_unblended_cost) as service_cost
      FROM ${this.config.costDatabase}.${this.config.costTable}
      WHERE line_item_usage_start_date >= current_date - interval '30' day
      GROUP BY line_item_product_code, line_item_usage_account_id
      ORDER BY service_cost DESC
      LIMIT 20
    `;

    return await this.executeQuery(query);
  }

  private generateCostAlerts(dailyCosts: any[], monthlyCosts: any[]): any[] {
    const alerts = [];

    // Check daily spend thresholds
    dailyCosts.forEach(cost => {
      if (parseFloat(cost.daily_cost) > this.config.alertThresholds.dailySpendThreshold) {
        alerts.push({
          type: 'DAILY_SPEND_THRESHOLD',
          accountId: cost.account_id,
          amount: cost.daily_cost,
          threshold: this.config.alertThresholds.dailySpendThreshold,
          date: cost.usage_date
        });
      }
    });

    // Check monthly spend thresholds
    monthlyCosts.forEach(cost => {
      if (parseFloat(cost.monthly_cost) > this.config.alertThresholds.monthlySpendThreshold) {
        alerts.push({
          type: 'MONTHLY_SPEND_THRESHOLD',
          accountId: cost.account_id,
          amount: cost.monthly_cost,
          threshold: this.config.alertThresholds.monthlySpendThreshold,
          month: cost.month
        });
      }
    });

    return alerts;
  }

  private async publishCostAnalysis(analysis: any): Promise<void> {
    console.log('Publishing cost analysis results:', {
      accounts: analysis.dailyCosts.length,
      alerts: analysis.alerts.length,
      topServices: analysis.topServices.length
    });

    // Implementation would store analysis results in S3, DynamoDB, or other storage
    // for dashboard consumption and historical tracking
  }

  private async sendCostAlert(alerts: any[]): Promise<void> {
    const message = {
      subject: 'Cross-Account Cost Alert',
      body: `Cost thresholds exceeded in ${alerts.length} cases:\n\n` +
            alerts.map(alert => 
              `Account ${alert.accountId}: $${alert.amount} exceeded threshold of $${alert.threshold}`
            ).join('\n')
    };

    const command = new PublishCommand({
      TopicArn: this.config.snsTopicArn,
      Subject: message.subject,
      Message: message.body
    });

    await this.snsClient.send(command);
    console.log('Cost alert sent successfully');
  }
}
```

## Step 6: Monitoring Dashboard Integration

Create unified monitoring dashboards that combine data from all cross-account observability sources:

```typescript
export class UnifiedMonitoringDashboardStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const dashboard = new cloudwatch.Dashboard(this, 'UnifiedCrossAccountDashboard', {
      dashboardName: 'unified-cross-account-monitoring'
    });

    // Add cross-account metrics widgets
    dashboard.addWidgets(
      // Application performance across accounts
      new cloudwatch.GraphWidget({
        title: 'Cross-Account Application Performance',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/Lambda',
            metricName: 'Duration',
            statistic: 'Average',
            account: '222222222222'
          }),
          new cloudwatch.Metric({
            namespace: 'AWS/Lambda',
            metricName: 'Duration',
            statistic: 'Average',
            account: '333333333333'
          })
        ],
        width: 24,
        height: 6
      }),

      // Error rates across accounts
      new cloudwatch.GraphWidget({
        title: 'Cross-Account Error Rates',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/Lambda',
            metricName: 'Errors',
            statistic: 'Sum',
            account: '222222222222'
          }),
          new cloudwatch.Metric({
            namespace: 'AWS/Lambda',
            metricName: 'Errors',
            statistic: 'Sum',
            account: '333333333333'
          })
        ],
        width: 12,
        height: 6
      }),

      // Cost trends.
      //
      // A per-member-account `AWS/Billing` widget does not work, and this is a
      // common disappointment. Under consolidated billing, EstimatedCharges is
      // published only by the *payer* account, and only into us-east-1, and
      // only if "Receive Billing Alerts" is enabled. Pointing the metric at a
      // member account with `account:` yields an empty graph, not an error.
      //
      // For per-account spend, query the Cost and Usage Report with Athena as
      // shown below and publish your own custom metric, or use AWS Budgets and
      // Cost Anomaly Detection, which are built for this.
      new cloudwatch.GraphWidget({
        title: 'Estimated Charges (payer account, us-east-1)',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/Billing',
            metricName: 'EstimatedCharges',
            statistic: 'Maximum',
            dimensionsMap: { Currency: 'USD' },
            region: 'us-east-1'
          })
        ],
        width: 12,
        height: 6
      })
    );

    // Add compliance status widget
    dashboard.addWidgets(
      new cloudwatch.SingleValueWidget({
        title: 'Cross-Account Compliance Status',
        metrics: [
          new cloudwatch.Metric({
            namespace: 'AWS/Config',
            metricName: 'ComplianceByConfigRule',
            statistic: 'Average',
            dimensionsMap: { 
              ComplianceType: 'COMPLIANT',
              ConfigRuleName: 'root-access-key-check'
            }
          })
        ],
        width: 6,
        height: 4
      })
    );
  }
}
```

## Security Best Practices and Monitoring

Implementing comprehensive security monitoring across cross-account observability infrastructure ensures that monitoring systems themselves don't become security vulnerabilities while providing the visibility needed for threat detection and compliance.

Set up security monitoring for cross-account access:

```typescript
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as logs from 'aws-cdk-lib/aws-logs';

export class SecurityMonitoringStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // CloudTrail for cross-account API monitoring.
    //
    // `sendToCloudWatchLogs` is required. Without it, `trail.logGroup` is
    // undefined, and the non-null assertion below (`trail.logGroup!`) throws
    // during synthesis -- the trail only writes to S3 by default.
    const monitoringCloudTrail = new cloudtrail.Trail(this, 'CrossAccountMonitoringTrail', {
      trailName: 'cross-account-monitoring-trail',
      includeGlobalServiceEvents: true,
      isLogging: true,
      enableFileValidation: true,
      sendToCloudWatchLogs: true,
      cloudWatchLogsRetention: logs.RetentionDays.ONE_YEAR
    });

    // Metric filters first, then alarms on those filters.
    //
    // There is no `AWS/CloudTrail` namespace, and no `AssumeRoleFailures`
    // metric -- CloudTrail publishes events, not CloudWatch metrics. An alarm
    // on a nonexistent metric never fires and sits in INSUFFICIENT_DATA
    // forever, which looks indistinguishable from "no problems detected".
    // The only way to alarm on CloudTrail content is to extract a metric from
    // the log group with a metric filter, then alarm on *that* metric.
    const failedAssumeRoleFilter = new logs.MetricFilter(this, 'FailedAssumeRoleFilter', {
      logGroup: monitoringCloudTrail.logGroup!,
      metricNamespace: 'SecurityMonitoring/CrossAccount',
      metricName: 'FailedAssumeRole',
      filterPattern: logs.FilterPattern.literal(
        '{ ($.eventName = "AssumeRole*") && ($.errorCode = "*") }'
      ),
      metricValue: '1',
      defaultValue: 0
    });

    const suspiciousAssumeRoleAlarm = new cloudwatch.Alarm(this, 'SuspiciousAssumeRoleActivity', {
      alarmName: 'cross-account-suspicious-assume-role',
      // Alarm on the metric the filter actually publishes.
      metric: failedAssumeRoleFilter.metric({ statistic: 'Sum' }),
      threshold: 10,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      alarmDescription: 'Repeated cross-account role assumption failures'
    });

    // Successful cross-account access, tracked separately for baselining.
    const crossAccountAccessFilter = new logs.MetricFilter(this, 'CrossAccountAccessFilter', {
      logGroup: monitoringCloudTrail.logGroup!,
      metricNamespace: 'SecurityMonitoring/CrossAccount',
      metricName: 'CrossAccountAccess',
      filterPattern: logs.FilterPattern.literal(
        '{ ($.eventName = AssumeRole) && ($.errorCode NOT EXISTS) }'
      ),
      metricValue: '1',
      defaultValue: 0
    });

    // One more scoping caveat: a `cloudtrail.Trail` covers only this account.
    // To see cross-account activity you need an organization trail created
    // from the management account with `isOrganizationTrail` enabled.
  }
}
```

## Testing and Validation

Comprehensive testing ensures that cross-account monitoring and observability systems function correctly and provide accurate insights across all integrated accounts.

Create automated tests for monitoring functionality. Treat these as smoke tests against a real account rather than unit tests — they need live credentials and real data, so keep them out of the pull-request path and avoid asserting on data volume (`length > 0` fails on a quiet Sunday, which teaches the team to ignore the suite):

```typescript
// monitoring-integration.test.ts - Integration tests for cross-account monitoring
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { CloudWatchClient, GetMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { XRayClient, GetServiceGraphCommand } from '@aws-sdk/client-xray';
import {
  ConfigServiceClient,
  DescribeAggregateComplianceByConfigRulesCommand
} from '@aws-sdk/client-config-service';

describe('Cross-Account Monitoring Integration Tests', () => {
  let cloudWatchClient: CloudWatchClient;
  let xrayClient: XRayClient;
  let configClient: ConfigServiceClient;

  beforeAll(() => {
    cloudWatchClient = new CloudWatchClient({ region: 'us-east-1' });
    xrayClient = new XRayClient({ region: 'us-east-1' });
    configClient = new ConfigServiceClient({ region: 'us-east-1' });
  });

  it('should retrieve cross-account CloudWatch metrics', async () => {
    const command = new GetMetricDataCommand({
      MetricDataQueries: [{
        Id: 'cross_account_lambda_duration',
        MetricStat: {
          Metric: {
            Namespace: 'AWS/Lambda',
            MetricName: 'Duration'
          },
          Period: 300,
          Stat: 'Average'
        }
      }],
      StartTime: new Date(Date.now() - 3600000), // 1 hour ago
      EndTime: new Date()
    });

    const response = await cloudWatchClient.send(command);
    expect(response.MetricDataResults).toBeDefined();
  });

  it('should aggregate X-Ray service maps across accounts', async () => {
    const command = new GetServiceGraphCommand({
      StartTime: new Date(Date.now() - 3600000),
      EndTime: new Date()
    });

    const response = await xrayClient.send(command);
    expect(response.Services).toBeDefined();
  });

  it('should retrieve Config aggregator compliance data', async () => {
    // `GetConfigRuleEvaluationStatus` reads rules in the *local* account and
    // says nothing about the aggregator. Query the aggregator explicitly.
    const command = new DescribeAggregateComplianceByConfigRulesCommand({
      ConfigurationAggregatorName: 'organization-config-aggregator'
    });

    const response = await configClient.send(command);
    expect(response.AggregateComplianceByConfigRules).toBeDefined();
  });
});
```

Cross-account monitoring and observability provides the foundation for maintaining operational excellence across complex multi-account AWS architectures. The patterns we've explored - centralized dashboards, distributed tracing aggregation, unified logging, compliance monitoring, and cost consolidation - work together to create comprehensive visibility while preserving the security boundaries that make multi-account architectures valuable.

## Key Takeaways

**Start Simple**: Turn on CloudWatch cross-account observability first. It is one sink plus one link per account, it needs no custom code, and it covers metrics, logs and traces in the consoles your team already uses. Build the custom pieces in this post only for what OAM genuinely does not reach.

**Security First**: Grant read-only access, scope it to the accounts that need it, and prefer an organization-scoped condition (`aws:PrincipalOrgID`) over a list of account IDs you have to maintain. External IDs are for third parties assuming your roles — between accounts you own they add a secret to manage without adding protection.

**Automate Everything**: Manual correlation of data across accounts doesn't scale. Build automation into your monitoring from day one, especially for compliance reporting and cost analysis.

**Plan for Growth**: Design your monitoring architecture to handle new accounts and services without requiring major refactoring. Use infrastructure as code and standardized role patterns.

## Next Steps

If you're just getting started with cross-account monitoring, I recommend this approach:

1. **Day 1**: Create an OAM sink in your monitoring account and link your production account. Metrics, logs and traces show up immediately, and this is where most of the value is.
2. **Week 1**: Link the remaining accounts and build the cross-account dashboards your on-call actually needs — not one widget per account, but one view per user journey.
3. **Week 2**: Add log forwarding to S3 for the retention and query requirements OAM does not cover.
4. **Month 2**: Extend to Config aggregators for compliance monitoring, remembering that the rules themselves need to be deployed org-wide separately.
5. **Month 3**: Add cost consolidation from the Cost and Usage Report.

The investment in comprehensive cross-account observability pays dividends in improved incident response times, better cost optimization, and enhanced compliance posture. Your 3 AM incident response scenarios will transform from frantic dashboard-hopping exercises into focused, data-driven investigations that resolve quickly and prevent recurrence.

Remember: monitoring fragmentation is a choice, not an inevitability of multi-account architectures. With the right patterns and tools, you can have both the security benefits of account separation and the operational visibility you need to run reliable systems at scale.

## More in This Series

This is post 4 of 5 in the **AWS Cross-Account Patterns** series:

1. [Cross-Account Lambda Access to S3](/posts/cross-account-lambda-s3-access/)
2. [Cross-Account EventBridge Integration](/posts/2025/07/30/cross-account-eventbridge-integration/)
3. [Implementing Cross-Account CI/CD Pipelines](/posts/2025/08/06/cross-account-cicd-pipelines/)
4. **Cross-Account Monitoring and Observability** (this post)
5. [Simplified Cross-Account Backup and Disaster Recovery](/posts/2025/08/20/simplified-aws-backup-cross-account/)
