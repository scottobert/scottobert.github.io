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
series: AWS Cross-Account Patterns
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

The cost of monitoring fragmentation extends beyond operational inconvenience. Teams report average incident resolution times increase by 300% when troubleshooting requires data from multiple accounts. More critically, the lack of proactive monitoring across account boundaries means issues often escalate to customer-impacting incidents before detection.

Organizations I've worked with have seen dramatic improvements after implementing proper cross-account monitoring: mean time to detection (MTTD) decreased from hours to minutes, false positive alerts reduced by 60%, and compliance reporting that previously took weeks now completes automatically.

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

CloudWatch cross-account dashboards provide unified visibility into metrics and alarms across multiple AWS accounts. These dashboards enable teams to monitor distributed applications from a single pane of glass while maintaining appropriate access controls.

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

    // Create role that can assume roles in source accounts
    this.monitoringRole = new iam.Role(this, 'CrossAccountMonitoringRole', {
      assumedBy: new iam.ServicePrincipal('cloudwatch.amazonaws.com'),
      description: 'Role for cross-account CloudWatch monitoring',
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

    const monitoringSourceRole = new iam.Role(this, 'MonitoringSourceRole', {
      roleName: 'MonitoringSourceRole',
      assumedBy: new iam.AccountPrincipal(props?.monitoringAccountId || ''),
      externalIds: [props?.externalId || ''],
      description: 'Allows monitoring account to access CloudWatch data'
    });

    monitoringSourceRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchReadOnlyAccess')
    );

    // Additional permissions for enhanced monitoring
    monitoringSourceRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'xray:GetServiceMap',
        'xray:GetTraceSummaries',
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

```typescript
import { XRayClient, CreateServiceMapCommand, GetServiceMapCommand } from '@aws-sdk/client-xray';
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
      RoleSessionName: `xray-aggregation-${Date.now()}`,
      ExternalId: 'xray-aggregation-external-id'
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

    const command = new GetServiceMapCommand({
      TimeRangeType: 'TraceId',
      StartTime: startTime,
      EndTime: endTime
    });

    const response = await xrayClient.send(command);
    return {
      services: response.Services || [],
      accountId: accountId
    };
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
      runtime: lambda.Runtime.NODEJS_18_X,
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
  public readonly logDestination: logs.LogDestination;
  public readonly logAnalyticsS3Bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    sourceAccounts: string[];
  }) {
    super(scope, id, props);

    // S3 bucket for centralized log storage
    this.logAnalyticsS3Bucket = new s3.Bucket(this, 'LogAnalyticsS3Bucket', {
      bucketName: `centralized-logs-${this.account}-${this.region}`,
      versioned: true,
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

    // Kinesis Firehose for S3 delivery
    const logDeliveryRole = new iam.Role(this, 'LogDeliveryRole', {
      assumedBy: new iam.ServicePrincipal('firehose.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonKinesisFirehoseFullAccess')
      ]
    });

    this.logAnalyticsS3Bucket.grantWrite(logDeliveryRole);

    const firehoseDeliveryStream = new kinesisfirehose.DeliveryStream(this, 'LogDeliveryStream', {
      deliveryStreamName: 'centralized-logs-delivery',
      destinations: [
        new kinesisfirehose.S3Destination({
          bucket: this.logAnalyticsS3Bucket,
          role: logDeliveryRole,
          prefix: 'year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/',
          errorOutputPrefix: 'errors/',
          compressionFormat: kinesisfirehose.CompressionFormat.GZIP,
          bufferingInterval: cdk.Duration.minutes(5),
          bufferingSize: cdk.Size.mebibytes(5)
        })
      ]
    });

    // IAM role for cross-account log destination
    const logDestinationRole = new iam.Role(this, 'LogDestinationRole', {
      assumedBy: new iam.ServicePrincipal('logs.amazonaws.com'),
      description: 'Role for cross-account log destination'
    });

    logStream.grantWrite(logDestinationRole);

    // Create log destination that source accounts can send logs to
    this.logDestination = new logs.LogDestination(this, 'CrossAccountLogDestination', {
      destinationName: 'cross-account-centralized-logs',
      targetArn: logStream.streamArn,
      role: logDestinationRole
    });

    // Grant source accounts permission to put logs to destination
    const logDestinationPolicy = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          principals: props?.sourceAccounts?.map(accountId => 
            new iam.AccountPrincipal(accountId)
          ) || [],
          actions: ['logs:PutSubscriptionFilter']
        })
      ]
    });

    // Apply the policy to the log destination
    new logs.LogDestinationPolicy(this, 'LogDestinationPolicy', {
      logDestination: this.logDestination,
      accessPolicy: logDestinationPolicy
    });
  }
}
```

Configure log forwarding in source accounts:

```typescript
export class SourceAccountLoggingStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps & {
    centralLoggingDestinationArn: string;
    logGroupNames: string[];
  }) {
    super(scope, id, props);

    // Create subscription filters for each log group
    props?.logGroupNames?.forEach((logGroupName, index) => {
      const logGroup = logs.LogGroup.fromLogGroupName(
        this, 
        `LogGroup${index}`, 
        logGroupName
      );

      new logs.SubscriptionFilter(this, `CrossAccountSubscriptionFilter${index}`, {
        logGroup: logGroup,
        destination: logs.LogDestination.fromLogDestinationArn(
          this,
          `CrossAccountDestination${index}`,
          props.centralLoggingDestinationArn
        ),
        filterPattern: logs.FilterPattern.allEvents(),
        filterName: `cross-account-filter-${logGroupName.replace('/', '-')}`
      });
    });

    // Lambda function to automatically create subscription filters for new log groups
    const autoSubscriptionFunction = new lambda.Function(this, 'AutoSubscriptionFunction', {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
        const AWS = require('aws-sdk');
        const logs = new AWS.CloudWatchLogs();
        
        exports.handler = async (event) => {
          console.log('Processing CloudWatch Logs event:', JSON.stringify(event, null, 2));
          
          if (event.detail.eventName === 'CreateLogGroup') {
            const logGroupName = event.detail.requestParameters.logGroupName;
            
            try {
              await logs.putSubscriptionFilter({
                logGroupName: logGroupName,
                filterName: \`cross-account-filter-\${logGroupName.replace('/', '-')}\`,
                filterPattern: '',
                destinationArn: '${props?.centralLoggingDestinationArn}'
              }).promise();
              
              console.log(\`Created subscription filter for log group: \${logGroupName}\`);
            } catch (error) {
              console.error(\`Failed to create subscription filter for \${logGroupName}:\`, error);
            }
          }
          
          return { statusCode: 200 };
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
      resources: ['*']
    }));
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

    // IAM role for Config aggregator
    const configAggregatorRole = new iam.Role(this, 'ConfigAggregatorRole', {
      roleName: 'AWSConfigRoleForConfigurationAggregator',
      assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/ConfigRole')
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
      // Organization-based aggregator (recommended for AWS Organizations)
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

    // Config rules for compliance monitoring
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
import { ConfigServiceClient, GetAggregateComplianceDetailsByConfigRuleCommand } from '@aws-sdk/client-config-service';
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

  private async getAggregateComplianceData(): Promise<any> {
    const complianceRules = [
      'root-access-key-check',
      's3-bucket-ssl-requests-only',
      'iam-password-policy',
      'cloudtrail-enabled'
    ];

    const complianceResults = [];

    for (const ruleName of complianceRules) {
      try {
        const command = new GetAggregateComplianceDetailsByConfigRuleCommand({
          ConfigurationAggregatorName: this.config.aggregatorName,
          ConfigRuleName: ruleName,
          ComplianceType: 'NON_COMPLIANT'
        });

        const response = await this.configClient.send(command);
        
        complianceResults.push({
          ruleName,
          nonCompliantResources: response.AggregateEvaluationResults || [],
          totalNonCompliant: response.AggregateEvaluationResults?.length || 0
        });
      } catch (error) {
        console.error(`Failed to get compliance data for rule ${ruleName}:`, error);
        complianceResults.push({
          ruleName,
          nonCompliantResources: [],
          totalNonCompliant: 0,
          error: error.message
        });
      }
    }

    return complianceResults;
  }

  private formatComplianceReport(complianceData: any[]): any {
    const totalNonCompliant = complianceData.reduce((sum, rule) => sum + rule.totalNonCompliant, 0);
    const accountSummary = new Map();

    complianceData.forEach(rule => {
      rule.nonCompliantResources?.forEach((resource: any) => {
        const accountId = resource.AccountId;
        if (!accountSummary.has(accountId)) {
          accountSummary.set(accountId, {
            accountId,
            nonCompliantRules: [],
            totalNonCompliant: 0
          });
        }
        
        const account = accountSummary.get(accountId);
        account.nonCompliantRules.push({
          ruleName: rule.ruleName,
          resourceType: resource.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceType,
          resourceId: resource.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceId
        });
        account.totalNonCompliant++;
      });
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
  public readonly costDatabase: glue.Database;

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

    // Create Cost and Usage Report
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

    // Glue database for cost analysis
    this.costDatabase = new glue.Database(this, 'CostAnalyticsDatabase', {
      databaseName: 'cost_analytics_db',
      description: 'Database for cross-account cost and usage analysis'
    });

    // Athena workgroup for cost queries
    const costAnalyticsWorkgroup = new athena.WorkGroup(this, 'CostAnalyticsWorkgroup', {
      name: 'cost-analytics-workgroup',
      description: 'Workgroup for cross-account cost analysis queries',
      resultConfiguration: {
        outputLocation: `s3://${this.costReportsBucket.bucketName}/athena-results/`
      }
    });

    this.createCostAnalyticsResources();
  }

  private createCostAnalyticsResources(): void {
    // Lambda function for cost analysis automation
    const costAnalysisFunction = new lambda.Function(this, 'CostAnalysisFunction', {
      runtime: lambda.Runtime.NODEJS_18_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda/cost-analysis'),
      timeout: cdk.Duration.minutes(15),
      memorySize: 1024,
      environment: {
        COST_DATABASE: this.costDatabase.databaseName,
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
        'athena:GetQueryExecution',
        'glue:GetTable',
        'glue:GetPartitions'
      ],
      resources: ['*']
    }));

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
import { AthenaClient, StartQueryExecutionCommand, GetQueryResultsCommand } from '@aws-sdk/client-athena';
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
  private readonly athenaClient: AthenaClient;
  private readonly snsClient: SNSClient;
  private readonly config: CostAnalysisConfig;

  constructor(config: CostAnalysisConfig) {
    this.config = config;
    this.athenaClient = new AthenaClient({ region: 'us-east-1' });
    this.snsClient = new SNSClient({ region: 'us-east-1' });
  }

  async analyzeCrosAccountCosts(): Promise<void> {
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
    const startCommand = new StartQueryExecutionCommand({
      QueryString: query,
      WorkGroup: this.config.athenaWorkgroup,
      ResultConfiguration: {
        OutputLocation: 's3://cost-analysis-results/'
      }
    });

    const startResponse = await this.athenaClient.send(startCommand);
    const queryExecutionId = startResponse.QueryExecutionId!;

    // Wait for query completion (simplified - production code should poll)
    await new Promise(resolve => setTimeout(resolve, 10000));

    const resultsCommand = new GetQueryResultsCommand({
      QueryExecutionId: queryExecutionId
    });

    const resultsResponse = await this.athenaClient.send(resultsCommand);
    return this.parseQueryResults(resultsResponse.ResultSet);
  }

  private parseQueryResults(resultSet: any): any[] {
    if (!resultSet?.Rows || resultSet.Rows.length <= 1) {
      return [];
    }

    const headers = resultSet.Rows[0].Data.map((col: any) => col.VarCharValue);
    const rows = resultSet.Rows.slice(1);

    return rows.map((row: any) => {
      const rowData: any = {};
      row.Data.forEach((col: any, index: number) => {
        rowData[headers[index]] = col.VarCharValue;
      });
      return rowData;
    });
  }

  private async getDailyCostsByAccount(): Promise<any[]> {
    const query = `
      SELECT 
        line_item_usage_account_id as account_id,
        line_item_usage_start_date as usage_date,
        SUM(line_item_unblended_cost) as daily_cost
      FROM ${this.config.costDatabase}.${this.config.costTable}
      WHERE line_item_usage_start_date >= current_date - interval '7' day
      GROUP BY line_item_usage_account_id, line_item_usage_start_date
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

      // Cost trends across accounts
      new cloudwatch.GraphWidget({
        title: 'Cross-Account Cost Trends',
        left: [
          new cloudwatch.Metric({
            namespace: 'AWS/Billing',
            metricName: 'EstimatedCharges',
            statistic: 'Maximum',
            dimensionsMap: { Currency: 'USD' },
            account: '222222222222'
          }),
          new cloudwatch.Metric({
            namespace: 'AWS/Billing',
            metricName: 'EstimatedCharges',
            statistic: 'Maximum',
            dimensionsMap: { Currency: 'USD' },
            account: '333333333333'
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

    // CloudTrail for cross-account API monitoring
    const monitoringCloudTrail = new cloudtrail.Trail(this, 'CrossAccountMonitoringTrail', {
      trailName: 'cross-account-monitoring-trail',
      includeGlobalServiceEvents: true,
      isLogging: true,
      enableFileValidation: true
    });

    // CloudWatch alarms for suspicious cross-account activity
    const suspiciousAssumeRoleAlarm = new cloudwatch.Alarm(this, 'SuspiciousAssumeRoleActivity', {
      alarmName: 'cross-account-suspicious-assume-role',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/CloudTrail',
        metricName: 'AssumeRoleFailures',
        statistic: 'Sum'
      }),
      threshold: 10,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      alarmDescription: 'Alarm for suspicious cross-account role assumption failures'
    });

    // Log metric filter for cross-account access patterns
    const crossAccountAccessFilter = new logs.MetricFilter(this, 'CrossAccountAccessFilter', {
      logGroup: monitoringCloudTrail.logGroup!,
      metricNamespace: 'SecurityMonitoring/CrossAccount',
      metricName: 'CrossAccountAccess',
      filterPattern: logs.FilterPattern.literal('{ ($.eventName = AssumeRole) && ($.errorCode NOT EXISTS) }'),
      metricValue: '1'
    });
  }
}
```

## Testing and Validation

Comprehensive testing ensures that cross-account monitoring and observability systems function correctly and provide accurate insights across all integrated accounts.

Create automated tests for monitoring functionality:

```typescript
// monitoring-integration.test.ts - Integration tests for cross-account monitoring
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import { CloudWatchClient, GetMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { XRayClient, GetServiceMapCommand } from '@aws-sdk/client-xray';
import { ConfigServiceClient, GetConfigRuleEvaluationStatusCommand } from '@aws-sdk/client-config-service';

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
    expect(response.MetricDataResults!.length).toBeGreaterThan(0);
  });

  it('should aggregate X-Ray service maps across accounts', async () => {
    const command = new GetServiceMapCommand({
      TimeRangeType: 'TraceId',
      StartTime: new Date(Date.now() - 3600000),
      EndTime: new Date()
    });

    const response = await xrayClient.send(command);
    expect(response.Services).toBeDefined();
  });

  it('should retrieve Config aggregator compliance data', async () => {
    const command = new GetConfigRuleEvaluationStatusCommand({
      ConfigRuleNames: ['root-access-key-check', 's3-bucket-ssl-requests-only']
    });

    const response = await configClient.send(command);
    expect(response.ConfigRulesEvaluationStatus).toBeDefined();
    expect(response.ConfigRulesEvaluationStatus!.length).toBeGreaterThan(0);
  });
});
```

Cross-account monitoring and observability provides the foundation for maintaining operational excellence across complex multi-account AWS architectures. The patterns we've explored - centralized dashboards, distributed tracing aggregation, unified logging, compliance monitoring, and cost consolidation - work together to create comprehensive visibility while preserving the security boundaries that make multi-account architectures valuable.

## Key Takeaways

**Start Simple**: Begin with basic cross-account CloudWatch dashboards and gradually add complexity. Most organizations see immediate value from centralizing metrics visualization alone.

**Security First**: Always implement proper IAM roles and external IDs for cross-account access. The convenience of monitoring should never compromise your security posture.

**Automate Everything**: Manual correlation of data across accounts doesn't scale. Build automation into your monitoring from day one, especially for compliance reporting and cost analysis.

**Plan for Growth**: Design your monitoring architecture to handle new accounts and services without requiring major refactoring. Use infrastructure as code and standardized role patterns.

## Next Steps

If you're just getting started with cross-account monitoring, I recommend this approach:

1. **Week 1**: Set up basic cross-account CloudWatch dashboards for your most critical applications
2. **Week 2**: Implement centralized logging for application logs across your primary accounts  
3. **Week 3**: Add X-Ray distributed tracing aggregation for end-to-end transaction visibility
4. **Month 2**: Extend to Config aggregators for compliance monitoring
5. **Month 3**: Add cost consolidation and automated reporting

The investment in comprehensive cross-account observability pays dividends in improved incident response times, better cost optimization, and enhanced compliance posture. Your 3 AM incident response scenarios will transform from frantic dashboard-hopping exercises into focused, data-driven investigations that resolve quickly and prevent recurrence.

Remember: monitoring fragmentation is a choice, not an inevitability of multi-account architectures. With the right patterns and tools, you can have both the security benefits of account separation and the operational visibility you need to run reliable systems at scale.
