---
title: "Simplified Cross-Account Backup and Disaster Recovery with AWS Backup"
date: 2025-08-20T10:00:00-07:00
draft: false
categories: ["Cloud Computing", "Architecture and Design"]
tags:
- AWS
- Backup
- Disaster Recovery
- Cross-Account
- AWS Backup
- TypeScript
- CDK
series: "AWS Cross-Account Patterns"
---
{{< image src="/posts/2025/08/20/simplified-aws-backup-cross-account.png" alt="Meme showing a person frantically searching through multiple AWS accounts for backups during an outage" width="600" caption="When your production database crashes at 2 AM and your backups are scattered across 6 different AWS accounts" >}}

The call comes at 2:17 AM. Your primary RDS cluster has suffered a catastrophic failure, taking down the entire e-commerce platform during peak holiday shopping. Customers can't place orders, revenue is hemorrhaging by the minute, and your CEO is already awake asking hard questions. You sprint to your laptop, heart racing, only to discover that your perfectly planned backup strategy has become a nightmare of account boundaries and access controls.

The RDS snapshots live in the production account, but the automated backups went to the backup account. The cross-region copies are in another account for compliance reasons. The restore procedures are documented... somewhere... but require switching between four different AWS consoles with different IAM roles. Twenty minutes later, you're still figuring out which backup contains yesterday's data while your application burns.

Welcome to what I call "backup fragmentation syndrome" - the hidden liability that emerges when enterprises distribute their AWS infrastructure across multiple accounts without considering disaster recovery implications. You get excellent security isolation, but at the cost of recovery complexity that can turn minor incidents into business-threatening disasters.

**The Problem**: Traditional backup strategies assume single-account environments. When data, backups, and recovery resources span multiple AWS accounts, complexity explodes exponentially. Simple operations like "restore from last night's backup" become multi-step orchestrations requiring cross-account permissions, manual coordination, and deep knowledge of distributed recovery procedures.

**The Solution**: AWS Backup's native cross-account capabilities replace most of the custom orchestration you would otherwise write — scheduling, cross-account copying, lifecycle transitions and compliance reporting are all service features rather than Lambda functions you maintain. What remains custom is the part AWS does not do for you, which turns out to be restore *testing*, and that is the part this post treats most carefully.

In this guide, you'll learn how to implement a production-ready cross-account backup and disaster recovery solution using AWS Backup's managed services. We'll cover everything from project setup to deployment validation, showing you exactly how to organize the code and deploy a system that recovers from failures in minutes instead of hours.

## Why AWS Backup Simplifies Everything

Traditional backup solutions require complex orchestration across multiple services, custom monitoring systems, and manual compliance validation. AWS Backup consolidates these capabilities into a single managed service that handles backup scheduling, cross-account copying, lifecycle management, and compliance reporting automatically.

**Key Simplifications:**

- **Single Service Management**: Replace multiple Lambda functions, Step Functions, and custom orchestration with AWS Backup's native capabilities
- **Built-in Cross-Account Support**: Native cross-account backup copying without complex IAM policy management
- **Automated Compliance**: Built-in compliance frameworks and reporting eliminate custom validation logic
- **Integrated Monitoring**: CloudWatch integration and AWS Backup console provide comprehensive visibility
- **Cost Optimization**: Lifecycle rules move recovery points to cold storage automatically, at roughly a quarter of warm storage cost for the resource types that support it

## Architecture Overview

The simplified architecture uses AWS Backup as the central orchestration service with minimal custom components:

{{< plantuml id="simplified-aws-backup-architecture" >}}
@startuml
!theme aws-orange
title Simplified Cross-Account Backup and Disaster Recovery with AWS Backup

cloud "Production Account (111122223333)" as ProdAccount {
  rectangle "Production Resources" as ProdRes {
    rectangle "RDS Databases" as RDS
    rectangle "EBS Volumes" as EBS
    rectangle "DynamoDB Tables" as DDB
    rectangle "EFS File Systems" as EFS
    rectangle "EC2 Instances" as EC2
  }
  
  rectangle "AWS Backup" as ProdBackup {
    rectangle "Backup Plan" as BackupPlan
    rectangle "Backup Selections\n(Tag-based)" as BackupSelection
    rectangle "Local Backup Vault" as LocalVault
  }
  
  rectangle "Resource Tagging" as Tags {
    note as TagNote
      Environment=Production
      BackupRequired=true
      DataClassification=Critical
    end note
  }
}

cloud "Backup Account (444455556666)" as BackupAccount {
  rectangle "Centralized Backup Management" as CentralMgmt {
    rectangle "Cross-Account\nBackup Vault" as CrossVault
    rectangle "Compliance\nFrameworks" as Compliance
    rectangle "Audit Reports" as AuditReports
  }
  
  rectangle "DR Testing" as DRTest {
    rectangle "Lambda Function\n(DR Testing)" as DRLambda
    rectangle "Automated\nRestore Tests" as RestoreTests
    rectangle "RTO/RPO\nValidation" as RTOValidation
  }
  
  rectangle "Monitoring & Alerting" as Monitoring {
    rectangle "CloudWatch\nDashboard" as Dashboard
    rectangle "SNS Notifications" as SNS
    rectangle "Cost Tracking" as CostTrack
  }
}

cloud "DR Account (777788889999)" as DRAccount {
  rectangle "Disaster Recovery" as DR {
    rectangle "Cross-Region\nBackup Copies" as CrossRegion
    rectangle "DR Infrastructure" as DRInfra
    rectangle "Recovery\nEnvironment" as RecoveryEnv
  }
}

cloud "AWS Services" as AWSServices {
  rectangle "EventBridge" as EventBridge
  rectangle "CloudWatch" as CloudWatch
  rectangle "IAM Cross-Account\nRoles" as IAM
  rectangle "KMS Encryption" as KMS
}

' Resource tagging drives backup selection
Tags --> BackupSelection : "Automatic\nDiscovery"
ProdRes --> Tags : "Tagged\nResources"

' Local backup process
BackupPlan --> BackupSelection : "Backup\nPolicy"
BackupSelection --> LocalVault : "Create\nBackups"
ProdRes --> LocalVault : "Automated\nSnapshots"

' Cross-account backup copying
LocalVault --> CrossVault : "Cross-Account\nBackup Copy"
CrossVault --> CrossRegion : "Cross-Region\nReplication"

' DR testing automation
CrossVault --> DRLambda : "Test Recovery\nPoints"
DRLambda --> RestoreTests : "Automated\nRestore Jobs"
RestoreTests --> RTOValidation : "Measure\nPerformance"

' Compliance and monitoring
CrossVault --> Compliance : "Compliance\nValidation"
Compliance --> AuditReports : "Generate\nReports"
BackupPlan --> Dashboard : "Backup\nMetrics"
RestoreTests --> Dashboard : "DR Test\nResults"
Dashboard --> SNS : "Alert\nNotifications"

' AWS service integrations
BackupPlan --> EventBridge : "Scheduled\nBackups"
EventBridge --> DRLambda : "Monthly\nDR Tests"
Dashboard --> CloudWatch : "Custom\nMetrics"
CrossVault --> KMS : "Encryption\nAt Rest"
LocalVault --> IAM : "Cross-Account\nAccess"

' Styling
ProdAccount -[#orange,thickness=3]-> BackupAccount : "Native AWS Backup\nCross-Account Integration"
BackupAccount -[#blue,thickness=2]-> DRAccount : "Automated\nDR Replication"

note right of CrossVault
  **Key Benefits:**
  • Single managed service
  • Native cross-account support
  • Built-in compliance frameworks
  • Automated lifecycle management
  • 80% less complexity
end note

note left of DRLambda
  **Automated Testing:**
  • Monthly DR validation
  • RTO/RPO measurement
  • Cost-efficient test restores
  • Automated cleanup
end note
@enduml
{{< /plantuml >}}

## Project Structure and Setup

First, create a new CDK project to organize the backup infrastructure:

```bash
# Create a new CDK project
mkdir aws-backup-cross-account
cd aws-backup-cross-account
npx cdk init app --language typescript
```

There are no extra packages to install. `cdk init` scaffolds a CDK v2 project, and in v2 every stable service module ships inside the single `aws-cdk-lib` dependency — `import * as backup from 'aws-cdk-lib/aws-backup'`. The `@aws-cdk/aws-backup` and `@aws-cdk/aws-sns-subscriptions` packages are CDK **v1** artifacts; v1 reached end of support in 2023, and installing them alongside `aws-cdk-lib` produces two incompatible copies of the construct library and a stream of confusing type errors.

Organize your project structure like this:

```text
aws-backup-cross-account/
├── bin/
│   └── app.ts                    # CDK app entry point
├── lib/
│   ├── backup-stack.ts           # Main backup infrastructure
│   ├── dr-testing-stack.ts       # Disaster recovery testing
│   └── monitoring-stack.ts       # Monitoring and alerting
├── lambda/
│   └── dr-testing/
│       ├── index.ts              # DR testing Lambda function
│       └── package.json
├── cdk.json
├── package.json
└── README.md
```

## Step 1: Main CDK App Entry Point

Create `bin/app.ts` to define your application and deploy the stacks:

```typescript
#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SimplifiedCrossAccountBackupStack } from '../lib/backup-stack';
import { DisasterRecoveryTestingStack } from '../lib/dr-testing-stack';
import { BackupMonitoringStack } from '../lib/monitoring-stack';

const app = new cdk.App();

// Configuration for your environment.
//
// These stacks deploy into the PRODUCTION account (the one holding the
// resources being backed up); the backup and DR account IDs identify the
// copy destinations. Keep them consistent with the architecture diagram
// above -- 111122223333 is production, so using it as `backupAccountId`
// would point the copy action back at the account you are copying from.
const config = {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,   // 111122223333 (production)
    region: process.env.CDK_DEFAULT_REGION || 'us-west-2'
  },
  backupAccountId: '444455556666',        // Replace with your backup account ID
  drAccountId: '777788889999',            // Replace with your DR account ID
  // The destination vault ARNs, which must already exist in those accounts.
  // Cross-account copy targets are referenced by ARN, not by name.
  backupVaultArn: 'arn:aws:backup:us-west-2:444455556666:backup-vault:central-backup-vault',
  drVaultArn: 'arn:aws:backup:us-east-1:777788889999:backup-vault:dr-backup-vault',
  complianceFrameworks: ['SOC2', 'HIPAA', 'PCI_DSS'],
  notificationEmail: 'admin@yourcompany.com', // Replace with your email
  // Retention must clear the cold-storage floor: a recovery point moved to
  // cold storage must stay there at least 90 days, so `deleteAfter` has to be
  // at least `moveToColdStorageAfter + 90`. See Step 2.
  retentionDays: {
    daily: 35,     // warm only, no cold transition
    weekly: 180,   // cold at 30 -> delete at 180 (150 days in cold)
    monthly: 365,  // cold at 90 -> delete at 365
    yearly: 2555   // cold at 365 -> delete at 2555 (7 years)
  },
  crossRegionCopy: {
    enabled: true,
    destinationRegion: 'us-east-1',
    retentionDays: 180
  }
};

// Deploy the backup infrastructure stack
const backupStack = new SimplifiedCrossAccountBackupStack(app, 'BackupStack', {
  ...config,
  stackName: 'cross-account-backup-infrastructure'
});

// Deploy disaster recovery testing. The restore role comes from the backup
// stack -- it must be a role AWS Backup can assume, not the Lambda's own.
const drTestingStack = new DisasterRecoveryTestingStack(app, 'DRTestingStack', {
  env: config.env,
  backupVault: backupStack.backupVault,
  restoreRole: backupStack.restoreRole,
  stackName: 'cross-account-dr-testing'
});

// Deploy monitoring and alerting
const monitoringStack = new BackupMonitoringStack(app, 'MonitoringStack', {
  env: config.env,
  backupVault: backupStack.backupVault,
  notificationEmail: config.notificationEmail,
  stackName: 'cross-account-backup-monitoring'
});

// Passing constructs between stacks already creates the CloudFormation
// export/import dependency, so these calls are redundant. Keep them only if
// you switch to passing plain strings (ARNs, names) instead of constructs,
// which is generally the better choice for cross-stack references anyway.
drTestingStack.addDependency(backupStack);
monitoringStack.addDependency(backupStack);
```

## Step 2: Core Backup Infrastructure Implementation

Create `lib/backup-stack.ts` with the core backup infrastructure:

```typescript
// lib/backup-stack.ts
import * as backup from 'aws-cdk-lib/aws-backup';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface SimplifiedBackupProps extends cdk.StackProps {
  backupAccountId: string;
  drAccountId: string;
  /** ARN of the destination vault in the backup account. */
  backupVaultArn: string;
  /** ARN of the destination vault in the DR account. */
  drVaultArn: string;
  complianceFrameworks: string[];
  notificationEmail: string;
  retentionDays: {
    daily: number;
    weekly: number;
    monthly: number;
    yearly: number;
  };
  crossRegionCopy: {
    enabled: boolean;
    destinationRegion: string;
    retentionDays: number;
  };
}

export class SimplifiedCrossAccountBackupStack extends cdk.Stack {
  public readonly backupVault: backup.BackupVault;
  public readonly backupPlan: backup.BackupPlan;
  public readonly crossAccountRole: iam.Role;
  public readonly restoreRole: iam.Role;

  constructor(scope: Construct, id: string, props: SimplifiedBackupProps) {
    super(scope, id, props);

    // Create KMS key for backup encryption
    const backupKey = new kms.Key(this, 'BackupEncryptionKey', {
      description: 'Cross-account backup encryption key',
      enableKeyRotation: true,
      policy: this.createBackupKeyPolicy(props.backupAccountId, props.drAccountId)
    });

    // Create backup vault with cross-account access
    this.backupVault = new backup.BackupVault(this, 'CrossAccountBackupVault', {
      backupVaultName: 'cross-account-backup-vault',
      encryptionKey: backupKey,
      accessPolicy: this.createVaultAccessPolicy(props.backupAccountId, props.drAccountId)
    });

    // The AWS Backup service role. Only AWS Backup should be able to assume
    // it.
    //
    // Adding `AccountPrincipal(backupAccountId)` and
    // `AccountPrincipal(drAccountId)` -- as is often done to "enable
    // cross-account backup" -- makes a role carrying
    // AWSBackupServiceRolePolicyForRestores assumable by *any* principal in
    // two entire accounts, with no external ID and no conditions. That policy
    // can create and overwrite RDS instances, EBS volumes and DynamoDB tables.
    // It is a serious over-grant, and it is not needed: cross-account copying
    // is authorised by the destination vault's resource policy, not by the
    // source role's trust policy.
    //
    // Restores are also a separate concern from backups. Split them so a
    // scheduled backup cannot restore over live data.
    this.crossAccountRole = new iam.Role(this, 'CrossAccountBackupRole', {
      assumedBy: new iam.ServicePrincipal('backup.amazonaws.com'),
      description: 'Service role AWS Backup assumes to create and copy backups',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSBackupServiceRolePolicyForBackup'
        )
      ]
    });

    // A separate, narrowly used role for restores, including DR test restores.
    this.restoreRole = new iam.Role(this, 'BackupRestoreRole', {
      assumedBy: new iam.ServicePrincipal('backup.amazonaws.com'),
      description: 'Service role AWS Backup assumes to perform restores',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSBackupServiceRolePolicyForRestores'
        )
      ]
    });

    // Create comprehensive backup plan
    this.backupPlan = this.createBackupPlan(props);

    // Two lifecycle rules will fail deployment if you get them wrong, so they
    // are worth stating plainly:
    //
    //  1. A recovery point moved to cold storage must remain there for at
    //     least 90 days. AWS Backup enforces this as
    //     `deleteAfter >= moveToColdStorageAfter + 90`, and a plan violating
    //     it is rejected at create time -- so `moveToColdStorageAfter: 30`
    //     with `deleteAfter: 30` (or even 90) never deploys.
    //  2. Cold storage is not supported for every resource type. EFS supports
    //     it, and DynamoDB and S3 support it with advanced features enabled;
    //     EBS, EC2 and RDS do not. Attaching a cold transition to a rule whose
    //     selection is mostly RDS and EBS buys nothing.

    // Create backup selections (resources to backup)
    this.createBackupSelections(props);

    // Set up notifications
    this.setupNotifications(props);

    // Create compliance reporting
    this.setupComplianceReporting(props);

    // Cross-account and cross-region copying is expressed entirely by the
    // `copyActions` on the plan rules above -- there is no separate wiring
    // step, which is exactly why AWS Backup is worth using here.

    // Output important values
    new cdk.CfnOutput(this, 'BackupVaultName', {
      value: this.backupVault.backupVaultName,
      description: 'Name of the backup vault'
    });

    new cdk.CfnOutput(this, 'BackupPlanId', {
      value: this.backupPlan.backupPlanId,
      description: 'ID of the backup plan'
    });
  }

  private createBackupKeyPolicy(backupAccountId: string, drAccountId: string): iam.PolicyDocument {
    return new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: 'Enable IAM User Permissions',
          effect: iam.Effect.ALLOW,
          principals: [new iam.AccountRootPrincipal()],
          actions: ['kms:*'],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          sid: 'Allow AWS Backup',
          effect: iam.Effect.ALLOW,
          principals: [new iam.ServicePrincipal('backup.amazonaws.com')],
          actions: [
            'kms:Decrypt',
            'kms:GenerateDataKey',
            'kms:ReEncrypt*',
            'kms:CreateGrant',
            'kms:DescribeKey'
          ],
          resources: ['*']
        }),
        new iam.PolicyStatement({
          sid: 'Allow cross-account access',
          effect: iam.Effect.ALLOW,
          principals: [
            new iam.AccountPrincipal(backupAccountId),
            new iam.AccountPrincipal(drAccountId)
          ],
          actions: [
            'kms:Decrypt',
            'kms:GenerateDataKey',
            'kms:CreateGrant',
            'kms:DescribeKey'
          ],
          resources: ['*']
        })
      ]
    });
  }

  // Which account grants what, for cross-account copy:
  //
  //   source vault (production)  --copy-->  destination vault (backup account)
  //
  // `backup:CopyIntoBackupVault` is required on the **destination** vault,
  // granted to the **source** account. Putting it on the production vault and
  // granting it to the backup account -- the arrangement you will often see --
  // permits a copy in the opposite direction to the one you want, and the
  // copies you actually configured still fail with AccessDenied.
  //
  // So this policy, on the production vault, is for read access: it lets the
  // backup and DR accounts inspect and restore from recovery points here.
  // The `CopyIntoBackupVault` grant belongs in the stack that creates the
  // destination vaults, shown immediately below.
  private createVaultAccessPolicy(backupAccountId: string, drAccountId: string): iam.PolicyDocument {
    return new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: 'AllowCentralAccountsToReadRecoveryPoints',
          effect: iam.Effect.ALLOW,
          principals: [
            new iam.AccountPrincipal(backupAccountId),
            new iam.AccountPrincipal(drAccountId)
          ],
          actions: [
            'backup:DescribeBackupVault',
            'backup:DescribeRecoveryPoint',
            'backup:ListRecoveryPointsByBackupVault',
            'backup:GetRecoveryPointRestoreMetadata',
            'backup:StartRestoreJob'
          ],
          // A vault access policy is evaluated against this vault, so `*`
          // means "this vault". `backup:ListBackupVaults` is omitted because
          // it is an account-level action -- it has no effect in a vault
          // policy.
          resources: ['*']
        })
      ]
    });
  }

  private createBackupPlan(props: SimplifiedBackupProps): backup.BackupPlan {
    // Cross-account copy destinations are referenced by ARN. Do NOT use
    // `BackupVault.fromBackupVaultName` for these: it builds an ARN using the
    // *current* stack's account and region, so a vault named
    // "...-us-east-1" resolves to a same-account, same-region ARN that does
    // not exist, and the copy silently targets the wrong place.
    const centralBackupVault = backup.BackupVault.fromBackupVaultArn(
      this, 'CentralBackupVault', props.backupVaultArn
    );
    const drBackupVault = backup.BackupVault.fromBackupVaultArn(
      this, 'DrBackupVault', props.drVaultArn
    );

    return new backup.BackupPlan(this, 'ComprehensiveBackupPlan', {
      backupPlanName: 'cross-account-enterprise-backup',
      backupPlanRules: [
        // Daily backups. Deliberately warm-only: with a 35-day retention there
        // is no legal cold transition (see the note below), and daily points
        // are the ones you actually restore from, where cold storage retrieval
        // latency hurts most.
        //
        // This rule carries the cross-account copy -- the whole point of the
        // architecture. Note that AWS Backup schedules are always UTC.
        new backup.BackupPlanRule({
          ruleName: 'DailyBackupRule',
          backupVault: this.backupVault,
          scheduleExpression: events.Schedule.cron({
            hour: '2',
            minute: '0'
          }),
          deleteAfter: cdk.Duration.days(props.retentionDays.daily),
          copyActions: [
            // Cross-account copy into the backup account.
            {
              destinationBackupVault: centralBackupVault,
              deleteAfter: cdk.Duration.days(props.retentionDays.daily)
            },
            // Cross-account AND cross-region copy into the DR account.
            ...(props.crossRegionCopy.enabled ? [{
              destinationBackupVault: drBackupVault,
              deleteAfter: cdk.Duration.days(props.crossRegionCopy.retentionDays),
              moveToColdStorageAfter: cdk.Duration.days(30)
            }] : [])
          ]
        }),

        // Weekly backups with extended retention
        new backup.BackupPlanRule({
          ruleName: 'WeeklyBackupRule',
          backupVault: this.backupVault,
          scheduleExpression: events.Schedule.cron({
            weekDay: 'SUN',
            hour: '3',
            minute: '0'
          }),
          deleteAfter: cdk.Duration.days(props.retentionDays.weekly),
          moveToColdStorageAfter: cdk.Duration.days(30),
          copyActions: [{
            destinationBackupVault: centralBackupVault,
            deleteAfter: cdk.Duration.days(props.retentionDays.weekly),
            moveToColdStorageAfter: cdk.Duration.days(30)
          }]
        }),

        // Monthly backups for long-term retention
        new backup.BackupPlanRule({
          ruleName: 'MonthlyBackupRule',
          backupVault: this.backupVault,
          scheduleExpression: events.Schedule.cron({
            day: '1',
            hour: '4',
            minute: '0'
          }),
          deleteAfter: cdk.Duration.days(props.retentionDays.monthly),
          moveToColdStorageAfter: cdk.Duration.days(90),
          copyActions: [{
            destinationBackupVault: centralBackupVault,
            deleteAfter: cdk.Duration.days(props.retentionDays.monthly),
            moveToColdStorageAfter: cdk.Duration.days(90)
          }]
        }),

        // Yearly backups for compliance
        new backup.BackupPlanRule({
          ruleName: 'YearlyBackupRule',
          backupVault: this.backupVault,
          scheduleExpression: events.Schedule.cron({
            month: 'JAN',
            day: '1',
            hour: '5',
            minute: '0'
          }),
          deleteAfter: cdk.Duration.days(props.retentionDays.yearly),
          moveToColdStorageAfter: cdk.Duration.days(365),
          copyActions: [{
            destinationBackupVault: centralBackupVault,
            deleteAfter: cdk.Duration.days(props.retentionDays.yearly),
            moveToColdStorageAfter: cdk.Duration.days(365)
          }]
        })
      ]
    });
  }

  private createBackupSelections(props: SimplifiedBackupProps): void {
    // Production resources backup selection.
    //
    // The two selection mechanisms behave differently and must not be mixed:
    //
    //  * Multiple `fromTag(...)` entries become AWS Backup's legacy
    //    `ListOfTags`, which is evaluated as **OR**. Passing three tags there
    //    does not mean "all three" -- anything carrying `BackupRequired=true`
    //    alone is selected, which is usually a much wider net than intended.
    //  * `conditions` is evaluated as **AND**, and supports negation.
    //
    // Use `conditions` alone when you mean AND. Here we want: everything in
    // production that is marked for backup, minus anything explicitly opted
    // out.
    new backup.BackupSelection(this, 'ProductionResourcesSelection', {
      backupPlan: this.backupPlan,
      selectionName: 'production-resources',
      role: this.crossAccountRole,
      // `fromArn('arn:aws:*')` would be the "all supported types" wildcard;
      // the conditions below do the real filtering.
      resources: [backup.BackupResource.fromArn('*')],
      conditions: {
        stringEquals: {
          'aws:ResourceTag/Environment': ['Production'],
          'aws:ResourceTag/BackupRequired': ['true']
        },
        stringNotEquals: {
          'aws:ResourceTag/BackupExcluded': ['true']
        }
      }
    });

    // Database-specific backup selection
    new backup.BackupSelection(this, 'DatabaseSelection', {
      backupPlan: this.backupPlan,
      selectionName: 'database-resources',
      role: this.crossAccountRole,
      resources: [
        backup.BackupResource.fromArn('arn:aws:rds:*:*:db:*'),
        backup.BackupResource.fromArn('arn:aws:rds:*:*:cluster:*'),
        backup.BackupResource.fromArn('arn:aws:dynamodb:*:*:table/*')
      ],
      conditions: {
        stringEquals: {
          'aws:ResourceTag/DatabaseBackup': ['enabled']
        }
      }
    });

    // File system backup selection
    new backup.BackupSelection(this, 'FileSystemSelection', {
      backupPlan: this.backupPlan,
      selectionName: 'filesystem-resources',
      role: this.crossAccountRole,
      resources: [
        backup.BackupResource.fromArn('arn:aws:ec2:*:*:volume/*'),
        backup.BackupResource.fromArn('arn:aws:efs:*:*:file-system/*')
      ],
      conditions: {
        stringEquals: {
          'aws:ResourceTag/FilesystemBackup': ['enabled']
        }
      }
    });
  }

  private setupNotifications(props: SimplifiedBackupProps): void {
    // Create SNS topic for backup notifications
    const backupTopic = new sns.Topic(this, 'BackupNotificationTopic', {
      displayName: 'Cross-Account Backup Notifications'
    });

    backupTopic.addSubscription(
      new cdk.aws_sns_subscriptions.EmailSubscription(props.notificationEmail)
    );

    // EventBridge rules for backup events.
    //
    // Only failures go to email. Subscribing `COMPLETED` sends one message per
    // successful backup per resource per rule -- for a tag-based selection
    // across a production account that is hundreds of emails a day, and the
    // reliable outcome is a filter rule that hides the failures too. Success
    // belongs on a dashboard; email is for things that need a human.
    const backupFailedRule = new events.Rule(this, 'BackupFailedRule', {
      eventPattern: {
        source: ['aws.backup'],
        detailType: ['Backup Job State Change'],
        detail: {
          state: ['FAILED', 'ABORTED', 'EXPIRED']
        }
      }
    });

    backupFailedRule.addTarget(new events_targets.SnsTopic(backupTopic));

    // Copy job failures are the ones to watch most closely: a backup can
    // succeed locally while the cross-account copy fails, which leaves you
    // believing you have off-site protection that does not exist.
    const copyJobRule = new events.Rule(this, 'CopyJobRule', {
      eventPattern: {
        source: ['aws.backup'],
        detailType: ['Copy Job State Change'],
        detail: {
          state: ['FAILED']
        }
      }
    });

    copyJobRule.addTarget(new events_targets.SnsTopic(backupTopic));

    // Restores are rare and always worth knowing about, success or failure.
    const restoreJobRule = new events.Rule(this, 'RestoreJobRule', {
      eventPattern: {
        source: ['aws.backup'],
        detailType: ['Restore Job State Change'],
        detail: {
          state: ['COMPLETED', 'FAILED']
        }
      }
    });

    restoreJobRule.addTarget(new events_targets.SnsTopic(backupTopic));
  }

  private setupComplianceReporting(props: SimplifiedBackupProps): void {
    // Framework and report plan names must match `[a-zA-Z][_a-zA-Z0-9]*` --
    // hyphens are rejected. `cross-account-soc2-compliance` fails validation
    // at deploy time, which is an annoying thing to discover after a
    // twelve-minute stack rollback. Use underscores.
    props.complianceFrameworks.forEach(framework => {
      new backup.CfnFramework(this, `${framework}Framework`, {
        frameworkName: `CrossAccount_${framework}_Compliance`,
        frameworkDescription: `Cross-account backup compliance for ${framework}`,
        frameworkControls: this.getFrameworkControls(framework)
      });
    });

    // The report plan needs a bucket that actually exists, and AWS Backup
    // needs permission to write to it. Create it here rather than referencing
    // a name and hoping.
    const reportsBucket = new s3.Bucket(this, 'ComplianceReportsBucket', {
      bucketName: `backup-compliance-reports-${cdk.Aws.ACCOUNT_ID}`,
      enforceSSL: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      lifecycleRules: [{
        id: 'compliance-report-retention',
        enabled: true,
        expiration: cdk.Duration.days(2555)
      }]
    });

    reportsBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowBackupAuditManagerToWriteReports',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('backup.amazonaws.com')],
      actions: ['s3:PutObject'],
      resources: [reportsBucket.arnForObjects('compliance-reports/*')],
      conditions: {
        StringEquals: { 's3:x-amz-acl': 'bucket-owner-full-control' }
      }
    }));

    new backup.CfnReportPlan(this, 'ComplianceAuditReport', {
      reportPlanName: 'CrossAccount_Compliance_Report',
      reportPlanDescription: 'Cross-account backup compliance audit report',
      reportDeliveryChannel: {
        s3BucketName: reportsBucket.bucketName,
        s3KeyPrefix: 'compliance-reports/',
        formats: ['CSV', 'JSON']
      },
      reportSetting: {
        reportTemplate: 'BACKUP_COMPLIANCE_REPORT'
      }
    });
  }

  // A word on naming these after SOC 2, HIPAA and PCI DSS: AWS Backup Audit
  // Manager provides *controls*, not certified compliance packs. Naming a
  // framework "HIPAA" does not make anything HIPAA-compliant -- it groups a
  // set of backup checks you have decided are relevant to that audit. Treat
  // these as evidence for an auditor, not as a compliance attestation, and
  // map the controls to your actual control matrix rather than assuming the
  // label does that work.
  private getFrameworkControls(framework: string): any[] {
    const baseControls = [
      {
        controlName: 'BACKUP_RECOVERY_POINT_MINIMUM_FREQUENCY_AND_POINT_IN_TIME_RECOVERY',
        controlInputParameters: [
          {
            parameterName: 'requiredFrequencyUnit',
            parameterValue: 'hours'
          },
          {
            parameterName: 'requiredFrequencyValue',
            parameterValue: '24'
          }
        ]
      },
      {
        controlName: 'BACKUP_RECOVERY_POINT_ENCRYPTED',
        controlInputParameters: []
      },
      {
        controlName: 'BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN',
        controlInputParameters: []
      }
    ];

    // Framework-specific controls.
    //
    // A control may appear only once per framework -- CreateFramework rejects
    // duplicates. `BACKUP_RECOVERY_POINT_ENCRYPTED` is already in
    // `baseControls`, so listing it again under PCI_DSS (an easy mistake when
    // mapping standards to controls) fails validation. PCI_DSS therefore adds
    // a retention control instead.
    const frameworkSpecificControls: { [key: string]: any[] } = {
      'HIPAA': [
        {
          controlName: 'BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED',
          controlInputParameters: []
        }
      ],
      'PCI_DSS': [
        {
          controlName: 'BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK',
          controlInputParameters: [
            { parameterName: 'requiredRetentionDays', parameterValue: '365' }
          ]
        }
      ],
      'SOC2': [
        {
          controlName: 'BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK',
          controlInputParameters: [
            {
              parameterName: 'requiredFrequencyUnit',
              parameterValue: 'days'
            },
            {
              parameterName: 'requiredRetentionDays',
              parameterValue: '35'
            }
          ]
        }
      ]
    };

    return [...baseControls, ...(frameworkSpecificControls[framework] || [])];
  }

}
```

### The destination side

The copy actions above will not work until the receiving vaults grant this account permission to write into them. Deploy this stack in the **backup account** (and an equivalent one in the DR account):

```typescript
// Deployed in the BACKUP account (444455556666)
export class CentralBackupVaultStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: cdk.StackProps & {
    sourceAccountIds: string[];
  }) {
    super(scope, id, props);

    // The destination vault needs its own KMS key, in this account. A copy
    // is re-encrypted at the destination -- it cannot use the source
    // account's key.
    const vaultKey = new kms.Key(this, 'CentralBackupKey', {
      description: 'Encryption key for centralised cross-account backups',
      enableKeyRotation: true
    });

    new backup.BackupVault(this, 'CentralBackupVault', {
      backupVaultName: 'central-backup-vault',
      encryptionKey: vaultKey,
      // Vault Lock is the reason to have a separate backup account at all: in
      // compliance mode nobody -- including this account's administrators and
      // AWS itself -- can shorten retention or delete a recovery point before
      // it expires. That is what makes these copies ransomware-resistant
      // rather than merely off-site. It is irreversible once the cooling-off
      // window closes, so set `changeableForDays` and graduate deliberately.
      lockConfiguration: {
        minRetention: cdk.Duration.days(30),
        maxRetention: cdk.Duration.days(2555),
        changeableFor: cdk.Duration.days(3)
      },
      accessPolicy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'AllowSourceAccountsToCopyIn',
            effect: iam.Effect.ALLOW,
            principals: props.sourceAccountIds.map(
              accountId => new iam.AccountPrincipal(accountId)
            ),
            actions: ['backup:CopyIntoBackupVault'],
            resources: ['*']
          })
        ]
      })
    });

  }
}
```

## Step 3: Disaster Recovery Testing Stack

Create `lib/dr-testing-stack.ts` for automated DR testing:

```typescript
// lib/dr-testing-stack.ts
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as events from 'aws-cdk-lib/aws-events';
import * as events_targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface DRTestingProps extends cdk.StackProps {
  backupVault: backup.BackupVault;
  /**
   * The role AWS Backup assumes to perform the restore. This is NOT the
   * Lambda's execution role -- see the note below.
   */
  restoreRole: iam.IRole;
}

export class DisasterRecoveryTestingStack extends cdk.Stack {
  public readonly drTestFunction: lambda.Function;

  constructor(scope: Construct, id: string, props: DRTestingProps) {
    super(scope, id, props);

    // IAM role for DR testing
    const drTestRole = new iam.Role(this, 'DRTestRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    // Grant necessary permissions for DR testing
    drTestRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'backup:ListRecoveryPointsByBackupVault',
        'backup:DescribeRecoveryPoint',
        'backup:GetRecoveryPointRestoreMetadata',
        'backup:StartRestoreJob',
        'backup:DescribeRestoreJob',
        'backup:ListRestoreJobs',
        'cloudwatch:PutMetricData'
      ],
      resources: ['*']
    }));

    // `StartRestoreJob` takes an `IamRoleArn` that **AWS Backup** assumes to
    // create the restored resource. Two things follow, and getting either
    // wrong produces an AccessDenied that looks like a permissions problem
    // with the Lambda:
    //
    //  1. That role must trust `backup.amazonaws.com`. Passing the Lambda's
    //     own execution role -- which only trusts `lambda.amazonaws.com` --
    //     fails, so `TEST_RESTORE_ROLE_ARN: drTestRole.roleArn` cannot work.
    //  2. The caller needs `iam:PassRole` for it.
    props.restoreRole.grantPassRole(drTestRole);

    // Cleanup needs to delete what the restore created. Scope it to resources
    // tagged as DR test artefacts so this can never touch production.
    drTestRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DeleteVolume',
        'rds:DeleteDBInstance',
        'dynamodb:DeleteTable',
        'ec2:DescribeVolumes',
        'rds:DescribeDBInstances'
      ],
      resources: ['*'],
      conditions: {
        StringEquals: { 'aws:ResourceTag/DrTestArtifact': 'true' }
      }
    }));

    // Create the DR testing Lambda function
    this.drTestFunction = new lambda.Function(this, 'DRTestFunction', {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      // Prefer NodejsFunction for a TypeScript handler -- it runs esbuild for
      // you. `fromAsset` uploads the directory as-is, so `index.ts` is
      // shipped uncompiled and the runtime cannot load it.
      code: lambda.Code.fromAsset('lambda/dr-testing'),
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      role: drTestRole,
      environment: {
        BACKUP_VAULT_NAME: props.backupVault.backupVaultName,
        TEST_RESTORE_ROLE_ARN: props.restoreRole.roleArn
      }
    });

    // Schedule monthly DR tests
    const drTestRule = new events.Rule(this, 'DRTestSchedule', {
      schedule: events.Schedule.cron({
        day: '15',
        hour: '10',
        minute: '0'
      }),
      description: 'Monthly disaster recovery testing'
    });

    drTestRule.addTarget(new events_targets.LambdaFunction(this.drTestFunction, {
      event: events.RuleTargetInput.fromObject({
        testType: 'sample',
        maxTestRestores: 3,
        resourceTypes: ['EBS', 'RDS', 'DynamoDB']
      })
    }));

    // Create a manual invoke option
    new cdk.CfnOutput(this, 'DRTestFunctionName', {
      value: this.drTestFunction.functionName,
      description: 'Name of the DR testing Lambda function'
    });
  }
}
```

## Step 4: DR Testing Lambda Function

Create `lambda/dr-testing/package.json`:

```json
{
  "name": "dr-testing-lambda",
  "version": "1.0.0",
  "description": "Disaster Recovery Testing Lambda Function",
  "main": "index.js",
  "dependencies": {
    "@aws-sdk/client-backup": "^3.0.0",
    "@aws-sdk/client-cloudwatch": "^3.0.0"
  },
  "scripts": {
    "build": "tsc",
    "test": "jest"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "typescript": "^5.6.0"
  }
}
```

### Why this is a Step Functions job, not a Lambda

The obvious implementation — loop over recovery points, start a restore, wait for it, check the result — cannot work, and it is worth being explicit about why before showing code:

- **Lambda's hard ceiling is 15 minutes.** Restores take far longer: an RDS instance is typically 20–40 minutes, and a large EBS volume can be hours. A `waitForRestoreCompletion` helper that polls for "30 minutes maximum" is killed by the runtime at 15, mid-poll. The function times out, the metric never gets published, and the restore keeps running unattended.
- **Nothing cleans up.** This is the expensive one. Each test restore creates a *real* RDS instance, EBS volume or DynamoDB table. If cleanup is a `console.log` placeholder — as it very often is — every monthly DR test leaks live billable resources indefinitely. A quarterly test of three resources leaves a dozen orphaned instances by year end, which is a genuinely surprising line item to trace back to your backup testing.

So: use Step Functions. Start the restore in one short Lambda, let the state machine's `Wait` state poll for completion at no compute cost, and run cleanup in a state that executes even when validation fails.

```typescript
// lib/dr-testing-stack.ts (state machine)
const startRestore = new tasks.LambdaInvoke(this, 'StartRestore', {
  lambdaFunction: startRestoreFn,
  outputPath: '$.Payload'
});

const checkRestore = new tasks.LambdaInvoke(this, 'CheckRestore', {
  lambdaFunction: checkRestoreFn,
  outputPath: '$.Payload'
});

// Cleanup runs on both the success and failure paths. Registering it only on
// the happy path is how orphaned test resources happen.
const cleanup = new tasks.LambdaInvoke(this, 'CleanupTestResources', {
  lambdaFunction: cleanupFn,
  outputPath: '$.Payload'
});

const definition = startRestore
  .next(new sfn.Wait(this, 'WaitForRestore', {
    time: sfn.WaitTime.duration(cdk.Duration.minutes(2))
  }))
  .next(checkRestore)
  .next(new sfn.Choice(this, 'RestoreComplete?')
    .when(sfn.Condition.stringEquals('$.status', 'RUNNING'),
      new sfn.Wait(this, 'WaitAgain', {
        time: sfn.WaitTime.duration(cdk.Duration.minutes(2))
      }).next(checkRestore))
    .otherwise(cleanup));

new sfn.StateMachine(this, 'DrTestStateMachine', {
  definitionBody: sfn.DefinitionBody.fromChainable(definition),
  // Generous: a large RDS restore genuinely takes this long.
  timeout: cdk.Duration.hours(6)
});
```

Now the handlers. `lambda/dr-testing/index.ts`:

```typescript
// lambda/dr-testing/index.ts
import {
  BackupClient,
  ListRecoveryPointsByBackupVaultCommand,
  GetRecoveryPointRestoreMetadataCommand,
  StartRestoreJobCommand,
  DescribeRestoreJobCommand
} from '@aws-sdk/client-backup';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { DynamoDBClient, DeleteTableCommand } from '@aws-sdk/client-dynamodb';
import { RDSClient, DeleteDBInstanceCommand } from '@aws-sdk/client-rds';
import { EC2Client, DeleteVolumeCommand } from '@aws-sdk/client-ec2';

const backup = new BackupClient({});
const cloudwatch = new CloudWatchClient({});
const dynamodb = new DynamoDBClient({});
const rds = new RDSClient({});
const ec2 = new EC2Client({});

interface DRTestEvent {
  testType: 'full' | 'sample' | 'validation';
  resourceTypes: string[];
  maxTestRestores: number;
}

interface TestResults {
  totalTests: number;
  successfulTests: number;
  failedTests: number;
  testDuration: number;
  averageRTO: number;
  successRate: number;
}

export const handler = async (event: DRTestEvent): Promise<any> => {
  console.log('Starting DR test with event:', JSON.stringify(event, null, 2));
  
  const startTime = Date.now();
  const restoreDurations: number[] = [];
  const testResults: TestResults = {
    totalTests: 0,
    successfulTests: 0,
    failedTests: 0,
    testDuration: 0,
    averageRTO: 0,
    successRate: 0
  };

  try {
    // Get recent recovery points from the backup vault
    const recoveryPoints = await backup.send(new ListRecoveryPointsByBackupVaultCommand({
      BackupVaultName: process.env.BACKUP_VAULT_NAME!,
      ByCreatedAfter: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // Last 7 days
      MaxResults: event.maxTestRestores || 5
    }));

    console.log(`Found ${recoveryPoints.RecoveryPoints?.length || 0} recovery points to test`);

    // Test restore for each recovery point
    for (const recoveryPoint of recoveryPoints.RecoveryPoints || []) {
      if (testResults.totalTests >= (event.maxTestRestores || 5)) break;
      
      testResults.totalTests++;
      console.log(`Testing recovery point: ${recoveryPoint.RecoveryPointArn}`);
      
      try {
        const restoreStartTime = Date.now();
        
        // Start a test restore
        const restoreJobId = await startTestRestore(recoveryPoint);
        console.log(`Started restore job: ${restoreJobId}`);
        
        // Wait for restore completion (simplified for demo)
        const restoreResult = await waitForRestoreCompletion(restoreJobId);
        
        const restoreEndTime = Date.now();
        const restoreDuration = restoreEndTime - restoreStartTime;
        
        if (restoreResult.status === 'COMPLETED') {
          testResults.successfulTests++;
          restoreDurations.push(restoreDuration);
          console.log(`Restore test successful in ${restoreDuration}ms`);
        } else {
          testResults.failedTests++;
          console.error(`Restore test failed with status: ${restoreResult.status}`);
        }

        // Always clean up, whatever the outcome. A restore that reached
        // FAILED may still have created a partial resource, and a TIMEOUT
        // almost certainly created a resource that is still provisioning.
        await cleanupTestRestore(restoreJobId);
      } catch (error) {
        console.error(`Restore test failed for recovery point ${recoveryPoint.RecoveryPointArn}:`, error);
        testResults.failedTests++;
      }
    }

    // Calculate final metrics.
    //
    // RTO is per-restore elapsed time, so average the individual
    // `restoreDuration` values -- dividing total handler wall-clock by the
    // number of tests conflates sequential restores with each other and
    // includes list/setup overhead, understating each restore's real duration.
    testResults.testDuration = Date.now() - startTime;
    testResults.averageRTO = restoreDurations.length > 0
      ? restoreDurations.reduce((sum, d) => sum + d, 0) / restoreDurations.length
      : 0;
    testResults.successRate = testResults.totalTests > 0
      ? (testResults.successfulTests / testResults.totalTests) * 100
      : 0;

    // Publish metrics to CloudWatch
    await publishTestMetrics(testResults);

    // Generate recommendations based on results
    const recommendations = generateRecommendations(testResults);

    console.log('DR test completed:', testResults);

    return {
      statusCode: 200,
      body: JSON.stringify({
        testResults,
        recommendations,
        timestamp: new Date().toISOString()
      })
    };

  } catch (error) {
    console.error('DR test execution failed:', error);
    
    // Publish failure metrics
    await cloudwatch.send(new PutMetricDataCommand({
      Namespace: 'DR/Testing',
      MetricData: [
        {
          MetricName: 'TestExecutionFailure',
          Value: 1,
          Unit: 'Count',
          Timestamp: new Date()
        }
      ]
    }));
    
    throw error;
  }
};

async function startTestRestore(recoveryPoint: any): Promise<string> {
  const restoreMetadata = await getRestoreMetadata(recoveryPoint);

  const result = await backup.send(new StartRestoreJobCommand({
    RecoveryPointArn: recoveryPoint.RecoveryPointArn,
    Metadata: restoreMetadata,
    // Must be a role AWS Backup can assume -- not the Lambda's own role.
    IamRoleArn: process.env.TEST_RESTORE_ROLE_ARN!,
    // `substr` is deprecated; and note this token is only idempotent within
    // the same millisecond, which is fine here but would not be if the state
    // machine retried this task.
    IdempotencyToken: `dr-test-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`
  }));

  return result.RestoreJobId!;
}

// Do not hand-write restore metadata. The valid keys are service-specific and
// differ from the corresponding API's parameter names -- EBS wants
// `volumeType`/`availabilityZone`/`encrypted`, DynamoDB wants
// `targetTableName`, and none of them are `newInstanceType` or `DBInstanceClass`.
// Guessing produces InvalidParameterValueException at restore time, hours after
// the pipeline reported success in starting the job.
//
// Ask AWS Backup for the correct metadata for this specific recovery point,
// then override only what you need to.
async function getRestoreMetadata(recoveryPoint: any): Promise<Record<string, string>> {
  const { RestoreMetadata } = await backup.send(
    new GetRecoveryPointRestoreMetadataCommand({
      BackupVaultName: process.env.BACKUP_VAULT_NAME!,
      RecoveryPointArn: recoveryPoint.RecoveryPointArn
    })
  );

  const metadata: Record<string, string> = { ...RestoreMetadata };

  // Restore under a new identity so a test can never overwrite the live
  // resource, and tag it so the cleanup step can find it -- and so the
  // cleanup IAM policy's tag condition permits deleting it.
  const suffix = `drtest-${Date.now()}`;

  if (recoveryPoint.ResourceType === 'DynamoDB') {
    metadata.targetTableName = `${suffix}`;
  }
  if (recoveryPoint.ResourceType === 'RDS') {
    metadata.DBInstanceIdentifier = suffix;
    metadata.DBInstanceClass = 'db.t3.micro';   // cheapest viable test size
    metadata.MultiAZ = 'false';
  }

  return metadata;
}

// Retained here for the single-resource case, but note the ceiling: this
// polls for up to 30 minutes inside a function whose own timeout is far
// shorter, so for anything slower than a small EBS volume the Lambda is
// killed mid-wait. That is what the Step Functions definition above replaces.
async function waitForRestoreCompletion(restoreJobId: string): Promise<{ status: string }> {
  let attempts = 0;
  const maxAttempts = 30; // 30 minutes -- exceeds any Lambda timeout
  
  while (attempts < maxAttempts) {
    try {
      const result = await backup.send(new DescribeRestoreJobCommand({
        RestoreJobId: restoreJobId
      }));

      const status = result.Status;
      console.log(`Restore job ${restoreJobId} status: ${status}`);

      if (status === 'COMPLETED' || status === 'FAILED' || status === 'ABORTED') {
        return { status: status };
      }

      // Wait 1 minute before checking again
      await new Promise(resolve => setTimeout(resolve, 60000));
      attempts++;
      
    } catch (error) {
      console.error(`Error checking restore status: ${error}`);
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 60000));
    }
  }
  
  return { status: 'TIMEOUT' };
}

// This function is the difference between a DR test and a recurring bill.
// A restore creates a real, running resource; if nothing deletes it, every
// test leaks one forever.
async function cleanupTestRestore(restoreJobId: string): Promise<void> {
  console.log(`Cleaning up test restore ${restoreJobId}`);

  const job = await backup.send(new DescribeRestoreJobCommand({
    RestoreJobId: restoreJobId
  }));

  const arn = job.CreatedResourceArn;
  if (!arn) {
    // Nothing was created (the restore failed early), so nothing to clean up.
    return;
  }

  if (arn.includes(':dynamodb:')) {
    const tableName = arn.split('/').pop()!;
    await dynamodb.send(new DeleteTableCommand({ TableName: tableName }));
  } else if (arn.includes(':rds:')) {
    const id = arn.split(':').pop()!;
    await rds.send(new DeleteDBInstanceCommand({
      DBInstanceIdentifier: id,
      SkipFinalSnapshot: true,
      DeleteAutomatedBackups: true
    }));
  } else if (arn.includes(':volume/')) {
    const volumeId = arn.split('/').pop()!;
    await ec2.send(new DeleteVolumeCommand({ VolumeId: volumeId }));
  } else {
    // Fail loudly rather than silently leaking an unrecognised resource type.
    throw new Error(`No cleanup handler for restored resource ${arn}`);
  }

  console.log(`Deleted test resource ${arn}`);
}

async function publishTestMetrics(testResults: TestResults): Promise<void> {
  const metricData = [
    {
      MetricName: 'TotalTests',
      Value: testResults.totalTests,
      Unit: 'Count'
    },
    {
      MetricName: 'SuccessfulTests',
      Value: testResults.successfulTests,
      Unit: 'Count'
    },
    {
      MetricName: 'FailedTests',
      Value: testResults.failedTests,
      Unit: 'Count'
    },
    {
      MetricName: 'TestSuccessRate',
      Value: testResults.successRate,
      Unit: 'Percent'
    },
    {
      MetricName: 'AverageRTO',
      Value: testResults.averageRTO,
      Unit: 'Milliseconds'
    }
  ];

  await cloudwatch.send(new PutMetricDataCommand({
    Namespace: 'DR/Testing',
    MetricData: metricData.map(metric => ({
      ...metric,
      Timestamp: new Date()
    }))
  }));

  console.log('Test metrics published to CloudWatch');
}

function generateRecommendations(testResults: TestResults): string[] {
  const recommendations: string[] = [];
  
  if (testResults.successRate < 90) {
    recommendations.push('Review failed restore operations and update backup configurations');
  }
  
  if (testResults.averageRTO > 1800000) { // 30 minutes
    recommendations.push('Consider optimizing restore performance or adjusting RTO targets');
  }
  
  if (testResults.failedTests > 0) {
    recommendations.push('Investigate backup integrity and restore procedures');
  }

  if (testResults.totalTests === 0) {
    recommendations.push('No recent recovery points found - verify backup scheduling');
  }
  
  return recommendations;
}
```

## Step 5: Monitoring Stack

Create `lib/monitoring-stack.ts` for comprehensive monitoring:

```typescript
// lib/monitoring-stack.ts
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as backup from 'aws-cdk-lib/aws-backup';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface MonitoringProps extends cdk.StackProps {
  backupVault: backup.BackupVault;
  notificationEmail: string;
}

export class BackupMonitoringStack extends cdk.Stack {
  public readonly dashboard: cloudwatch.Dashboard;

  constructor(scope: Construct, id: string, props: MonitoringProps) {
    super(scope, id, props);

    // Create comprehensive monitoring dashboard
    this.dashboard = new cloudwatch.Dashboard(this, 'BackupMonitoringDashboard', {
      dashboardName: 'CrossAccountBackupMonitoring',
      widgets: [
        // Backup success rate widget
        new cloudwatch.GraphWidget({
          title: 'Backup Job Success Rate',
          left: [
            new cloudwatch.Metric({
              namespace: 'AWS/Backup',
              metricName: 'NumberOfBackupJobsCompleted',
              statistic: 'Sum',
              period: cdk.Duration.hours(24)
            }),
            new cloudwatch.Metric({
              namespace: 'AWS/Backup',
              metricName: 'NumberOfBackupJobsFailed',
              statistic: 'Sum',
              period: cdk.Duration.hours(24)
            })
          ],
          width: 12,
          height: 6
        }),

        // DR test results widget
        new cloudwatch.GraphWidget({
          title: 'DR Test Results',
          left: [
            new cloudwatch.Metric({
              namespace: 'DR/Testing',
              metricName: 'TestSuccessRate',
              statistic: 'Average',
              period: cdk.Duration.days(1)
            }),
            new cloudwatch.Metric({
              namespace: 'DR/Testing',
              metricName: 'AverageRTO',
              statistic: 'Average',
              period: cdk.Duration.days(1)
            })
          ],
          width: 12,
          height: 6
        }),

        // Cost tracking widget.
        //
        // `AWS/Billing` metrics are published only by the payer account, only
        // into us-east-1, and only when "Receive Billing Alerts" is enabled in
        // billing preferences. Without `region: 'us-east-1'` this widget is
        // empty in any other region, which reads as "no backup costs".
        new cloudwatch.SingleValueWidget({
          title: 'Estimated Backup Charges (payer account)',
          metrics: [
            new cloudwatch.Metric({
              namespace: 'AWS/Billing',
              metricName: 'EstimatedCharges',
              dimensionsMap: {
                Currency: 'USD',
                ServiceName: 'AWSBackup'
              },
              statistic: 'Maximum',
              period: cdk.Duration.days(1),
              region: 'us-east-1'
            })
          ],
          width: 6,
          height: 6
        }),

        // Recovery point count widget.
        // The metric is `NumberOfRecoveryPointsCompleted` -- there is no
        // `...Created` metric, and a widget pointed at a nonexistent metric
        // renders an empty graph rather than an error.
        new cloudwatch.SingleValueWidget({
          title: 'Total Recovery Points',
          metrics: [
            new cloudwatch.Metric({
              namespace: 'AWS/Backup',
              metricName: 'NumberOfRecoveryPointsCompleted',
              statistic: 'Sum',
              period: cdk.Duration.days(1)
            })
          ],
          width: 6,
          height: 6
        })
      ]
    });

    // Create alarms for critical metrics
    this.createAlarms(props);

    // Output dashboard URL
    new cdk.CfnOutput(this, 'DashboardURL', {
      value: `https://console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${this.dashboard.dashboardName}`,
      description: 'URL to the backup monitoring dashboard'
    });
  }

  private createAlarms(props: MonitoringProps): void {
    // Create SNS topic for alarms
    const alarmTopic = new sns.Topic(this, 'BackupAlarmTopic', {
      displayName: 'Backup Monitoring Alarms'
    });

    alarmTopic.addSubscription(
      new cdk.aws_sns_subscriptions.EmailSubscription(props.notificationEmail)
    );

    // Backup failure alarm
    const backupFailureAlarm = new cloudwatch.Alarm(this, 'BackupFailureAlarm', {
      alarmName: 'BackupJobFailures',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/Backup',
        metricName: 'NumberOfBackupJobsFailed',
        statistic: 'Sum',
        period: cdk.Duration.hours(24)
      }),
      threshold: 1,
      evaluationPeriods: 1,
      alarmDescription: 'Alert when backup jobs fail',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });

    backupFailureAlarm.addAlarmAction(
      new cdk.aws_cloudwatch_actions.SnsAction(alarmTopic)
    );

    // DR test failure alarm
    const drTestFailureAlarm = new cloudwatch.Alarm(this, 'DRTestFailureAlarm', {
      alarmName: 'DRTestFailures',
      metric: new cloudwatch.Metric({
        namespace: 'DR/Testing',
        metricName: 'TestSuccessRate',
        statistic: 'Average',
        period: cdk.Duration.days(1)
      }),
      threshold: 90,
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      evaluationPeriods: 1,
      alarmDescription: 'Alert when DR test success rate drops below 90%',
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING
    });

    drTestFailureAlarm.addAlarmAction(
      new cdk.aws_cloudwatch_actions.SnsAction(alarmTopic)
    );
  }
}
```

## Step 6: Resource Tagging Strategy

Before deploying, ensure your AWS resources are properly tagged for backup selection. Create a tagging script or use AWS Tag Editor:

```bash
#!/bin/bash
# tag-resources.sh - Script to tag resources for backup

# Tag EC2 instances
aws ec2 create-tags \
    --resources i-1234567890abcdef0 \
    --tags Key=Environment,Value=Production \
           Key=BackupRequired,Value=true \
           Key=DataClassification,Value=Critical

# Tag RDS instances  
aws rds add-tags-to-resource \
    --resource-name arn:aws:rds:us-west-2:123456789012:db:prod-database \
    --tags Key=Environment,Value=Production \
           Key=BackupRequired,Value=true \
           Key=DatabaseBackup,Value=enabled

# Tag DynamoDB tables
aws dynamodb tag-resource \
    --resource-arn arn:aws:dynamodb:us-west-2:123456789012:table/ProductionTable \
    --tags Key=Environment,Value=Production \
           Key=BackupRequired,Value=true \
           Key=DataClassification,Value=Critical

# Tag EBS volumes
aws ec2 create-tags \
    --resources vol-1234567890abcdef0 \
    --tags Key=Environment,Value=Production \
           Key=FilesystemBackup,Value=enabled \
           Key=BackupRequired,Value=true
```

## Step 7: Deployment Process

Deploy the complete solution step by step:

```bash
# 1. Install dependencies
npm install

# 2. Bootstrap CDK in every account/region pair involved, including the
#    backup and DR accounts -- a cross-account deployment fails on the first
#    unbootstrapped target.
npx cdk bootstrap aws://111122223333/us-west-2
npx cdk bootstrap aws://444455556666/us-west-2
npx cdk bootstrap aws://777788889999/us-east-1

# 3. Create the destination vaults FIRST. The copy actions in the backup plan
#    reference them by ARN, and AWS Backup validates the destination at
#    create time.
npx cdk deploy CentralBackupVaultStack --profile backup-account
npx cdk deploy DrBackupVaultStack      --profile dr-account

# 4. Then the source account's backup infrastructure
npx cdk deploy BackupStack

# 5. DR testing and monitoring
npx cdk deploy DRTestingStack MonitoringStack

# 6. Verify
npx cdk list
```

Note the absence of `--parameters` here. The account IDs and retention values
live in `bin/app.ts` as plain TypeScript, so they are resolved at synthesis
time; they are not CloudFormation `Parameters`. Passing
`--parameters backupAccountId=...` fails with *"Parameters: [backupAccountId] do
not exist in the template"*. To vary these per deployment, use CDK context
instead:

```bash
npx cdk deploy BackupStack -c backupAccountId=444455556666
```

```typescript
// and read it in bin/app.ts
const backupAccountId = app.node.tryGetContext('backupAccountId') ?? '444455556666';
```

## Step 8: Testing and Validation

After deployment, test the system:

```bash
# Test DR function manually
aws lambda invoke \
    --function-name $(aws cloudformation describe-stacks \
        --stack-name DRTestingStack \
        --query 'Stacks[0].Outputs[?OutputKey==`DRTestFunctionName`].OutputValue' \
        --output text) \
    --payload '{"testType":"sample","maxTestRestores":1,"resourceTypes":["EBS"]}' \
    response.json

# Check the response
cat response.json

# View CloudWatch logs
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/DRTestingStack

# Check backup jobs
aws backup list-backup-jobs --by-state COMPLETED

# View compliance reports
aws backup list-report-jobs
```

This structured approach provides clear implementation guidance for each component, showing exactly how to organize and deploy the TypeScript code in a real AWS environment.

## Ongoing Operations

Once deployed, your backup solution will run automatically. Here's how to manage it:

**Daily Operations:**

- Monitor the CloudWatch dashboard for backup success rates
- Review backup job notifications via email
- Check compliance reports in the S3 bucket

**Weekly Operations:**

- Review DR test results from automated monthly tests
- Analyze cost trends and optimization opportunities
- Update resource tags as infrastructure changes

**Monthly Operations:**

- Review compliance reports and audit findings
- Validate cross-account permissions and access
- Update backup retention policies if needed

## Key Benefits of the Simplified Approach

**Reduced Complexity**: Scheduling, cross-account copying, lifecycle transitions, retention enforcement and audit reporting are all declarative configuration rather than code you own. The custom code that remains in this post is entirely restore *testing* — which is the part worth your attention anyway.

**Native AWS Integration**: AWS Backup covers RDS, Aurora, EBS, EC2, DynamoDB, EFS, FSx, Storage Gateway, DocumentDB, Neptune, Redshift, S3, Timestream and SAP HANA on EC2 through one API, so you are not writing per-service snapshot logic. Check the [supported resources list](https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html#supported-resources) before assuming coverage — the gaps tend to be where custom work reappears.

**Cost Optimization**: Cold storage is roughly a quarter the price of warm storage, so lifecycle rules genuinely help — subject to the two constraints in Step 2: only some resource types support cold storage, and a 90-day minimum applies once a recovery point moves there. Budget for the copies as well: a cross-account plus cross-region copy means you are storing three of everything.

**Compliance Automation**: Audit Manager gives you controls and scheduled reports, which is the evidence an auditor asks for. It does not certify anything against a standard — see the note on framework naming above.

**Operational Simplicity**: Single console for monitoring, alerting, and management across all backup operations and accounts.

## Conclusion

The simplified AWS Backup approach delivers enterprise-grade cross-account backup and disaster recovery capabilities with significantly reduced complexity. By leveraging AWS Backup's native features you move scheduling, copying, lifecycle and reporting out of code you maintain and into service configuration — and you get to spend the time you save on the thing that actually determines whether the strategy works, which is testing restores.

**Key Advantages:**

- **Simplified Architecture**: Single managed service replaces complex orchestration
- **Reduced Maintenance**: AWS manages the underlying infrastructure and updates
- **Auditable Compliance**: Scheduled reports and controls produce the evidence auditors ask for
- **Cost Efficiency**: Lifecycle management moves eligible recovery points to cold storage automatically
- **Operational Excellence**: Integrated monitoring and alerting through CloudWatch

**The one thing to get right**: an untested backup is a hypothesis. The Vault Lock configuration and the restore-testing pipeline are what turn this from a scheduled snapshot job into a disaster recovery capability — and they are the two parts most often skipped.

This approach is ideal for organizations that want enterprise-grade backup and DR capabilities without the complexity of custom solutions. The simplified implementation maintains security, compliance, and operational requirements while dramatically reducing development and maintenance overhead.

## More in This Series

This is post 5 of 5 in the **AWS Cross-Account Patterns** series:

1. [Cross-Account Lambda Access to S3](/posts/cross-account-lambda-s3-access/)
2. [Cross-Account EventBridge Integration](/posts/2025/07/30/cross-account-eventbridge-integration/)
3. [Implementing Cross-Account CI/CD Pipelines](/posts/2025/08/06/cross-account-cicd-pipelines/)
4. [Cross-Account Monitoring and Observability](/posts/cross-account-monitoring-observability/)
5. **Simplified Cross-Account Backup and Disaster Recovery** (this post)
