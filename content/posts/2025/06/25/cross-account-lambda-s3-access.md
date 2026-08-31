---
title: 'Cross-Account Lambda Access to S3: A Complete Implementation Guide'
date: 2025-06-25T23:04:13.000Z
draft: false
categories:
  - Cloud Computing
  - AWS
tags:
  - AWS
  - Lambda
  - S3
  - IAM
  - Cross-Account
  - Security
series: "AWS Cross-Account Patterns"
url: /posts/cross-account-lambda-s3-access/
---

Setting up cross-account access between AWS Lambda and S3 is a common requirement in enterprise environments where resources are distributed across multiple AWS accounts for security, compliance, or organizational reasons. This guide provides a comprehensive walkthrough of establishing secure cross-account access, covering IAM role configuration, bucket policies, and practical implementation patterns.

Cross-account access enables Lambda functions in one AWS account (Account A) to securely access S3 buckets in another account (Account B). This pattern is essential for data processing workflows, backup operations, and multi-account architectures where centralized data storage serves multiple application accounts.

## Architecture Overview

There are two distinct ways to do this, and conflating them is the most common source of confusion:

1. **Resource-policy access (used in this guide).** The bucket policy in Account B names Account A's Lambda execution role directly as a `Principal`. The Lambda function calls S3 with its own credentials — there is no `sts:AssumeRole` call anywhere. Access is granted only where the identity policy in Account A *and* the bucket policy in Account B both allow the action.
2. **Role assumption.** Account A's Lambda assumes a role that lives in Account B, then calls S3 with those temporary credentials. Here the bucket policy never mentions Account A at all; the role's trust policy does.

Pattern 1 is simpler and is the right default for a bucket you control on both sides. Pattern 2 is what you want when Account B belongs to someone else, when you need an external ID to guard against the confused-deputy problem, or when object writes must be attributed to a principal in Account B.

The rest of this guide implements pattern 1. **Account A** contains the Lambda function and its execution role. **Account B** hosts the S3 bucket. The bucket policy in Account B is what makes the access possible.

{{< plantuml id="cross-account-architecture" >}}
@startuml
!theme aws-orange
title Cross-Account Lambda S3 Access Architecture

cloud "Account A (123456789012)" as AccountA {
  rectangle "Lambda Function" as Lambda
  rectangle "Execution Role\n(CrossAccountS3Role)" as ExecutionRole
}

cloud "Account B (987654321098)" as AccountB {
  storage "S3 Bucket\n(my-cross-account-bucket)" as S3Bucket
  rectangle "Bucket Policy" as BucketPolicy
}

Lambda --> ExecutionRole : "Assumes"
ExecutionRole --> S3Bucket : "Accesses via\nBucket Policy"
BucketPolicy --> S3Bucket : "Grants Access"

note right of ExecutionRole
  Role ARN:
  arn:aws:iam::123456789012:role/CrossAccountS3Role
end note

note left of BucketPolicy
  Allows actions from
  Account A's role ARN
end note
@enduml
{{< /plantuml >}}

## Step 1: Setting Up the IAM Role in Account A

The first step involves creating an IAM role in Account A that your Lambda function will use to access the S3 bucket in Account B. This role must have the necessary permissions and be configured to be assumed by the Lambda service.

Create the IAM role with the following trust policy that allows the Lambda service to assume it:

```json
// trust-policy.json - Allows Lambda service to assume this role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Next, create a permissions policy that grants the necessary S3 actions. This policy should be as restrictive as possible while meeting your functional requirements:

```json
// cross-account-s3-policy.json - Permissions for S3 access
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ObjectLevelAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::my-cross-account-bucket/*"
    },
    {
      "Sid": "BucketLevelAccess",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-cross-account-bucket"
    }
  ]
}
```

Note the split between the two statements. Object-level actions such as `s3:GetObject` only ever apply to the object ARN (`bucket/*`), while `s3:ListBucket` only applies to the bucket ARN. Granting every action on both ARNs — as is commonly seen — is not a security hole, but it is noise: IAM Access Analyzer will flag it, and it obscures what the role can actually do.

Create the role using the AWS CLI or CloudFormation. Here's the CLI approach:

```bash
# Create the IAM role
aws iam create-role \
    --role-name CrossAccountS3Role \
    --assume-role-policy-document file://trust-policy.json

# Attach the S3 permissions policy
aws iam put-role-policy \
    --role-name CrossAccountS3Role \
    --policy-name CrossAccountS3Policy \
    --policy-document file://cross-account-s3-policy.json

# Attach the basic Lambda execution role (for CloudWatch logs)
aws iam attach-role-policy \
    --role-name CrossAccountS3Role \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

After creating the role, note the Role ARN which will be in the format: `arn:aws:iam::123456789012:role/CrossAccountS3Role`. You'll need this ARN for the bucket policy in Account B.

## Step 2: Configuring the S3 Bucket Policy in Account B

The S3 bucket in Account B requires a bucket policy that explicitly grants access to the IAM role from Account A. This policy acts as a resource-based access control mechanism that works in conjunction with the identity-based policies in Account A.

Create a bucket policy that allows the specific role ARN from Account A to perform the required S3 operations:

```json
// bucket-policy.json - Grants access to Account A's role
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CrossAccountLambdaAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/CrossAccountS3Role"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-cross-account-bucket",
        "arn:aws:s3:::my-cross-account-bucket/*"
      ]
    }
  ]
}
```

Apply the bucket policy using the AWS CLI:

```bash
# Apply the bucket policy to grant cross-account access
aws s3api put-bucket-policy \
    --bucket my-cross-account-bucket \
    --policy file://bucket-policy.json
```

For enhanced security, add conditions to the bucket policy. One caveat first: putting `"Bool": {"aws:SecureTransport": "true"}` on the `Allow` statement constrains only *that* statement — any other statement in the policy can still permit plaintext access. To actually require TLS across the whole bucket you need a separate explicit `Deny`, which overrides every `Allow`:

```json
// Enhanced bucket policy with security conditions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CrossAccountLambdaAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/CrossAccountS3Role"
      },
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-cross-account-bucket",
        "arn:aws:s3:::my-cross-account-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "DenyUnencryptedTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::my-cross-account-bucket",
        "arn:aws:s3:::my-cross-account-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### The gotcha that will bite you six months from now

When a bucket policy names a role ARN as its `Principal`, IAM silently resolves it to the role's internal *unique ID*. If somebody deletes and recreates `CrossAccountS3Role` — same name, same ARN — the new role gets a new unique ID and the bucket policy no longer matches it. Access breaks with a bare `AccessDenied`, and nothing in the policy text looks wrong.

If your roles get recreated by CI, delegate to the account root and let a condition do the narrowing:

```json
{
  "Sid": "CrossAccountLambdaAccess",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
  "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
  "Resource": "arn:aws:s3:::my-cross-account-bucket/*",
  "Condition": {
    "ArnLike": {
      "aws:PrincipalArn": "arn:aws:iam::123456789012:role/CrossAccount*"
    }
  }
}
```

This says "any principal in Account A whose ARN matches this pattern" rather than pinning one role instance, and `aws:PrincipalArn` keeps it from becoming a blanket grant to the entire account.

## Step 2b: Encryption — The Step That Breaks Most Setups

If the bucket uses SSE-KMS with a customer managed key, everything above is still not enough. This is comfortably the most common reason an otherwise correct cross-account setup returns `AccessDenied`: **the KMS key policy is a third, independent gate**, and unlike a bucket policy it has no implicit fallback.

Account A's role needs KMS permissions in its identity policy:

```json
{
  "Sid": "KmsForCrossAccountBucket",
  "Effect": "Allow",
  "Action": [
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": "arn:aws:kms:us-east-1:987654321098:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
```

And the key policy in Account B must grant that role access:

```json
{
  "Sid": "AllowCrossAccountUseOfKey",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::123456789012:role/CrossAccountS3Role"
  },
  "Action": [
    "kms:Decrypt",
    "kms:GenerateDataKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:ViaService": "s3.us-east-1.amazonaws.com"
    }
  }
}
```

`kms:Decrypt` covers reads and `kms:GenerateDataKey` covers writes. The `kms:ViaService` condition restricts the key to use through S3, so the grant does not become a general-purpose decryption capability for Account A. SSE-S3 (`AES256`) needs none of this — only customer managed KMS keys do.

## Step 2c: Who Owns the Objects You Write?

When a principal in Account A writes an object into Account B's bucket, ownership of the resulting object has some history worth knowing.

Buckets created since April 2023 default to **Bucket owner enforced** object ownership, which disables ACLs entirely. Under that setting Account B owns every object regardless of who uploaded it, and this whole class of problem disappears. Leave it enabled.

On older buckets where ACLs are still enabled, the *uploading* account retains ownership of objects it writes. Account B then owns the bucket but cannot read some of the objects inside it — a genuinely confusing failure mode. The historical workaround was for writers to send `--acl bucket-owner-full-control` on every upload and for the bucket policy to enforce it with a condition on `s3:x-amz-acl`. If you inherit a bucket like this, migrating it to bucket-owner-enforced beats maintaining that discipline forever.

## Step 3: Sharing ARNs Between Accounts

Securely sharing the IAM role ARN between accounts is crucial for proper configuration. Several approaches can facilitate this ARN sharing while maintaining security best practices.

**AWS Systems Manager Parameter Store** can hold the ARN, but watch out for a common misconception here: SSM parameters have **no resource-based policy**. The `put-parameter-policy` API sounds like it grants cross-account access, but it only supports the `Expiration`, `ExpirationNotification` and `NoChangeNotification` policy types on *advanced*-tier parameters. It cannot grant another account anything.

To share a parameter across accounts you either share it via **AWS Resource Access Manager** (advanced-tier parameters only), or you let the consumer assume a read-only role in the producer account:

```bash
# In Account A - store the role ARN
aws ssm put-parameter \
    --name "/cross-account/lambda-role-arn" \
    --value "arn:aws:iam::123456789012:role/CrossAccountS3Role" \
    --type "String" \
    --description "Role ARN for cross-account S3 access"

# In Account A - a role Account B can assume to read it
aws iam create-role \
    --role-name ConfigReaderForAccountB \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": { "AWS": "arn:aws:iam::987654321098:root" },
            "Action": "sts:AssumeRole"
        }]
    }'

aws iam put-role-policy \
    --role-name ConfigReaderForAccountB \
    --policy-name ReadCrossAccountParameters \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "ssm:GetParameter",
            "Resource": "arn:aws:ssm:us-east-1:123456789012:parameter/cross-account/*"
        }]
    }'
```

**Infrastructure as Code** can automate this too, with one important caveat: CloudFormation `Outputs` with an `Export` name are scoped to a **single account and region**. `Fn::ImportValue` cannot cross an account boundary, so the template below serves consumers *inside* Account A only. Moving a value into Account B needs a real cross-account channel — an SSM parameter read through an assumed role as above, a Terraform remote state data source, or simply a pipeline variable.

```yaml
# CloudFormation template in Account A
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  CrossAccountS3Role:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CrossAccountS3Role
      AssumeRolePolicyDocument: {}   # trust policy from Step 1
      Policies: []                   # permissions policies from Step 1
Outputs:
  CrossAccountRoleArn:
    Description: ARN of the cross-account S3 access role
    Value: !GetAtt CrossAccountS3Role.Arn
    Export:
      Name: CrossAccountS3RoleArn   # resolvable only within this account and region
```

**AWS Secrets Manager** is a genuine option here, because unlike Parameter Store it *does* support resource-based policies: you can attach a policy to the secret granting `secretsmanager:GetSecretValue` to Account B directly, with no role assumption involved. A role ARN is not secret, though, so this is worth the extra cost only when you are sharing real credentials alongside it.

## Step 4: Implementing the Lambda Function

With the IAM role and bucket policy configured, implement your Lambda function in Account A to access the S3 bucket in Account B. The function should use the AWS SDK v3 with proper error handling and logging.

```typescript
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';

interface CrossAccountS3Event {
  bucketName: string;
  objectKey: string;
  operation: 'get' | 'put' | 'delete';
  data?: string;
}

// Created once, outside the handler, so the client and its connection pool
// are reused across warm invocations. The region must be the *bucket's*
// region, not necessarily the Lambda's.
const s3Client = new S3Client({ region: process.env.BUCKET_REGION });

export const handler = async (event: CrossAccountS3Event): Promise<unknown> => {
  try {
    switch (event.operation) {
      case 'get':
        return await getObjectFromCrossAccountBucket(s3Client, event.bucketName, event.objectKey);
      
      case 'put':
        return await putObjectToCrossAccountBucket(s3Client, event.bucketName, event.objectKey, event.data);
      
      default:
        throw new Error(`Unsupported operation: ${event.operation}`);
    }
  } catch (error) {
    // In TypeScript 4.4+ `error` is typed `unknown`, so reading `.message`
    // directly is a compile error under `useUnknownInCatchVariables`.
    console.error('Cross-account S3 operation failed:', {
      error: error instanceof Error ? error.message : String(error),
      bucket: event.bucketName,
      key: event.objectKey,
      operation: event.operation
    });
    throw error;
  }
};

async function getObjectFromCrossAccountBucket(
  s3Client: S3Client,
  bucketName: string,
  objectKey: string
): Promise<string> {
  const command = new GetObjectCommand({
    Bucket: bucketName,
    Key: objectKey
  });

  const response = await s3Client.send(command);
  const bodyContents = await response.Body?.transformToString();
  
  console.log('Successfully retrieved object from cross-account bucket:', {
    bucket: bucketName,
    key: objectKey,
    contentLength: response.ContentLength
  });

  return bodyContents || '';
}

async function putObjectToCrossAccountBucket(
  s3Client: S3Client,
  bucketName: string,
  objectKey: string,
  data?: string
): Promise<void> {
  if (!data) {
    throw new Error('Data is required for put operation');
  }

  const command = new PutObjectCommand({
    Bucket: bucketName,
    Key: objectKey,
    Body: data,
    ContentType: 'text/plain'
  });

  await s3Client.send(command);
  
  console.log('Successfully stored object in cross-account bucket:', {
    bucket: bucketName,
    key: objectKey,
    dataLength: data.length
  });
}
```

Deploy the Lambda function with the IAM role created in Step 1:

```bash
# The handler above is TypeScript, so compile it first. The AWS SDK v3 is
# present in the managed runtime, so bundle it as a dev dependency only.
npx esbuild src/index.ts --bundle --platform=node --target=node22 \
    --outfile=dist/index.js --external:@aws-sdk/*

(cd dist && zip -r ../lambda-function.zip index.js)

aws lambda create-function \
    --function-name CrossAccountS3Access \
    --runtime nodejs22.x \
    --role arn:aws:iam::123456789012:role/CrossAccountS3Role \
    --handler index.handler \
    --zip-file fileb://lambda-function.zip \
    --environment 'Variables={BUCKET_REGION=us-east-1}' \
    --timeout 30
```

Check the [Lambda runtime support policy](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) before you pin a runtime — `nodejs18.x` reached end of support in 2025, and deploying onto a deprecated runtime eventually blocks both updates and invocations.

## Testing and Validation

Thorough testing ensures that your cross-account setup works correctly and handles error conditions gracefully. Create test objects and verify that your Lambda function can perform the expected operations.

Test the Lambda function with different scenarios:

```typescript
// Test event for getting an object
const getTestEvent = {
  bucketName: 'my-cross-account-bucket',
  objectKey: 'test-files/sample.txt',
  operation: 'get'
};

// Test event for putting an object
const putTestEvent = {
  bucketName: 'my-cross-account-bucket',
  objectKey: 'test-files/output.txt',
  operation: 'put',
  data: 'Hello from cross-account Lambda!'
};
```

Invoke the Lambda function using the AWS CLI to validate functionality:

```bash
# Test getting an object
aws lambda invoke \
    --function-name CrossAccountS3Access \
    --payload '{"bucketName":"my-cross-account-bucket","objectKey":"test-files/sample.txt","operation":"get"}' \
    response.json

# Test putting an object
aws lambda invoke \
    --function-name CrossAccountS3Access \
    --payload '{"bucketName":"my-cross-account-bucket","objectKey":"test-files/output.txt","operation":"put","data":"Test data"}' \
    response.json
```

Monitor CloudWatch logs for both successful operations and error conditions. Verify that appropriate log entries are created and that error handling works as expected.

## Security Considerations and Best Practices

Implementing cross-account access requires careful attention to security principles to prevent unauthorized access and data breaches. Follow the principle of least privilege by granting only the minimum permissions necessary for your use case.

**Regular permission auditing** should be performed to ensure that cross-account access remains appropriate and necessary. Remove unused permissions and regularly review bucket policies and IAM roles for compliance with current requirements.

**Monitoring and alerting** help detect unusual access patterns or potential security issues. Set up CloudTrail logging and CloudWatch alarms to monitor cross-account S3 operations:

```json
// CloudWatch alarm for unusual cross-account access
{
  "AlarmName": "CrossAccountS3AccessAnomalies",
  "MetricName": "4xxErrors",
  "Namespace": "AWS/S3",
  "Statistic": "Sum",
  "Period": 300,
  "EvaluationPeriods": 2,
  "Threshold": 5,
  "ComparisonOperator": "GreaterThanThreshold",
  "TreatMissingData": "notBreaching",
  "Dimensions": [
    {
      "Name": "BucketName",
      "Value": "my-cross-account-bucket"
    },
    {
      "Name": "FilterId",
      "Value": "EntireBucket"
    }
  ]
}
```

Two prerequisites that are easy to miss. The metric is `4xxErrors`, plural — `4xxError` silently never matches anything, and the alarm sits in `INSUFFICIENT_DATA` forever looking healthy. And `4xxErrors` is a *request* metric, not a storage metric: it is only published if you have enabled [S3 request metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-configurations.html) on the bucket, which is billed separately and requires the `FilterId` dimension naming the metrics configuration.

**Encryption** should be enforced for data in transit and at rest. Use HTTPS for all API calls and configure S3 bucket encryption with appropriate key management policies.

## Troubleshooting Common Issues

Several common issues can prevent successful cross-account access. **Access denied errors** typically indicate problems with IAM permissions or bucket policies. Verify that the role ARN in the bucket policy exactly matches the ARN of the Lambda execution role.

Work through the three gates in order, because they fail independently and produce the same error message:

1. **Account A's identity policy** — does the execution role allow the action on that exact ARN? Remember `s3:ListBucket` needs the bucket ARN, not `bucket/*`.
2. **Account B's bucket policy** — does the `Principal` match the execution role exactly? If the role was recreated, see the unique-ID gotcha above.
3. **The KMS key policy** — if the bucket uses a customer managed key, this is the gate that fails most often, and the S3 error message does not mention KMS at all.

There is deliberately no `sts:AssumeRole` in this pattern, so "check the trust policy" is not the fix here — the Lambda uses its own credentials throughout. If you *are* seeing `AccessDenied` on `sts:AssumeRole`, you have accidentally built pattern 2 from the architecture section.

**Network connectivity problems** can occur in VPC-enabled Lambda functions. A Lambda in private subnets has no route to the S3 public endpoint by default: add an S3 gateway VPC endpoint (free, and the usual choice) or a NAT gateway. If you use a gateway endpoint, note that its own endpoint policy is a *fourth* gate that can deny the request.

Use AWS CloudTrail to diagnose permission issues by examining the API calls and their responses. For cross-account requests, the denial is recorded in **both** accounts' trails, and Account B's copy is usually the more informative one — it names the bucket policy or key policy that rejected the call.

## Advanced Patterns and Extensions

Cross-account S3 access can be extended with additional patterns for complex enterprise scenarios. **Multi-region replication** enables Lambda functions to access replicated data across different AWS regions while maintaining cross-account boundaries.

**Event-driven processing** can trigger Lambda functions in Account A when objects are created or modified in Account B's S3 bucket. Configure S3 event notifications to send messages to SQS queues or SNS topics that span account boundaries.

**Data transformation pipelines** can leverage cross-account access to process data from centralized storage accounts and write results to application-specific accounts. This pattern supports data lake architectures where raw data is centrally managed while processed data is distributed to relevant business units.

Cross-account Lambda access to S3 provides a foundation for building secure, scalable multi-account architectures. By carefully implementing IAM roles, bucket policies, and proper monitoring, you can enable powerful data processing workflows while maintaining strong security boundaries. Regular review and testing of these configurations ensures continued security and functionality as your architecture evolves.

The patterns and practices outlined in this guide provide a solid foundation for implementing cross-account access in production environments. Start with the basic configuration and gradually add security enhancements and monitoring as your requirements mature.

## More in This Series

This is post 1 of 5 in the **AWS Cross-Account Patterns** series:

1. **Cross-Account Lambda Access to S3** (this post)
2. [Cross-Account EventBridge Integration](/posts/2025/07/30/cross-account-eventbridge-integration/)
3. [Implementing Cross-Account CI/CD Pipelines](/posts/2025/08/06/cross-account-cicd-pipelines/)
4. [Cross-Account Monitoring and Observability](/posts/cross-account-monitoring-observability/)
5. [Simplified Cross-Account Backup and Disaster Recovery](/posts/2025/08/20/simplified-aws-backup-cross-account/)
