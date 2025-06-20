---
title: "Cross-Account Lambda Access to S3: A Complete Implementation Guide"
date: 2025-06-19T16:04:13-07:00
draft: false
categories: ["Cloud Computing", "AWS"]
tags:
- AWS
- Lambda
- S3
- IAM
- Cross-Account
- Security
series: "AWS Cross-Account Patterns"
---

Setting up cross-account access between AWS Lambda and S3 is a common requirement in enterprise environments where resources are distributed across multiple AWS accounts for security, compliance, or organizational reasons. This guide provides a comprehensive walkthrough of establishing secure cross-account access, covering IAM role configuration, bucket policies, and practical implementation patterns.

Cross-account access enables Lambda functions in one AWS account (Account A) to securely access S3 buckets in another account (Account B). This pattern is essential for data processing workflows, backup operations, and multi-account architectures where centralized data storage serves multiple application accounts.

## Architecture Overview

The cross-account access pattern involves three key components working together to provide secure access. **Account A** contains the Lambda function that needs to access S3 resources. **Account B** hosts the S3 bucket containing the data. The **trust relationship** enables Account A's Lambda execution role to assume permissions for Account B's resources.

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

```typescript
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

```typescript
// cross-account-s3-policy.json - Permissions for S3 access
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
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

```typescript
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

For enhanced security, consider adding conditions to the bucket policy to restrict access based on additional factors such as source IP addresses, VPC endpoints, or request encryption:

```typescript
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
    }
  ]
}
```

## Step 3: Sharing ARNs Between Accounts

Securely sharing the IAM role ARN between accounts is crucial for proper configuration. Several approaches can facilitate this ARN sharing while maintaining security best practices.

**AWS Systems Manager Parameter Store** provides a secure way to share configuration values across accounts. Store the role ARN as a parameter in Account A and grant Account B read access:

```bash
# In Account A - Store the role ARN
aws ssm put-parameter \
    --name "/cross-account/lambda-role-arn" \
    --value "arn:aws:iam::123456789012:role/CrossAccountS3Role" \
    --type "String" \
    --description "Role ARN for cross-account S3 access"

# Grant Account B read access to the parameter
aws ssm put-parameter-policy \
    --name "/cross-account/lambda-role-arn" \
    --policy '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::987654321098:root"
                },
                "Action": "ssm:GetParameter",
                "Resource": "*"
            }
        ]
    }'
```

**Infrastructure as Code** tools like CloudFormation or Terraform can automate ARN sharing through stack outputs and cross-stack references:

```typescript
// CloudFormation template in Account A
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "CrossAccountS3Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "RoleName": "CrossAccountS3Role",
        "AssumeRolePolicyDocument": {
          // Trust policy here
        },
        "Policies": [
          // Permissions policies here
        ]
      }
    }
  },
  "Outputs": {
    "CrossAccountRoleArn": {
      "Description": "ARN of the cross-account S3 access role",
      "Value": {
        "Fn::GetAtt": ["CrossAccountS3Role", "Arn"]
      },
      "Export": {
        "Name": "CrossAccountS3RoleArn"
      }
    }
  }
}
```

**AWS Secrets Manager** offers another secure option for sharing sensitive configuration data between accounts with fine-grained access controls and automatic rotation capabilities.

## Step 4: Implementing the Lambda Function

With the IAM role and bucket policy configured, implement your Lambda function in Account A to access the S3 bucket in Account B. The function should use the AWS SDK v3 with proper error handling and logging.

```typescript
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';

interface CrossAccountS3Event {
  bucketName: string;
  objectKey: string;
  operation: 'get' | 'put' | 'delete';
  data?: string;
}

export const handler = async (event: CrossAccountS3Event): Promise<any> => {
  const s3Client = new S3Client({
    region: 'us-east-1',
    credentials: fromNodeProviderChain()
  });

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
    console.error('Cross-account S3 operation failed:', {
      error: error.message,
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
# Package and deploy the Lambda function
zip -r lambda-function.zip index.js node_modules/

aws lambda create-function \
    --function-name CrossAccountS3Access \
    --runtime nodejs18.x \
    --role arn:aws:iam::123456789012:role/CrossAccountS3Role \
    --handler index.handler \
    --zip-file fileb://lambda-function.zip \
    --timeout 30
```

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

```typescript
// CloudWatch alarm for unusual cross-account access
{
  "AlarmName": "CrossAccountS3AccessAnomalies",
  "MetricName": "4xxError",
  "Namespace": "AWS/S3",
  "Statistic": "Sum",
  "Period": 300,
  "EvaluationPeriods": 2,
  "Threshold": 5,
  "ComparisonOperator": "GreaterThanThreshold",
  "Dimensions": [
    {
      "Name": "BucketName",
      "Value": "my-cross-account-bucket"
    }
  ]
}
```

**Encryption** should be enforced for data in transit and at rest. Use HTTPS for all API calls and configure S3 bucket encryption with appropriate key management policies.

## Troubleshooting Common Issues

Several common issues can prevent successful cross-account access. **Access denied errors** typically indicate problems with IAM permissions or bucket policies. Verify that the role ARN in the bucket policy exactly matches the ARN of the Lambda execution role.

**Credential issues** may arise from incorrect role assumption or expired tokens. Ensure that the Lambda function is configured with the correct execution role and that the role has appropriate trust relationships.

**Network connectivity problems** can occur in VPC-enabled Lambda functions. Verify that VPC endpoints or NAT gateways provide appropriate internet access for S3 API calls.

Use AWS CloudTrail to diagnose permission issues by examining the API calls and their responses. CloudTrail logs show which principal made the request and why it was denied.

## Advanced Patterns and Extensions

Cross-account S3 access can be extended with additional patterns for complex enterprise scenarios. **Multi-region replication** enables Lambda functions to access replicated data across different AWS regions while maintaining cross-account boundaries.

**Event-driven processing** can trigger Lambda functions in Account A when objects are created or modified in Account B's S3 bucket. Configure S3 event notifications to send messages to SQS queues or SNS topics that span account boundaries.

**Data transformation pipelines** can leverage cross-account access to process data from centralized storage accounts and write results to application-specific accounts. This pattern supports data lake architectures where raw data is centrally managed while processed data is distributed to relevant business units.

Cross-account Lambda access to S3 provides a foundation for building secure, scalable multi-account architectures. By carefully implementing IAM roles, bucket policies, and proper monitoring, you can enable powerful data processing workflows while maintaining strong security boundaries. Regular review and testing of these configurations ensures continued security and functionality as your architecture evolves.

The patterns and practices outlined in this guide provide a solid foundation for implementing cross-account access in production environments. Start with the basic configuration and gradually add security enhancements and monitoring as your requirements mature.