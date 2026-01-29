---
title: "From CloudFormation to Diagrams: Automating Architecture Documentation"
date: 2026-01-29T09:00:00-07:00
draft: false
categories: ["Software Development", "DevOps", "Cloud Computing"]
tags:
- AWS
- CloudFormation
- SAM
- Serverless
- Documentation
- Automation
- GitHub Actions
- DevOps
- Architecture
- cfn-diagram
---

You're explaining your serverless architecture to a new team member at 2 PM on a Monday. You pull up the architecture diagram from Confluence, walk them through the API Gateway, Lambda functions, DynamoDB tables, and SNS topics. They nod along, asking good questions. Then they clone the repo, open the CloudFormation template, and immediately notice: "Wait, this diagram shows 3 Lambda functions but the template has 7. And where's this SQS queue in the diagram?"

You realize the diagram is 6 months out of date. Someone added new functions, changed the event sources, and refactored the queue architecture—but nobody updated the diagram. Why would they? It takes 30 minutes to open draw.io, find the right shapes, position everything, export it, and upload to Confluence. And next week, it'll be wrong again.

**The core tension:** Architecture diagrams are essential for understanding systems, but maintaining them manually is unsustainable. Every code change makes them more outdated. Teams face a choice: spend hours maintaining diagrams, or abandon them entirely and force everyone to read raw CloudFormation YAML.

**The promise:** There's a better way. What if your architecture diagrams were generated automatically from your CloudFormation templates? Updated on every commit. Always accurate. Multiple formats for different audiences. No manual maintenance required.

## The Documentation Debt Problem

### The Manual Diagram Trap

Most teams create beautiful architecture diagrams during initial design reviews or architecture planning sessions. Someone spends hours in Lucidchart, draw.io, or Visio, carefully arranging AWS service icons, drawing connection arrows, and labeling everything perfectly. The diagram gets uploaded to Confluence, shared in Slack, and presented to stakeholders.

Fast forward three months. The team has:
- Added two new Lambda functions for async processing
- Replaced the SNS topic with an SQS queue for better error handling
- Introduced DynamoDB streams for change data capture
- Added API Gateway authorizers

But the diagram? Still shows the original three Lambda functions and the SNS topic that no longer exists. Nobody updated it because:
- It takes 30+ minutes to locate the original file
- The person who created it left the team
- Everyone's focused on shipping features
- "We'll update it later" becomes "We never updated it"

Eventually, the diagram becomes a historical artifact—interesting but misleading. New team members learn to ignore it.

### Reading Raw CloudFormation Isn't the Answer

Some teams abandon diagrams entirely and tell people to "just read the CloudFormation template." For a simple stack with a dozen resources, this might work. But for a production application with 50+ resources, nested stacks, and complex dependencies, raw YAML is not documentation.

Consider this excerpt from a typical CloudFormation template:

```yaml
OrderProcessingFunction:
  Type: AWS::Serverless::Function
  Properties:
    Handler: index.handler
    Runtime: nodejs18.x
    Events:
      OrderCreated:
        Type: EventBridgRule
        Properties:
          Pattern:
            source:
              - order.service
            detail-type:
              - OrderCreated
      ProcessQueue:
        Type: SQS
        Properties:
          Queue: !GetAtt OrderQueue.Arn
    Environment:
      Variables:
        TABLE_NAME: !Ref OrdersTable
        NOTIFICATION_TOPIC: !Ref NotificationTopic
```

A diagram would instantly show that this Lambda function:
- Responds to EventBridge events
- Processes SQS messages
- Reads/writes to DynamoDB
- Publishes to SNS

But from the YAML alone? You have to trace references, understand intrinsic functions, and mentally construct the architecture.

### The Hidden Costs

Documentation debt accumulates interest:

**Onboarding time increases:** New team members spend days understanding the architecture instead of hours. They interrupt senior engineers with questions that a diagram would answer.

**Architecture decisions poorly communicated:** Without visual representation, it's hard to see patterns, identify bottlenecks, or discuss alternatives during design reviews.

**Security reviews take longer:** Security teams need to understand data flow, network boundaries, and IAM relationships. Reading CloudFormation templates is tedious and error-prone.

**Compliance audits require manual work:** Auditors want architecture diagrams. If you don't have current ones, someone has to create them from scratch under deadline pressure.

**Knowledge silos form:** The architecture exists in the heads of a few senior engineers. When they leave, institutional knowledge walks out the door.

## Infrastructure as Diagrams: A Better Philosophy

There's a fundamental insight that changes everything: **your infrastructure code IS your architecture**. The CloudFormation template, SAM template, or CDK app completely describes what exists in your AWS account. It's the single source of truth.

If the template is the source of truth, why are we maintaining diagrams separately? Why treat them as independent artifacts that need manual synchronization?

### Treating Diagrams as Build Artifacts

Think about other build artifacts in your development process:
- Source code compiles to binaries
- TypeScript transpiles to JavaScript  
- Tests generate coverage reports
- Linters produce analysis results

These aren't manually maintained—they're generated from source code. The same principle applies to architecture diagrams: they should be **generated from your infrastructure code**, not maintained separately.

```
Infrastructure Template (source)
        ↓
   cfn-diagram (compiler)
        ↓
Architecture Diagrams (artifacts)
```

This shift in perspective changes everything:

**Single source of truth:** The CloudFormation/SAM template is authoritative. Diagrams are derived views.

**Always accurate:** Diagrams are regenerated from current code, so they can't drift out of sync.

**Zero maintenance burden:** Changes to infrastructure automatically flow through to diagrams.

**Version controlled:** Diagrams change in the same commits as the infrastructure they document.

**Multiple formats:** Generate different views for different audiences from the same source.

### When Automation Makes Sense

Not every team needs automated diagram generation. Manual diagrams work fine for:
- Stable, rarely-changing infrastructure
- Small projects with a single owner
- High-level conceptual architectures
- Presentation-quality diagrams requiring custom layouts

But automated generation becomes essential when:
- Multiple developers modify infrastructure regularly
- The team struggles to keep documentation current
- Onboarding new team members is slow and painful
- Compliance or security reviews require architecture diagrams
- Stakeholders need visibility into system architecture

If you're using CloudFormation, SAM, or CDK and making infrastructure changes more than once a month, automated diagram generation will save you significant time and frustration.

## Enter cfn-diagram: The Swiss Army Knife

[cfn-diagram](https://github.com/ljacobsson/cfn-diagram) (maintained by @ljacobsson, formerly part of @mhlabs) is an open-source CLI tool that reads CloudFormation templates and generates architecture diagrams in multiple formats. It's production-ready, actively maintained, and widely used in the AWS community.

### What Makes It Special

Unlike tools that focus on a single output format, cfn-diagram is a Swiss Army knife:

**Multiple output formats:**
- **Draw.io** - Editable diagrams for architects who need to refine layouts
- **Mermaid** - Markdown-embeddable diagrams that render in GitHub
- **HTML with vis.js** - Interactive diagrams for documentation sites
- **ASCII art** - Quick terminal views during development

**Works with CloudFormation, SAM, and CDK:**
- Native CloudFormation YAML/JSON support
- SAM templates work directly (SAM is CloudFormation with serverless shortcuts)
- CDK apps supported by reading synthesized CloudFormation from `cdk.out`

**CI/CD ready:**
- Separate CI mode package for automated screenshot generation
- Filter resource types to focus diagrams
- Watch mode for live updates during development

### Installation

```bash
npm install -g @mhlabs/cfn-diagram
```

That's it. No complex dependencies, no cloud credentials required. It's a local tool that reads templates and generates diagrams.

### Why Multiple Formats Matter

Different stakeholders need different diagram formats:

**Architects** want editable diagrams they can refine and customize. They need draw.io format to adjust layouts, add annotations, or prepare presentation-quality visuals.

**Developers** want diagrams visible in GitHub pull requests and README files. They need Mermaid format that renders automatically in markdown.

**Product managers and stakeholders** want interactive exploration. They need HTML diagrams where they can zoom, pan, and click on resources to see details.

**DevOps engineers** want quick terminal feedback during development. They need ASCII art for rapid sanity checks without leaving the command line.

One tool, one source template, four different outputs. Generate all of them and serve different audiences without maintaining separate documentation.

## Real-World Example: Serverless Order Processing API

Let's walk through a realistic serverless application: an order processing API. This is the kind of architecture you'd see in production—not a trivial "Hello World" but also not overly complex.

### The Architecture

Our API handles:
- Creating new orders via REST API
- Storing orders in DynamoDB
- Processing orders asynchronously via SQS
- Sending notifications via SNS
- Capturing order changes with DynamoDB Streams

Here's the SAM template:

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: Order Processing API

Globals:
  Function:
    Runtime: nodejs18.x
    MemorySize: 512
    Timeout: 30
    Environment:
      Variables:
        ORDERS_TABLE: !Ref OrdersTable

Resources:
  # API Gateway
  OrderApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      Auth:
        DefaultAuthorizer: CognitoAuthorizer
        Authorizers:
          CognitoAuthorizer:
            UserPoolArn: !GetAtt UserPool.Arn

  # Lambda Functions
  CreateOrderFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/handlers/create-order/
      Handler: index.handler
      Events:
        CreateOrder:
          Type: Api
          Properties:
            RestApiId: !Ref OrderApi
            Path: /orders
            Method: POST
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref OrdersTable
        - SQSSendMessagePolicy:
            QueueName: !GetAtt OrderQueue.QueueName
      Environment:
        Variables:
          QUEUE_URL: !Ref OrderQueue

  GetOrderFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/handlers/get-order/
      Handler: index.handler
      Events:
        GetOrder:
          Type: Api
          Properties:
            RestApiId: !Ref OrderApi
            Path: /orders/{orderId}
            Method: GET
      Policies:
        - DynamoDBReadPolicy:
            TableName: !Ref OrdersTable

  ProcessOrderFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/handlers/process-order/
      Handler: index.handler
      Events:
        OrderQueue:
          Type: SQS
          Properties:
            Queue: !GetAtt OrderQueue.Arn
            BatchSize: 10
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref OrdersTable
        - SNSPublishMessagePolicy:
            TopicName: !GetAtt NotificationTopic.TopicName
      Environment:
        Variables:
          TOPIC_ARN: !Ref NotificationTopic

  OrderStreamFunction:
    Type: AWS::Serverless::Function
    Properties:
      CodeUri: src/handlers/order-stream/
      Handler: index.handler
      Events:
        Stream:
          Type: DynamoDB
          Properties:
            Stream: !GetAtt OrdersTable.StreamArn
            StartingPosition: TRIM_HORIZON
            BatchSize: 100
      Policies:
        - DynamoDBStreamReadPolicy:
            TableName: !Ref OrdersTable
            StreamName: !GetAtt OrdersTable.StreamArn

  # DynamoDB Table
  OrdersTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: orders
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: orderId
          AttributeType: S
        - AttributeName: customerId
          AttributeType: S
      KeySchema:
        - AttributeName: orderId
          KeyType: HASH
      GlobalSecondaryIndexes:
        - IndexName: customer-index
          KeySchema:
            - AttributeName: customerId
              KeyType: HASH
          Projection:
            ProjectionType: ALL
      StreamSpecification:
        StreamViewType: NEW_AND_OLD_IMAGES

  # SQS Queue
  OrderQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: order-processing-queue
      VisibilityTimeout: 180
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt OrderDLQ.Arn
        maxReceiveCount: 3

  OrderDLQ:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: order-processing-dlq
      MessageRetentionPeriod: 1209600  # 14 days

  # SNS Topic
  NotificationTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: order-notifications
      DisplayName: Order Notifications

  # Cognito User Pool
  UserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: order-api-users
      AutoVerifiedAttributes:
        - email

  # CloudWatch Alarms
  ProcessOrderErrorAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmDescription: Alert on ProcessOrder errors
      MetricName: Errors
      Namespace: AWS/Lambda
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 5
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: FunctionName
          Value: !Ref ProcessOrderFunction

Outputs:
  ApiEndpoint:
    Description: API Gateway endpoint URL
    Value: !Sub 'https://${OrderApi}.execute-api.${AWS::Region}.amazonaws.com/prod'
  
  OrdersTableName:
    Description: DynamoDB table name
    Value: !Ref OrdersTable
```

This is a realistic SAM template—not oversimplified, but not overwhelming. It has the complexity you'd see in production: multiple Lambda functions, event sources, data stores, queues, topics, and monitoring.

Now let's generate diagrams from it.

### Generating Diagrams

Save the template as `template.yaml` and let's see what cfn-diagram can do.

#### Draw.io for Architecture Reviews

```bash
cfn-dia draw.io -t template.yaml -o architecture.drawio
```

This generates an editable draw.io diagram. Open it in VS Code with the [Draw.io Integration extension](https://marketplace.visualstudio.com/items?itemName=hediet.vscode-drawio):

The diagram shows:
- API Gateway connected to CreateOrder and GetOrder functions
- CreateOrderFunction writing to DynamoDB and enqueueing to SQS
- ProcessOrderFunction reading from SQS and publishing to SNS
- OrderStreamFunction triggered by DynamoDB Streams
- Cognito User Pool authorizing the API
- CloudWatch Alarm monitoring ProcessOrderFunction

**Use cases:**
- Architecture review meetings (open and discuss)
- Refining layout for presentations (draw.io is editable)
- Adding annotations and notes
- Exporting to PNG/SVG for slides

#### Mermaid for GitHub README

```bash
cfn-dia mermaid -t template.yaml -o docs/architecture.md
```

This generates a Mermaid diagram that renders automatically in GitHub:

````markdown
```mermaid
graph TD
    OrderApi[API Gateway: OrderApi]
    CreateOrderFunction[Lambda: CreateOrderFunction]
    GetOrderFunction[Lambda: GetOrderFunction]
    ProcessOrderFunction[Lambda: ProcessOrderFunction]
    OrderStreamFunction[Lambda: OrderStreamFunction]
    OrdersTable[DynamoDB: OrdersTable]
    OrderQueue[SQS: OrderQueue]
    OrderDLQ[SQS: OrderDLQ]
    NotificationTopic[SNS: NotificationTopic]
    UserPool[Cognito: UserPool]
    ProcessOrderErrorAlarm[CloudWatch: ProcessOrderErrorAlarm]
    
    OrderApi -->|POST /orders| CreateOrderFunction
    OrderApi -->|GET /orders/{id}| GetOrderFunction
    CreateOrderFunction -->|Write| OrdersTable
    CreateOrderFunction -->|Enqueue| OrderQueue
    GetOrderFunction -->|Read| OrdersTable
    OrderQueue -->|Trigger| ProcessOrderFunction
    ProcessOrderFunction -->|Update| OrdersTable
    ProcessOrderFunction -->|Publish| NotificationTopic
    OrdersTable -->|Stream| OrderStreamFunction
    OrderQueue -->|DLQ| OrderDLQ
    UserPool -->|Authorize| OrderApi
    ProcessOrderErrorAlarm -->|Monitor| ProcessOrderFunction
```
````

**Use cases:**
- README.md architecture section
- Pull request descriptions showing changes
- Architecture Decision Records (ADRs)
- Wiki/documentation pages

The beauty of Mermaid is that it's just text in your markdown. GitHub, GitLab, and many documentation tools render it automatically. No image uploads, no broken links.

#### HTML for Interactive Documentation

```bash
cfn-dia html -t template.yaml -o docs/
```

This generates an HTML file with an interactive vis.js diagram. Open `docs/index.html` in a browser and you get:
- Zoom and pan controls
- Click nodes to see resource details
- Drag to rearrange layout
- Filter by resource type
- Physics-based automatic layout

**Use cases:**
- Documentation sites (GitHub Pages, S3 + CloudFront)
- Internal wiki with iframe embeds
- Stakeholder presentations (interactive exploration)
- Architecture workshops (live discussion tool)

Host it on GitHub Pages:
```bash
# In your repo
mkdir -p docs
cfn-dia html -t template.yaml -o docs/
git add docs/
git commit -m "Add interactive architecture diagram"
git push

# Enable GitHub Pages in repo settings pointing to /docs
```

Now your architecture diagram is accessible at `https://<username>.github.io/<repo>/`.

#### ASCII Art for Quick Checks

```bash
cfn-dia ascii-art -t template.yaml
```

Output:
```
┌──────────────────┐
│  OrderApi (API)  │
└────────┬─────────┘
         │
    ┌────┴─────┬──────────────┐
    │          │              │
┌───▼────┐  ┌──▼─────┐  ┌────▼────────┐
│ Create │  │  Get   │  │  UserPool   │
│ Order  │  │ Order  │  │  (Cognito)  │
└───┬────┘  └──┬─────┘  └─────────────┘
    │          │
    │      ┌───▼──────────┐
    │      │  OrdersTable │
    │      │  (DynamoDB)  │◄────┐
    │      └──────┬───────┘     │
    │             │ Stream      │
    │      ┌──────▼───────┐     │
    │      │ OrderStream  │     │
    │      │   Function   │     │
    │      └──────────────┘     │
    │                           │
┌───▼──────┐              ┌────┴────┐
│OrderQueue│              │ Process │
│  (SQS)   │─────────────►│  Order  │
└──────────┘              │Function │
                          └────┬────┘
                               │
                          ┌────▼──────────┐
                          │ Notification  │
                          │Topic (SNS)    │
                          └───────────────┘
```

**Use cases:**
- Quick sanity checks during development
- Terminal-based code reviews
- Remote SSH sessions without GUI
- Understanding structure before detailed work

Watch mode is particularly useful:
```bash
cfn-dia ascii-art -t template.yaml --watch
```

Now every time you save `template.yaml`, the diagram regenerates instantly. Perfect for rapid iteration.

### Filtering and Customization

Real stacks often include dozens of IAM roles, policies, and log groups that clutter diagrams without adding insight. Filter them out:

```bash
# Exclude IAM resources to focus on architecture
cfn-dia draw.io -t template.yaml \
  -e AWS::IAM::Role \
     AWS::IAM::Policy \
     AWS::Logs::LogGroup

# For multi-stack CDK apps, select specific stacks
cfn-dia html -t cdk.json --stacks ApiStack,DataStack
```

This is crucial for large CloudFormation templates. A production stack might have:
- 10 Lambda functions
- 30 IAM roles (one per function, plus execution roles)
- 10 CloudWatch log groups
- 5 IAM policies

That's 55 resources, but only 15 are architecturally interesting. Filtering lets you generate focused diagrams.

## Automating with GitHub Actions

Manual diagram generation is better than manual diagram maintenance, but we can go further: **fully automated diagram updates on every commit**.

### The Workflow Goals

Here's what we want:
1. Generate diagrams automatically on every push to `main`
2. Update diagrams in pull requests so reviewers see changes
3. Commit updated diagrams back to the repository
4. Optionally: fail CI if diagrams are out of sync (strict mode)

### GitHub Actions Workflow

Create `.github/workflows/update-diagrams.yml`:

```yaml
name: Update Architecture Diagrams

on:
  push:
    branches:
      - main
    paths:
      - 'template.yaml'
      - 'src/**'
  pull_request:
    paths:
      - 'template.yaml'
      - 'src/**'

jobs:
  generate-diagrams:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          
      - name: Install cfn-diagram
        run: npm install -g @mhlabs/cfn-diagram
        
      - name: Generate Draw.io diagram
        run: cfn-dia draw.io -t template.yaml -o docs/architecture.drawio -c
        
      - name: Generate Mermaid diagram
        run: |
          mkdir -p docs
          cfn-dia mermaid -t template.yaml -o docs/architecture.md
          
      - name: Generate HTML diagram
        run: cfn-dia html -t template.yaml -o docs/ -c
        
      - name: Check for changes
        id: check_changes
        run: |
          if git diff --quiet docs/; then
            echo "changed=false" >> $GITHUB_OUTPUT
          else
            echo "changed=true" >> $GITHUB_OUTPUT
          fi
          
      - name: Commit updated diagrams
        if: steps.check_changes.outputs.changed == 'true' && github.event_name == 'push'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add docs/
          git commit -m "docs: update architecture diagrams [skip ci]"
          git push
          
      - name: Comment on PR with diagram
        if: steps.check_changes.outputs.changed == 'true' && github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const diagram = fs.readFileSync('docs/architecture.md', 'utf8');
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## Updated Architecture Diagram\n\n${diagram}`
            });
```

### Workflow Breakdown

Let's understand what this workflow does:

**Triggers:**
- Runs on pushes to `main` when `template.yaml` or source code changes
- Runs on pull requests that modify infrastructure
- The `paths` filter prevents unnecessary runs when only docs change

**Diagram Generation:**
- Installs cfn-diagram via npm
- Generates draw.io, Mermaid, and HTML formats
- The `-c` flag enables CI mode (non-interactive)
- Outputs go to `docs/` directory

**Commit Strategy:**
- Checks if diagrams actually changed (avoids empty commits)
- On `main`: commits and pushes updated diagrams
- `[skip ci]` in commit message prevents infinite loops
- On PRs: comments with the updated Mermaid diagram

**PR Comments:**
The PR comment feature is powerful. When someone opens a PR that changes infrastructure, the bot automatically posts the updated architecture diagram in the PR comments. Reviewers can see how the architecture changes without running cfn-diagram locally.

### Advanced: Multi-Stack CDK Projects

For CDK projects with multiple stacks:

```yaml
- name: Synthesize CDK app
  run: |
    npm ci
    npm run build
    npx cdk synth
    
- name: Generate diagrams for each stack
  run: |
    for stack in ApiStack DataStack AuthStack; do
      cfn-dia draw.io \
        --cdk-output cdk.out \
        --stacks $stack \
        -o docs/${stack}.drawio \
        -c
    done
```

This generates separate diagrams for each stack, making large applications easier to understand.

### Advanced: Diagram Validation (Strict Mode)

Want to enforce that developers update diagrams? Add validation:

```yaml
- name: Validate diagrams are current
  run: |
    cfn-dia draw.io -t template.yaml -o temp.drawio -c
    if ! diff -q temp.drawio docs/architecture.drawio; then
      echo "❌ Diagrams are out of date. Run 'cfn-dia draw.io -t template.yaml' and commit."
      exit 1
    fi
```

This fails the CI build if someone modifies infrastructure without regenerating diagrams. Strict mode is controversial—some teams love it, others find it annoying. Start without it and add if needed.

## Real-World Patterns and Best Practices

### Documentation Site Integration

A polished approach: generate HTML diagrams and deploy them alongside your documentation.

**Structure:**
```
/
├── template.yaml
├── docs/
│   ├── index.md
│   ├── architecture/
│   │   ├── overview.md
│   │   ├── diagram.html          # Interactive diagram
│   │   ├── diagram.drawio        # Editable source
│   │   └── diagram.md            # Mermaid for markdown
│   └── api/
│       └── ...
└── .github/
    └── workflows/
        └── update-diagrams.yml
```

**In `docs/architecture/overview.md`:**
```markdown
# Architecture Overview

Our order processing system uses a serverless architecture on AWS...

## Interactive Diagram

<iframe src="../diagram.html" width="100%" height="600px" frameborder="0"></iframe>

## Static View

For a static view, see the [diagram source](diagram.md).
```

Deploy to GitHub Pages, S3 + CloudFront, or your documentation platform. The interactive diagram becomes part of your living documentation.

### Confluence/Wiki Sync Pattern

Extend this with Confluence synchronization (building on [my earlier PlantUML/Confluence post](/posts/github-actions-plantuml-confluence-sync/)):

```yaml
- name: Generate PNG for Confluence
  run: |
    npm install -g @mhlabs/cfn-diagram-ci
    cfn-dia-ci html -t template.yaml
    # Generates screenshot as PNG
    
- name: Update Confluence page
  run: |
    # Use Confluence API to update page
    # Attach the PNG diagram
    # Update page content with metadata
```

This keeps your Confluence architecture pages synchronized with reality. When infrastructure changes, Confluence updates automatically.

### Multiple Audiences Strategy

Serve different audiences with different formats:

```
/docs
  /architecture
    README.md                    # Links to all versions
    diagram.drawio               # For architects (editable)
    diagram.md                   # For developers (GitHub-rendered Mermaid)
    diagram.html                 # For stakeholders (interactive)
    api-only.drawio              # Filtered view: just API layer
    data-flow.drawio             # Filtered view: just data stores
```

**README.md:**
```markdown
# Architecture Documentation

## For Developers
The [Mermaid diagram](diagram.md) renders directly in GitHub.

## For Architects
Download [diagram.drawio](diagram.drawio) and open in draw.io or VS Code.

## For Stakeholders
View the [interactive diagram](https://yourteam.github.io/project/architecture/diagram.html).

## Focused Views
- [API Layer](api-only.drawio) - Just API Gateway and Lambda functions
- [Data Flow](data-flow.drawio) - Data stores and processing pipelines
```

Generate focused views with filtering:
```bash
# API layer only
cfn-dia draw.io -t template.yaml -o docs/api-only.drawio \
  -e AWS::DynamoDB::Table AWS::SQS::Queue AWS::SNS::Topic

# Data layer only
cfn-dia draw.io -t template.yaml -o docs/data-flow.drawio \
  -e AWS::ApiGateway::RestApi AWS::Lambda::Function AWS::Cognito::UserPool
```

### SAM vs CloudFormation vs CDK

The great news: cfn-diagram works with all three.

**SAM templates work directly:**
```bash
cfn-dia draw.io -t template.yaml
```
SAM templates are CloudFormation templates with the `AWS::Serverless::*` resource types. cfn-diagram understands them natively.

**Pure CloudFormation works out of the box:**
```bash
cfn-dia draw.io -t stack-template.json
```

**CDK requires synthesis first:**
```bash
cdk synth
cfn-dia draw.io --cdk-output cdk.out
```
CDK generates CloudFormation templates in `cdk.out/`. cfn-diagram reads those synthesized templates. The `-s` flag skips synthesis if you've already run it:
```bash
cfn-dia draw.io --cdk-output cdk.out --skip-synth
```

**The beauty:** Same tool, same workflow, regardless of whether you're using SAM, CloudFormation, or CDK. Your choice of infrastructure-as-code tool doesn't lock you into a specific diagramming solution.

### Handling Large Stacks

Production stacks can be massive. A real-world application might have:
- 20+ Lambda functions
- Multiple API Gateways
- Dozens of DynamoDB tables and indexes
- Step Functions state machines
- EventBridge rules
- SQS queues and SNS topics
- Hundreds of IAM roles and policies

Trying to diagram everything at once creates an incomprehensible mess. Instead, generate multiple focused views:

**By layer:**
```bash
# API layer
cfn-dia draw.io -t template.yaml -o docs/api-layer.drawio \
  --include-types AWS::ApiGateway::* AWS::Lambda::Function AWS::Cognito::*

# Data layer
cfn-dia draw.io -t template.yaml -o docs/data-layer.drawio \
  --include-types AWS::DynamoDB::* AWS::S3::* AWS::RDS::*

# Processing layer
cfn-dia draw.io -t template.yaml -o docs/processing.drawio \
  --include-types AWS::Lambda::Function AWS::SQS::* AWS::SNS::* AWS::StepFunctions::*
```

**By domain:**
For multi-stack applications, diagram each stack separately:
```bash
cfn-dia draw.io --stacks OrderProcessingStack -o docs/orders.drawio
cfn-dia draw.io --stacks PaymentStack -o docs/payments.drawio
cfn-dia draw.io --stacks NotificationStack -o docs/notifications.drawio
```

**Exclude infrastructure clutter:**
```bash
cfn-dia draw.io -t template.yaml -o docs/simplified.drawio \
  -e AWS::IAM::Role \
     AWS::IAM::Policy \
     AWS::IAM::ManagedPolicy \
     AWS::Logs::LogGroup \
     AWS::CloudWatch::Alarm
```

This removes IAM, logging, and monitoring resources that, while important, distract from the core architecture.

### Version Control Considerations

Should you commit generated diagrams to git? It depends on the format:

**Definitely commit:**
- **draw.io files** - These are editable artifacts. Someone might make manual refinements.
- **Mermaid markdown** - Small text files that render in GitHub. Essential for README visibility.

**Maybe commit:**
- **HTML files** - Can be large (include vis.js library). Consider hosting separately or building on-demand.

**Don't commit:**
- **ASCII art output** - Temporary, terminal-only views.
- **PNG screenshots** - Binary files that bloat repo size. Generate in CI/CD instead.

**Recommended `.gitignore`:**
```gitignore
# Exclude temporary diagram artifacts
docs/temp*.drawio
docs/*.html

# But do commit the source diagrams
!docs/architecture.drawio
!docs/architecture.md
```

**When to regenerate vs edit manually:**

Generate initially, edit for presentation:
1. Run `cfn-dia draw.io -t template.yaml`
2. Open in draw.io and refine layout
3. Add annotations, adjust positioning
4. Save the customized version
5. Regenerate periodically when structure changes significantly

Think of it like compiled code: you can patch the binary, but eventually you need to recompile from source.

## Beyond Basic Diagrams: Advanced Use Cases

### Security Review Automation

Generate diagrams highlighting security boundaries:

```bash
# Focus on security-relevant resources
cfn-dia draw.io -t template.yaml -o docs/security-review.drawio \
  --include-types AWS::IAM::* \
                  AWS::Cognito::* \
                  AWS::ApiGateway::* \
                  AWS::EC2::SecurityGroup \
                  AWS::EC2::VPC \
                  AWS::KMS::*
```

This creates a diagram showing:
- IAM roles and policies
- Cognito authentication flows
- API Gateway authorization
- VPC security groups
- KMS encryption keys

Perfect for security reviews or compliance audits. Include it in your security documentation and regenerate whenever infrastructure changes.

### Compliance Documentation

Auditors love diagrams. Generate them automatically for SOC2, ISO 27001, or HIPAA compliance:

**Create a compliance-focused workflow:**
```yaml
name: Generate Compliance Diagrams

on:
  release:
    types: [published]

jobs:
  compliance-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install cfn-diagram
        run: npm install -g @mhlabs/cfn-diagram @mhlabs/cfn-diagram-ci
        
      - name: Generate data flow diagram
        run: cfn-dia-ci html -t template.yaml
        
      - name: Archive for audit
        run: |
          mkdir -p compliance-artifacts
          cp docs/*.png compliance-artifacts/
          echo "Generated: $(date)" > compliance-artifacts/metadata.txt
          echo "Template SHA: $(sha256sum template.yaml)" >> compliance-artifacts/metadata.txt
          
      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: compliance-diagrams-${{ github.ref_name }}
          path: compliance-artifacts/
```

This generates timestamped, version-controlled architecture diagrams for every release. When auditors ask "show me your architecture as of Q3 2025," you have artifacts ready.

### Onboarding Artifacts

Include generated diagrams in onboarding documentation:

```markdown
# Onboarding: Order Processing Service

## Architecture Overview

Our service uses AWS serverless technologies:

[View Interactive Diagram](https://yourteam.github.io/orders-service/architecture/)

## Key Components

The diagram shows:
- **API Gateway**: REST API for order creation and retrieval
- **Lambda Functions**: Business logic (create, get, process, stream)
- **DynamoDB**: Order persistence with streams enabled
- **SQS**: Async processing queue with DLQ
- **SNS**: Order notification delivery
- **Cognito**: User authentication and authorization

For detailed component documentation, see...
```

New hires get an accurate, current architecture diagram on day one. No "oh, that's outdated, let me explain the real architecture" conversations.

## Limitations and Trade-offs

### What cfn-diagram Does Well

- **Standard AWS resources** - Excellent support for common services
- **Resource relationships** - Correctly identifies connections via `!Ref`, `!GetAtt`, event sources
- **Multiple outputs** - Draw.io, Mermaid, HTML, ASCII all work great
- **CloudFormation, SAM, CDK** - Broad compatibility

### Current Limitations

**Some AWS icons may be missing:** Newer services might lack official AWS icons. The tool uses text labels instead, which is functional but less polished.

**Very large stacks can be cluttered:** A 200-resource stack produces an overwhelming diagram. Solution: use filtering and generate multiple focused views.

**Complex nested stacks require filtering:** Deeply nested CloudFormation stacks can produce recursive diagrams. Solution: target specific stacks with `--stacks` flag.

**Layout algorithms are automatic:** You can't specify exact positioning (except by editing draw.io output manually). Solution: let the tool generate, then refine in draw.io.

### When Manual Diagrams Still Make Sense

Automated diagrams excel at **technical accuracy** but sometimes you need **conceptual clarity**:

**High-level system architecture:** When showing how multiple services interact across AWS accounts, or how your system connects to third-party APIs, manual diagrams work better.

**Business process flows:** Diagrams showing business logic, user journeys, or data lifecycle need human judgment about what to include and emphasize.

**Presentation-quality visuals:** Conference talks and executive presentations often need custom layouts, specific color schemes, and carefully crafted visual hierarchy.

**Cross-system architectures:** When diagramming multiple microservices, external integrations, and hybrid cloud setups, manual diagrams provide necessary abstraction.

### The Hybrid Approach

The best strategy: **generate for accuracy, edit for communication**.

1. **Generate baseline:** Run cfn-diagram to get accurate resource relationships
2. **Edit in draw.io:** Open the generated `.drawio` file and refine:
   - Adjust layout for visual appeal
   - Add swim lanes or grouping boxes
   - Include annotations and notes
   - Customize colors and styles
3. **Save customized version:** Commit the edited diagram
4. **Regenerate periodically:** When infrastructure changes significantly, regenerate and reapply customizations

Think of it like code formatting: the tool gets you 90% there, you refine the last 10% for readability.

## Getting Started Checklist

Ready to implement automated diagram generation? Here's your action plan:

### Prerequisites

- **Node.js and npm** - Already installed if you're doing any JavaScript/TypeScript development
- **CloudFormation or SAM template** - Your existing infrastructure code
- **GitHub repository** - For automated workflows (or GitLab/Bitbucket with similar CI/CD)

### Quick Start (15 minutes)

**1. Install cfn-diagram**
```bash
npm install -g @mhlabs/cfn-diagram
```

**2. Generate your first diagram**
```bash
cd your-project/
cfn-dia draw.io -t template.yaml -o architecture.drawio
```

**3. View it**
- Install [Draw.io Integration](https://marketplace.visualstudio.com/items?itemName=hediet.vscode-drawio) for VS Code
- Open `architecture.drawio` in VS Code
- See your infrastructure visualized

**4. Try different formats**
```bash
cfn-dia mermaid -t template.yaml -o architecture.md
cfn-dia html -t template.yaml -o docs/
cfn-dia ascii-art -t template.yaml
```

**5. Set up GitHub Actions**
- Copy the workflow from earlier in this post
- Commit and push
- Watch diagrams update automatically

### Team Adoption Strategy

Don't try to automate everything overnight. Roll out gradually:

**Week 1: Proof of concept**
- Pick one project/stack
- Generate diagrams manually
- Demo to team in standup or architecture meeting
- Gather feedback

**Week 2: Document the process**
- Add README section: "Updating Architecture Diagrams"
- Include commands developers need
- Explain when to regenerate

**Week 3: Automate in CI/CD**
- Add GitHub Actions workflow
- Test with a few PRs
- Iterate on what formats/filters work best

**Week 4: Expand**
- Add to other projects
- Make it part of your definition of done
- Update architecture review template to require diagrams

**Month 2+: Refine**
- Create filtered views for different audiences
- Integrate with documentation sites
- Add compliance/audit artifact generation

## Conclusion

Architecture diagrams are essential, but maintaining them manually is unsustainable. Every time your infrastructure changes, your diagrams drift further from reality. Eventually, they become historical artifacts—interesting but misleading.

**The solution:** Stop maintaining diagrams. Generate them.

Your CloudFormation or SAM template is the source of truth. It completely describes your infrastructure. Diagrams should be derived from that source, not maintained separately. With cfn-diagram, you can:

- Generate accurate diagrams in seconds, not hours
- Produce multiple formats for different audiences
- Automate updates with every infrastructure change
- Never have outdated diagrams again

**The workflow is simple:**
1. Write your infrastructure as code (you're already doing this)
2. Run cfn-diagram to generate diagrams
3. Commit them to your repo
4. Automate with GitHub Actions
5. Diagrams update automatically forever

**Start today:**
- Install cfn-diagram: `npm install -g @mhlabs/cfn-diagram`
- Generate your first diagram: `cfn-dia draw.io -t template.yaml`
- Add GitHub Actions workflow from this post
- Stop maintaining diagrams manually

Your future self—and your team—will thank you. No more "wait, is this diagram current?" conversations. No more scrambling to create diagrams for architecture reviews. No more onboarding new team members with outdated documentation.

Infrastructure as Code enables Infrastructure as Diagrams. Your CloudFormation templates are the truth. Let the tooling handle the visualization.

---

**Resources:**
- [cfn-diagram GitHub](https://github.com/ljacobsson/cfn-diagram)
- [Draw.io VS Code Extension](https://marketplace.visualstudio.com/items?itemName=hediet.vscode-drawio)
- [Mermaid Documentation](https://mermaid.js.org/)
- [Example workflow in this post's repo](https://github.com/scottobert/blog-examples/cfn-diagrams)

What's your experience with architecture documentation? Have you tried automated diagram generation? Share your stories in the comments below.
