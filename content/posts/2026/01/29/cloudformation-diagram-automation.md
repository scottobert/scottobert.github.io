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
{{< image src="/posts/2026/01/29/hero-cloudformation-automation.png" >}}

> This post shows how I stopped maintaining AWS architecture diagrams by hand and started generating them on every commit—from my actual CloudFormation templates, with no extra effort.

Imagine it's Monday, 2 PM. I'm explaining our serverless architecture to a new dev. I pull up the "current" architecture diagram from Confluence. We go through API Gateway, a handful of Lambda functions, DynamoDB, and SNS. Five minutes in, that developer checks the repo, scrolls through the CloudFormation, and asks, "Why are there seven Lambda functions here but only three on the diagram? Where's the SQS queue?"

That diagram is six months out of date. New functions were added, queues moved, several things renamed—and nobody updated the diagram. Open draw.io, move some shapes around, upload the result to Confluence? It takes half an hour, and honestly, next week it'll probably be wrong again.

**Real problem:** Manually-maintained diagrams don't survive long in active teams. Updates slip through the cracks. New hires get confused; design reviews stall; eventually, the diagram becomes an artifact for historians.

But reading giant CloudFormation templates? Not better. In small stacks, maybe. For anything with more than a dozen resources, YAML is just not documentation—you can't see how the pieces fit.

## Why documentation gets out of sync

Most teams do the same thing: draw nice diagrams in Lucidchart or draw.io, upload them to Confluence, and share in Slack or meetings. Three months pass: new Lambdas appear, SQS replaces SNS, DynamoDB Streams sneak in. The diagram stays as it was, because:
- Nobody remembers where the source file lives
- The person who built it left
- Feature work always comes first

Sooner or later, the diagram is only good for giggles. Nobody trusts it.

**What about "just read the CloudFormation"?** For trivial stacks, okay. For real-world ones with nested stacks or tricky permissions? You'd have to trace variables and cross-stack refs just to find out which Lambda talks to which SQS queue.

## What you're really missing
- Onboarding takes days—you answer the same architecture questions on repeat.
- Architecture reviews can't catch bottlenecks or weird data flow at a glance.
- Security reviews and audits drag on, because nobody can show a current diagram.
- Eventually, the architecture only exists inside a few people's heads. When they quit, knowledge walks out with them.

## My solution: Infra as Diagrams, built-in
Your infrastructure-as-code (IaC) **is** the architecture. The YAML template is the truth. So why invent a parallel artifact? Instead:

- Treat diagrams as build artifacts, not documentation you maintain by hand.
- Each commit runs a tool that turns CloudFormation or SAM into diagrams in all the relevant formats (draw.io, Mermaid, interactive HTML, even ASCII art for terminal peeks).
- Version-control the diagrams; keep them side-by-side with your templates. If a pull request changes infrastructure, the corresponding diagrams update too.

## The tool: cfn-diagram
I use [cfn-diagram](https://github.com/ljacobsson/cfn-diagram), a CLI that does all of the above in a single step. It reads templates and spits out diagrams—editable, embeddable, or just easy to link in a PR.

- Output formats: draw.io, Mermaid markdown, HTML (interactive), or ASCII art
- Works with CloudFormation and SAM out of the box
- Handles CDK projects directly too—point `-t` at `cdk.json` and it synthesizes for you (skip that step with `-s` if you've already synthesized)
- Filters out noisy resources like IAM roles if you want a "signal-only" view

## What automation looks like
Add a GitHub Actions workflow:
```
name: Update Architecture Diagrams
on:
  push:
    branches: [ main ]
    paths:
      - 'template.yaml'
      - 'src/**'
  pull_request:
    paths:
      - 'template.yaml'
      - 'src/**'
permissions:
  contents: write
jobs:
  generate-diagrams:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g @mhlabs/cfn-diagram@2
      - run: cfn-dia draw.io -t template.yaml -o docs/architecture.drawio -c
      - run: cfn-dia mermaid -t template.yaml -o docs/architecture.md -c
      - run: cfn-dia html -t template.yaml -o docs/ -c
      - name: Commit updated diagrams
        if: github.event_name == 'push'
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add docs/architecture.drawio docs/architecture.md docs/*.html
          git diff --staged --quiet || git commit -m "chore: update architecture diagrams [skip ci]"
          git push
```
The `-c` flag runs each command in CI mode (no interactive prompts). On pushes to `main`, the job commits regenerated diagrams straight back to the repo; on pull requests it just regenerates and validates them as a build artifact—true infra changes still need a merge to `main` before the committed diagrams update. Pin the `cfn-diagram` version too, so a tool update doesn't silently change your diagrams out from under you.

## Why this is worth it
It saves real time. No more out-of-sync diagrams. No more confusion during onboarding or reviews. The real architecture is always visible, in a glanceable format, right next to the actual code.

Don't let diagrams become lies or create review headaches. Do it like code: automate all the way.