---
title: "The mainframe was our monitoring system"
date: 2026-09-30T09:00:00-07:00
draft: false
categories:
  - Architecture and Design
  - Cloud Computing
  - DevOps
tags:
  - Legacy Modernization
  - Strangler Fig
  - Monitoring
  - CloudWatch
  - Step Functions
  - Batch Processing
  - Mainframe
---

We retired four mainframe batch pipelines in one month, and in all four the mainframe turned out to be the monitoring system. Nobody had designed it that way. Nobody had written it down. It was true anyway, and we removed it four times without noticing.

The four were unglamorous: a quarterly credit score refresh, a current carrier lookup, a declarations page merge for the print vendor, and an annual notice run. Different data, different vendors, same shape. In each one, the replacement platform did not produce the outbound file. It read a file the mainframe had already written, merged its own records into the middle of it, reused the mainframe's header and trailer records verbatim, and did not start at all until a trigger file from the mainframe landed in the transfer directory. Fetching that trigger file was the first step in the state machine.

That first step was doing two jobs. It was reading a file, and it was checking whether the mainframe had run.

## The alert nobody wrote

If the mainframe job did not run, the trigger file was not there, the fetch threw, the execution failed, and somebody got an email. That was not a missing run alert. It was an unhandled error on a download, and errors already had somewhere to go. But it was reliable, it fired on the right condition, and it pointed at the actual problem, which was that an upstream job had not run. For a quarterly pipeline, it is close to the only alert you need.

Once the replacement platform owns the schedule, that step goes away. An EventBridge rule fires the state machine on a cron expression. There is no trigger file, so there is nothing missing, so nothing throws. A quarter where the pipeline never ran produces no failed execution, no error metric, and no log entry, because nothing ran to fail. It looks exactly like a quarter where everything worked, which is to say it looks like nothing at all.

Two of these four stacks had no CloudWatch alarms of any kind. That had been fine for years. It was fine because the mainframe held the clock, and a clock that stops is loud.

{{< archify src="/diagrams/mainframe-monitoring.html" title="What the cutover removed" caption="Both shapes produce the same file. The top one also produces two signals, and neither is listed anywhere as a monitoring requirement." height="860" >}}

## The envelope was doing work too

The header and trailer records were the second thing we deleted without reading. The trailer carried a record count, and the vendor validated it on receipt. If our merge dropped records, the count disagreed with the file, the vendor rejected it, and we heard about it within a day. That is a completeness check we did not write, do not maintain, and cannot break, sitting at the far end of the pipe and running on somebody else's computer.

When you start writing your own trailer, you start computing that count yourself, from the same data you just wrote. A count derived from the thing it is counting cannot disagree with it. It can only ever agree, which means it can never catch anything. The check survives cutover in form and loses all of its value, and the diff looks clean.

## The count that was never the same count

So we wrote a real completeness check, and it was wrong on the first run that mattered.

In a lower environment, the dispatcher finished and wrote a done marker recording 182 events sent. The generator produced 78 policy files. The merge step compared those two numbers, found them different, and rejected the run. The run was correct. Only eligible orders produce a file, and 104 of those 182 policies were not eligible, which is the entire point of the eligibility check that runs in between.

The bug is obvious stated that way: events dispatched and files produced are not the same quantity, and they diverge the moment any filtering happens between them. What is interesting is that the bug could not appear until we took over the schedule. Before that, the number that mattered was the one in the mainframe's trailer, and the mainframe counted rows in a file it had already written. It never compared a request count to an output count, because it never knew how many requests there had been. We inherited the need for a definition of "complete" along with the schedule, and the first definition we reached for was the one that reads most naturally in a ticket and is false in production.

## What the migration plan was missing

The standard advice for a strangler fig migration is about behavior. Preserve the interface, move the implementation behind it, verify that the output matches. We did all of that, and the output did match.

The advice is silent about something else: a legacy system's outputs include signals that nobody ever recorded as outputs. The trigger file was an input to our code and an alarm to our operations team. Only the first of those appeared in any design document. The trailer count was a field in a record layout and a reconciliation control owned by a third party. Only the first of those appeared in the mapping spec. Both times, the thing we were migrating was described accurately and incompletely, and the missing part was the part that told a human something had gone wrong.

What I do now, before cutting a pipeline over, is write down every way the current arrangement produces a human-visible failure, and treat each one as a requirement rather than an observation. For these four, that list came to three items. A run that never happens has to produce an alert of its own. A record count has to be checked against something derived independently, not against the data it summarizes. A downstream rejection has to come back to us as something louder than mail to a shared box.

The first of those turned out to be much harder than it sounds for a job that runs four times a year, and CloudFormation rejected my first two attempts at it. That is its own post.

## Where this does not apply

This is a batch pattern, and specifically a low-frequency batch pattern. If you are moving a request and response service, the traffic is the alarm. Stop serving and somebody notices in minutes without any instrumentation at all, and none of this is worth your attention.

It also matters less when the legacy side is genuinely inert. If the old system only ever dropped a file into a directory and had no schedule of its own, there was no clock to inherit and nothing accidental to preserve.

And the honest limit: a disciplined enough design review catches this. Ours did not, four times in a row, and I have stopped believing that was carelessness. When you are reviewing a diagram of a system running, the question "what tells us this did not run" does not come up on its own. It has to be on a list, which is why I keep one now.
