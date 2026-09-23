---
title: "You can't alarm on a quarterly job"
date: 2026-10-07T09:00:00-07:00
draft: false
categories:
  - Cloud Computing
  - DevOps
  - Architecture and Design
tags:
  - AWS
  - CloudWatch
  - CloudFormation
  - Monitoring
  - Alarms
  - EventBridge
  - Batch Processing
---

CloudFormation rejected two of my alarms, and the rejection was correct. I had asked CloudWatch to do something it does not do, and the interesting part is that the thing I asked for is the only thing a quarterly batch job actually needs.

The context is a pipeline that runs four times a year. I was adding the alerting that the mainframe used to provide for free before we took over the schedule, and two of the alarms were the ones that mattered most: one for a run that never completed, and one for a vendor return file that never arrived. Both are absence alarms. Nothing is wrong with any metric value. The problem is that an expected thing did not happen, and the window in which it should have happened is months long.

So I published a custom metric on completion, set `TreatMissingData` to `breaching`, chose a period of one day, and set enough evaluation periods to cover a quarter. That is the shape every tutorial teaches for a missing data alarm, scaled up. The stack failed to deploy.

## The limit

CloudWatch caps the total evaluation window of an alarm. Period multiplied by evaluation periods cannot exceed seven days for alarms with a period of an hour or more, and cannot exceed one day for anything shorter. It is right there in the [`PutMetricAlarm` reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html), and it is not a soft limit or a quota you can raise. Seven days is the widest view an alarm gets.

A quarterly job has a ninety day gap between runs. There is no combination of period and evaluation periods that lets a native metric alarm notice that something failed to happen in February. The alarm will sit in `INSUFFICIENT_DATA` or drop back to `OK` long before the next run is due, and it will never have the breaching data points it needs, because "breaching" here means missing for ninety days and the alarm is only allowed to look back seven.

There is a smaller detail with the same edge on it. CloudWatch keeps alarm history for thirty days. Even if you could evaluate a quarter, the alarm's own record of what it did would not span one cycle of the job it watches. You cannot answer "did this alarm fire last quarter" from the alarm.

## Why the limit is not a bug

My first reaction was that this was an arbitrary product decision. It is not. A metric alarm is a windowed comparison of recent data against a threshold, and that is the whole abstraction. It answers "is this number out of range right now," and it answers it by holding a small buffer of recent data points and nothing else. It is deliberately close to stateless, which is why you can create ten thousand of them and never think about them again.

"Has this event happened since the last time it should have" is a different question. It requires knowing when the last time was, and that is durable state with a lifetime measured in months. CloudWatch alarms do not hold state on that timescale, and the seven day cap is the product telling you so, somewhat rudely.

Once I read the limit that way, the alarm I wanted stopped being a configuration problem and started being a design problem, which was a better place for it to be.

## Store the expectation, not the absence

The pattern that works is to stop asking CloudWatch to remember, and give it something continuous to watch instead.

When a run completes, write the next expected deadline to a table. A single scheduled function runs daily, reads every expectation, and publishes one metric: the number of expectations that are now past due. That metric is emitted every day, whether or not anything is overdue, so it is a continuous series with a value of zero most of the time. Alarm on it going above zero with a one day period and a window of a day or two. The rare event has been converted into a number that is reported constantly, and CloudWatch is now being asked the question it was built for.

{{< archify src="/diagrams/quarterly-alarm.html" title="Watching a quarterly job with a daily metric" caption="The rare event is written down as a deadline. The thing CloudWatch watches is a number that shows up every day." height="860" >}}

The return file alarm falls out of the same mechanism. When the outbound file goes to the vendor, write an expectation with a deadline a few days out. Clear it when the return file lands. The sweeper does not care what kind of thing it is waiting for, which means the second, third, and tenth low-frequency pipeline cost a row in a table rather than a new alarm design.

## What this costs

I moved the fragility rather than eliminating it. The sweeper is now the thing that must not fail silently, and if the sweeper stops running, every overdue deadline in the table goes unreported. That is a real regression in the abstract, and a small one in practice, because the sweeper runs daily. A daily job is squarely inside the regime CloudWatch was designed for, so an ordinary missing data alarm on its own completion metric works. Two levels, and the second level is a solved problem. It does not go deeper than that, which I checked, because it is the obvious objection.

The other cost is that the table is state, and state drifts from reality. If someone reruns a quarter by hand and does not clear the expectation, the sweeper reports an overdue job that ran fine. That direction of error is the one I want. A false alarm on a job that ran costs somebody ten minutes. Silence on a job that did not run costs a quarter of vendor data and gets discovered by an auditor.

I also considered a dead man switch built from a one time EventBridge schedule created at the start of each run and deleted on success, which is less machinery and reads more cleanly. I did not take it because our deadlines are calendar driven rather than relative to a start time, and because a resource that has to be deleted on success is a resource that eventually gets orphaned in a way nobody notices. If your deadlines are "four hours after it starts" rather than "the fifth business day after quarter close," that approach is probably better than mine.

## Where this does not apply

If your job runs hourly or more often, none of this is your problem. Set `TreatMissingData` to `breaching`, pick a window that covers a few intervals, and move on. The seven day cap will never come near you.

The other limit is harder. This does not help with jobs that run on an irregular human schedule, where nobody can say in advance when the next one is due. The whole approach rests on being able to compute a deadline at the end of the previous run. If you cannot name the deadline, you cannot alarm on missing it, and no amount of CloudWatch configuration will rescue that. What you have there is a process problem wearing a monitoring problem's clothes.
