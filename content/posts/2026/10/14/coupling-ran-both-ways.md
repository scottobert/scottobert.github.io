---
title: "The coupling ran both ways"
date: 2026-10-14T09:00:00-07:00
draft: false
categories:
  - Architecture and Design
  - Cloud Computing
  - Security
tags:
  - Legacy Modernization
  - Integration
  - File Transfer
  - Dependencies
  - PGP
  - Risk
  - Mainframe
---

I asked which system reads the file the vendor sends back. Four people gave me three answers, and the answer that mattered was one nobody gave.

This was the last step before retiring a send and receive path we had been running for years. We produce a request file, it goes to a vendor, a response file comes back, and the response gets loaded. Everybody on the call could describe that in one sentence, which is why it took me two days to notice that nobody could describe it hop by hop.

So I wrote down the hops. There were ten. An internal scheduler, a mainframe job, a task in the managed file transfer tool, an encryption step, a queue on the way out, the vendor's endpoint, and then most of that in reverse for the return file. Three of those ten hops are not represented in any repository we own. You cannot discover them by reading code, by querying CloudTrail, or by generating a dependency graph from templates, because they are configuration in a transfer product and rows in someone else's firewall.

Getting the list took an afternoon of interviews. The value was not in the list.

## The leg nobody traced

Everyone traces an integration in the direction the data moves. You start at the source, follow the payload, and stop when it reaches its destination. The return file gets documented as "the response," and a response reads like a leaf. A leaf has no dependents, so a leaf is safe to delete.

Tracing the return direction with the same discipline as the outbound one turned up a likely mainframe read of the return file, which contradicted the assumption everyone had been working from, including me, that the coupling only ran one way. I want to be careful here: it is not proven. What I had at the end was a path that exists, a job that has the access to use it, and no one who could tell me it does not. Our cutover plan contained a step that removed that directory.

Not being able to rule it out was the finding. I had been treating "we found no dependency" and "we confirmed there is no dependency" as the same result, and on a ten hop path with three hops outside our account, they are very much not. The first one is a statement about how hard I looked.

## Two things that were not on anyone's list

The same inventory turned up a PGP key with about six months left on it. Nothing tracked it. Not a calendar entry, not a ticket, not a renewal process, not a dashboard. It sits in our transfer configuration and in the vendor's, and both sides would have learned about the expiry the same way, which is a quarterly run that quietly did not transfer anything. Nobody would have connected the silence to a key for a while.

The second one is still open. I do not know whether the vendor allowlists our source addresses. If they do, then any change to our egress path presents a different address to their firewall and the transfer fails on their side, where we have no logs and no alarm. That dependency is not discoverable from inside our account by any tool, at any price, because it is a line in a configuration file we will never see. The only way to resolve it is to ask, and the question has to occur to you first.

One inventory, five follow up tickets, and the two most expensive findings were not about the thing I set out to map.

## What I take from it

The hops that break your migration are the ones that are not in your code. That sounds like a truism until you notice how much of our dependency tooling is built on the opposite assumption. Trace analysis, IaC graphs, log-derived service maps: all of them are excellent, and all of them describe the inside of your account boundary, which is exactly the region where you already knew the answer. The scheduler on the other side of the wall, the credential with an expiry date, and the vendor's allowlist are all outside, all capable of failing the whole integration, and all invisible to the tools.

The inventory format I use now is a table with one row per hop and four columns: what triggers it, what it reads, what it writes, and who owns it. The owner column does most of the work. A hop with no named owner is a hop nobody will call you about when it breaks, and on this path two hops had no owner until I went looking for one.

The other change is the question I ask about every artifact. Not "what consumes this next," which gets you the happy path, but "who else reads this." Those produce different answers, and the difference is where the unplanned coupling lives.

## Where this does not apply

This is expensive. It cost an afternoon of other people's time plus two days of mine for one integration, and the document started going stale the day I finished it. It is only worth doing for an integration you are about to change structurally. If you are adding a field to an existing file, do not do this. You will produce a beautiful map of something you were not going to break.

The second limit is the hit rate, and it is worth being honest about. Of ten hops, eight were exactly what everyone said they were. The work paid for itself on two, and I had no way to know in advance which two. That is the argument for tracing all of them, and it is also the reason this feels like a bad use of a week right up until the moment it isn't.
