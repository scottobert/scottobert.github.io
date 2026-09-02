---
title: "Delete the Shim"
date: 2026-09-01T09:00:00-07:00
categories:
  - "Software Development"
  - "Cloud Computing"
tags:
  - "AWS"
  - "Lambda"
  - "Node.js"
  - "Technical Debt"
  - "Serverless"
  - "Observability"
  - "Shared Libraries"
draft: false
---

> In 2023 I pulled a tracing vendor out of a shared library and left its wrapper functions in place as an extension point for whatever came next. Nothing ever came next. Here is what that cost three years later, and the one thing I would do differently.

In April 2023 I removed our tracing vendor from a shared library that nearly every service on our platform depends on. The product was being sunset, and the library exposed three wrapper functions whose only job was handing Lambda handlers to it. I did not delete them. I reduced each one to an identity function:

```ts
export const lambdaWrapperAsync = (method) => {
    return method;
};
```

Every call site kept compiling. Nothing had to change across the twenty-four repositories that import that library, at least a hundred files in total. And when we chose a replacement tracing tool, the seam would already be sitting there waiting.

We never chose a replacement. Three years later, a routine runtime upgrade took every endpoint in one of those services to 502, straight through a wrapper that looks, at every single call site, like the thing responsible for preventing exactly that.

I still think keeping the seam was defensible. What I got wrong was keeping it with no expiry date. An extension point for an integration you have not built yet is a bet, and nothing in a codebase tells you when a bet has gone bad. Comments do not rot loudly. Tests do not start failing. The function keeps returning its argument, correctly, forever.

## What actually broke

I raised `Globals.Function.Runtime` in a template from `nodejs20.x` to `nodejs24.x`. Ordinary maintenance, done ahead of a deprecation rather than behind it, which is the right way round. I set this trap in 2023 and I am also the one who stepped in it, which is the only reason I get to write about it without blaming a runtime upgrade for doing its job.

AWS Lambda decides whether a handler is callback-style or promise-style by looking at the exported function's declared argument count. Node.js 24 removed the callback path entirely. Every handler in this service was declared the old way:

```ts
export const handler: Handler = lambdaWrapperAsync(async (event, context, callback) => {
    // ...
    callback(null, response);
});
```

That fails inside Lambda's own bootstrap, before a line of application code runs, with `Runtime.CallbackHandlerDeprecated`. API Gateway never receives a valid response from the function, so what the caller sees is a 502 rather than anything that points at the cause. Total outage of the service, every endpoint, every invocation, identical.

The change that caused it had merged five days earlier and sat in the default branch, green, until a stack update carried it into a live environment.

## The part I did not expect

I went looking for why the wrapper had not absorbed this. Handing your handler to a function whose entire purpose is to sit between you and the runtime is the one place you would hope a signature change gets handled.

It never could have. Here is what the wrapper looked like before I gutted it, back when the vendor was still in place:

```ts
export const lambdaWrapperAsync = (method) => {
    if (!getConfig().tracing) { return method; }
    return vendor.lambdaWrapper((event, context, callback) => {
        method(event, context, callback)
            .then((result) => { callback(null, result); })
            .catch((err) => { callback(err); });
    });
};
```

The active path is itself callback-based. The abstraction that existed to insulate handlers from the runtime was bound to the runtime's callback contract in its own implementation. If the vendor were still in place today, this upgrade would have broken just the same, one layer deeper, inside a dependency, considerably harder to see.

So the seam I preserved was never load-bearing for this. It was load-bearing for the appearance of being handled, across a hundred files, for three years. That is worse than a hole. A hole you can see.

## Coverage was irrelevant, and that is not a coverage problem

The test suite passed. Seventeen suites, two hundred and ten tests, all green, plus a clean type-check build that packaged all four functions for the new runtime without a single error.

None of it could have caught this, and I want to be precise about why, because "add a test" is the reflex answer and it is wrong here. Jest calls `handler(event, context, callback)` as a plain function in a normal Node process. Lambda's runtime dispatch, the only thing in the entire system that inspects handler arity and rejects it, is not present in a unit test. The declared shape of an exported function is part of the contract with the platform, not part of the code the tests exercise. You cannot unit test your way to it.

The type system was actively unhelpful too. The explicit `: Handler` annotation on the export declares `callback` as a required third parameter, so once the implementation underneath took only two, TypeScript started rejecting the two-argument call at every call site. Fixing the outage meant removing a type annotation to stop the compiler from defending the broken shape.

## What I do differently

When I leave a seam for an integration that is not built, I write the deletion ticket the same day, with a date on it, and I put the date in the code:

```ts
// Placeholder for tracing integration. If nothing is wired in by 2026-10-01,
// delete this and its call sites. See TICKET-1234.
```

Two things about that, and the second matters more than the first. It survives me leaving the team, which a shared understanding does not. And it makes the bet visible to the person who finds it under a debugger at the worst moment, which is the only reader who genuinely needs to know that this function does nothing.

The stronger version, when the call sites can bear it, is to not leave the seam at all. A hundred-file deletion is a bad afternoon and a large, boring, mechanical diff. Three years of a hundred files lying about what they do is worse, and I know that now with a number attached rather than as a principle.

## Where the claim breaks down

If the seam is one call site, keep it and stop worrying. Everything above is a function of how many places carry the false signal, and one place is not a false signal, it is a note to yourself.

If the replacement integration is genuinely funded, staffed, and scheduled, keep it. My bet was not unreasonable, it was unowned. Nobody was accountable for the follow-through, which is a different problem than the one I am describing.

And if the wrapper does something, this whole argument is off the table. Live abstractions that also happen to be extension points are just abstractions. The specific trap is the one that returns its argument unchanged while a hundred call sites imply otherwise.

The version of me who made this call in 2023 had a real constraint and made a reasonable trade. I would make the same trade again. I would just put a date on it.
