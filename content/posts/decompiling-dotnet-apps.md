---
title: "Decompiling dotnet apps"
date: 2022-04-12T15:09:00-07:00
draft: false
tags:
- Development
- Debugging
- Developer Tips
---

Sometimes as developers we run into a legacy application that has been running in production for years when suddenly a bug surfaces. If nobody knows where the source code for that legacy application is, that can be a huge problem.

dotPeek can solve this problem! I recently had an occasion to use it, and even without the .pdb file, it was able to decompile the code to be very close to the source code we had in source control that we knew wasn't what was running in production.