---
title: "git reset to a given commit"
date: 2022-04-21T09:50:32-07:00
draft: false
tags:
- Development
- Debugging
- Developer Tips
---

When you want to reset to a given commit in git history, but don't want to lose the commits that came later.

```shell
# Reset the index and working tree to the desired tree
# Ensure you have no uncommitted changes that you want to keep
git reset --hard 56e05fced
# Move the branch pointer back to the previous HEAD
git reset --soft "HEAD@{1}"
git commit -m "Revert to 56e05fced"
```