---
title: "git reset to a given commit"
date: 2022-04-21T09:50:32-07:00
draft: false
tags:
- Development
- Debugging
- Developer Tips
---

# Safely Resetting to a Previous Commit in Git

When working with Git, sometimes you need to reset your working tree to a specific commit while preserving the commit history. This guide explains how to do this safely and understand what's happening behind the scenes.

## The Problem

Typically, when developers want to revert to an older commit, they might reach for `git reset --hard`. However, this can be dangerous as it:
- Permanently removes all commits after the target commit
- Makes it difficult to recover those changes if needed
- Can cause issues with remote repositories

## The Solution

Here's a safer approach that preserves history while resetting your working tree:

```shell
# 1. First, note your current HEAD commit (in case you need it)
git rev-parse HEAD > /tmp/old-head

# 2. Reset the index and working tree to the desired tree
# Ensure you have no uncommitted changes that you want to keep
git reset --hard 56e05fced

# 3. Move the branch pointer back to the previous HEAD
git reset --soft "HEAD@{1}"

# 4. Create a new commit with the old tree state
git commit -m "Reset to commit 56e05fced while preserving history"
```

## Understanding the Process

Let's break down what each step does:

1. `git rev-parse HEAD`: Saves your current position (optional but recommended)
2. `git reset --hard`: Resets your working tree to the target commit
3. `git reset --soft`: Moves the HEAD back but keeps the working tree
4. `git commit`: Creates a new commit with the old tree state

## Different Reset Types

Git reset has three main modes:

1. **--soft**
   - Only moves the HEAD pointer
   - Keeps all changes in staging area
   - Useful for reorganizing commits

2. **--mixed** (default)
   - Moves HEAD and updates staging area
   - Keeps working directory unchanged
   - Good for combining multiple commits

3. **--hard**
   - Updates HEAD, staging area, and working directory
   - Most dangerous option
   - Use with caution

## Real-World Examples

### Scenario 1: Fixing a Bad Merge

```shell
# Bad merge happened
git reset --hard HEAD@{1}  # Go back to pre-merge state
git clean -fd             # Remove any new untracked files
git merge --strategy=recursive -X theirs feature-branch
```

### Scenario 2: Cherry-picking Specific Changes

```shell
# Instead of full reset, cherry-pick needed commits
git cherry-pick 56e05fced..HEAD
```

## Best Practices

1. **Always Check Your Current State**
   ```shell
   git status
   git log --oneline -n 5
   ```

2. **Create a Backup Branch**
   ```shell
   git branch backup-branch
   ```

3. **Use the Reflog**
   ```shell
   git reflog  # View history of HEAD changes
   ```

4. **Communicate with Team**
   - Inform teammates before major history changes
   - Coordinate force pushes if necessary
   - Document any significant resets

## Recovering from Mistakes

If something goes wrong, you can usually recover:

```shell
# View reflog to find lost commits
git reflog

# Restore to a previous state
git reset --hard HEAD@{n}  # where n is the reflog entry number

# Recover specific commits
git cherry-pick <commit-hash>
```

## Alternative Approaches

Sometimes a reset isn't the best solution. Consider these alternatives:

1. **git revert**: Creates new commits that undo changes
2. **git cherry-pick**: Selectively apply specific commits
3. **git rebase**: Restructure commit history
4. **git checkout -b**: Create a new branch at a specific point

## Conclusion

While `git reset` is a powerful command, it's important to use it carefully and understand its implications. The approach outlined here provides a safer way to reset your working tree while maintaining a clear history of changes.

Remember:
- Always verify your current state before resetting
- Create backups when attempting complex operations
- Use the reflog as your safety net
- Consider whether a reset is really the best solution

Need to undo a reset? Check the [Git documentation on undoing changes](https://git-scm.com/docs/git-reset#_examples) for more detailed scenarios.