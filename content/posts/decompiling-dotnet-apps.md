---
title: "Decompiling dotnet apps"
date: 2022-04-12T15:09:00-07:00
draft: false
categories: ["Development Tools", "Debugging and Troubleshooting"]
tags:
- Development
- Debugging
- Developer Tips
---

Sometimes as developers we run into a legacy application that has been running in production for years when suddenly a bug surfaces. If nobody knows where the source code for that legacy application is, that can be a huge problem.

## Introduction to .NET Decompilation

Decompilation is the process of converting compiled .NET assemblies (DLLs or EXEs) back into readable source code. This can be incredibly useful when:

- Dealing with legacy applications without source code
- Debugging production issues where deployed code differs from source control
- Understanding third-party libraries when documentation is insufficient
- Investigating potential security issues or malware

## Using dotPeek

[dotPeek](https://www.jetbrains.com/decompiler/) by JetBrains is a powerful free .NET decompiler that can help solve these problems. I recently had an occasion to use it, and even without the .pdb file, it was able to decompile the code to be very close to the source code we had in source control that we knew wasn't what was running in production.

### Key Features

- Free and lightweight
- Supports .NET Framework and .NET Core assemblies
- Decompiles to C# or IL
- Can export decompiled code to Visual Studio projects
- Integrates with Visual Studio
- Symbol server support

### Getting Started

1. Download and install dotPeek from JetBrains website
2. Open your assembly (DLL or EXE)
3. Navigate through the decompiled code using the Assembly Explorer
4. Export code or copy specific sections as needed

## Alternative Tools

While dotPeek is excellent, there are other tools worth considering:

1. **ILSpy**
   - Open source
   - Available as Visual Studio extension
   - Supports latest .NET versions
   - Can decompile to C# or Visual Basic

2. **dnSpy**
   - Includes debugger
   - Allows editing of decompiled code
   - Great for runtime analysis
   - Note: Development discontinued, but still useful

3. **Telerik JustDecompile**
   - Free tool
   - Good integration with Visual Studio
   - Plugin system for extensibility

## Best Practices

When working with decompiled code:

1. **Legal Considerations**
   - Ensure you have the right to decompile the code
   - Check license agreements
   - Document why decompilation was necessary

2. **Code Management**
   - Create a new repository for decompiled code
   - Document the origin of the assembly
   - Note any modifications made
   - Include the original assembly's version

3. **Debugging Tips**
   - Compare decompiled code with any available source
   - Use symbol servers when possible
   - Document any discrepancies found
   - Consider setting up a proper source control system for future deployments

## Real-World Example

Here's a practical example of using dotPeek:

```csharp
// Original compiled assembly: LegacyApp.dll
// No source code available, bug reported in production
// Using dotPeek to investigate

// Decompiled code revealed:
public class DataProcessor
{
    public void ProcessData(string input)
    {
        if (string.IsNullOrEmpty(input))
            return;  // Found the bug: silent failure instead of error

        // Rest of the processing logic
    }
}
```

In this case, decompilation revealed a silent failure that should have thrown an exception, helping us identify the root cause of production issues.

## Prevention Strategies

To avoid similar situations in the future:

1. **Source Control**
   - Maintain comprehensive source control
   - Tag/branch all production releases
   - Include build artifacts metadata

2. **Documentation**
   - Document build and deployment processes
   - Maintain a catalog of applications and their sources
   - Keep records of deployment locations

3. **Build Process**
   - Generate and store PDB files
   - Consider using Source Link
   - Implement deterministic builds

## Conclusion

While tools like dotPeek are invaluable for recovering lost source code, the best approach is to prevent the need for decompilation through proper source control and documentation practices. However, when you do need to decompile code, understanding these tools and following best practices can make the process much more manageable.