---
title: Fork and Run Implementation in C# - Process Creation
author: Fropops
date: 2023-06-10 08:21:00 +0800
categories: [Developpement]
tags: [C#, C2, Red Team, Fork and Run, Injection, WinAPI]
---

## Introduction

The first step of this technique is to master the creation of a new process.

While the .NET framework provides a set of classes to manage this task, certain limitations push us to prefer direct usage of the Windows API:

Firstly, the .NET encapsulation does not allow us to start a process in a suspended state (although we will not use this capability in this post, we will need it later on).
Secondly, native C# methods do not enable us to create a process by injecting tokens (we will explore this concept in the next post regarding token manipulation).
Lastly, for code consistency and because we will heavily rely on the Windows API in subsequent steps, it seems relevant to handle this part directly using it.
This process creation also plays a role in another C2 functionality: command execution. Therefore, we will study this feature and then expand its functionality to implement the "Fork and Run" technique.

## Creating the process
The use of the Windows API in C# is beyond the scope of this blog post series. There are numerous resources available on the internet that cover this topic, so I will assume that the reader has already familiarized themselves with it.

To create our process, we will use the CreateProcessW method from the Windows API (contained in the kernel32.dll). To use this method, we need to declare it using the following code:

```c#
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CreateProcessW(
   string lpApplicationName,
   string lpCommandLine,
   ref SECURITY_ATTRIBUTES lpProcessAttributes,
   ref SECURITY_ATTRIBUTES lpThreadAttributes,
   bool bInheritHandles,
   PROCESS_CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
   [In] ref STARTUPINFOEX lpStartupInfo,
   out PROCESS_INFORMATION lpProcessInformation);
```

We also need to declare the various structures used by this method: SECURITY_ATTRIBUTES, STARTUPINFOEX, STARTUPINFO, PROCESS_CREATION_FLAGS, and PROCESS_INFORMATION:

```c#
public struct SECURITY_ATTRIBUTES
{
	public int nLength;
	public IntPtr lpSecurityDescriptor;
	public bool bInheritHandle;
}


[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFO
{
	public uint cb;
	public IntPtr lpReserved;
	public IntPtr lpDesktop;
	public IntPtr lpTitle;
	public int dwX;
	public int dwY;
	public int dwXSize;
	public int dwYSize;
	public int dwXCountChars;
	public int dwYCountChars;
	public int dwFillAttribute;
	public uint dwFlags;
	public short wShowWindow;
	public short cbReserved2;
	public IntPtr lpReserved2;
	public IntPtr hStdInput;
	public IntPtr hStdOutput;
	public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFOEX
{
	public STARTUPINFO StartupInfo;
	public IntPtr lpAttributeList;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
	public IntPtr hProcess;
	public IntPtr hThread;
	public int dwProcessId;
	public int dwThreadId;
}

[Flags]
public enum PROCESS_CREATION_FLAGS : uint
{
	CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
	CREATE_DEFAULT_ERROR_MODE = 0x04000000,
	CREATE_NEW_CONSOLE = 0x00000010,
	CREATE_NEW_PROCESS_GROUP = 0x00000200,
	CREATE_NO_WINDOW = 0x08000000,
	CREATE_PROTECTED_PROCESS = 0x00040000,
	CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
	CREATE_SECURE_PROCESS = 0x00400000,
	CREATE_SEPARATE_WOW_VDM = 0x00000800,
	CREATE_SHARED_WOW_VDM = 0x00001000,
	CREATE_SUSPENDED = 0x00000004,
	CREATE_UNICODE_ENVIRONMENT = 0x00000400,
	DEBUG_ONLY_THIS_PROCESS = 0x00000002,
	DEBUG_PROCESS = 0x00000001,
	DETACHED_PROCESS = 0x00000008,
	EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
	INHERIT_PARENT_AFFINITY = 0x00010000
}
```

We will also need the CloseHandle method from the Windows API to properly close the opened handles with system objects:

```c#
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
```

Then, we simply call the method by passing the desired parameters:

```c#
 //prepare cmd parameters
string cmd = @"c:\windows\system32\cmd.exe /c whoami";

var startupInfoEx = new STARTUPINFOEX();
startupInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startupInfoEx);
var pInfo = new PROCESS_INFORMATION();
PROCESS_CREATION_FLAGS creationFlags = 0;
creationFlags |= PROCESS_CREATION_FLAGS.CREATE_NO_WINDOW;
creationFlags |= PROCESS_CREATION_FLAGS.EXTENDED_STARTUPINFO_PRESENT;
var pSec = new SECURITY_ATTRIBUTES();
var tSec = new SECURITY_ATTRIBUTES();
pSec.nLength = Marshal.SizeOf(pSec);
tSec.nLength = Marshal.SizeOf(tSec);

try
{
	//Create the process
	if (!CreateProcessW(null, cmd, ref pSec, ref tSec, false, creationFlags, IntPtr.Zero, null, ref startupInfoEx, out pInfo))
		throw new InvalidOperationException($"Error in CreateProcessW : {Marshal.GetLastWin32Error()}");

	Console.WriteLine("Process started!");
}
catch (Exception ex)
{
	Console.WriteLine("[X] Oooops something went wrong....");
	Console.WriteLine(ex.ToString());
}
finally
{
	//Cleaning
	CloseHandle(pInfo.hProcess);
	CloseHandle(pInfo.hThread);
}
```
Here is the result when the code is executed :

![Simple Process Creation Execution](/assets/img/posts/ForkAndRun/exec-simple-creation.png)

Well, it seems to be working, but off course, as it's a new process we didn't get any output, let's resolve this.


## Capturing Output stream

The Windows API comes to our rescue as we can create the process by redirecting the output (and input, although it's not relevant in this case) to a pipe.

To achieve this, we add a few API declarations, including two functions:
```c#
[DllImport("kernel32.dll")]
public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask, HANDLE_FLAGS dwFlags);
```

We also need the associated structures:
```c#
const uint USE_STD_HANDLES = 0x00000100;

[Flags]
public enum HANDLE_FLAGS : uint
{
	None = 0,
	INHERIT = 1,
	PROTECT_FROM_CLOSE = 2
}
```

Now, we need to create the pipe that will be used and configure the program startup to redirect its output:
```c#
var outPipe_w = IntPtr.Zero;

SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
saAttr.bInheritHandle = true;
saAttr.lpSecurityDescriptor = IntPtr.Zero;
saAttr.nLength = Marshal.SizeOf(saAttr);
CreatePipe(out var outPipe_rd, out outPipe_w, ref saAttr, 0);

// Ensure the read handle to the pipe for STDOUT is not inherited.
SetHandleInformation(outPipe_rd, HANDLE_FLAGS.INHERIT, 0);

startupInfoEx.StartupInfo.hStdError = outPipe_w;
startupInfoEx.StartupInfo.hStdOutput = outPipe_w;


startupInfoEx.StartupInfo.dwFlags |= USE_STD_HANDLES;
```

We also need to change the call to the CreateProcessW method:
```c#
if (!CreateProcessW(null, cmd, ref pSec, ref tSec, true, creationFlags, IntPtr.Zero, null, ref startupInfoEx, out pInfo))
```

One last element is missing: reading the pipe to display the program's output until its execution is complete. Again, we need to utilize the Windows API, which includes a ReadFile function:
```c#
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);
```

To simplify its usage, I have encapsulated it in a method:
```c#
public static byte[] ReadFromPipe(IntPtr pipe, uint buffSize = 1024)
{
	byte[] chBuf = new byte[buffSize];
	bool bSuccess = ReadFile(pipe, chBuf, (uint)buffSize, out var nbBytesRead, IntPtr.Zero);
	if (!bSuccess)
	{
		int lastError = Marshal.GetLastWin32Error();
		if (lastError == 109) //Broken Pipe
			return null;
		throw new InvalidOperationException($"Failed reading pipe : {lastError}");
	}

	byte[] ret = new byte[nbBytesRead];
	Array.Copy(chBuf, ret, nbBytesRead);
	return ret;
}
```

Simply call this method until the process terminates:
```c#
var process = System.Diagnostics.Process.GetProcessById(pInfo.dwProcessId);

byte[] b = null;
while (!process.HasExited)
{
	Thread.Sleep(100);
	b = ReadFromPipe(outPipe_rd);
	if (b != null)
		Console.WriteLine(Encoding.UTF8.GetString(b));
}
```

Don't forget to clean up the newly created pipe handles in the "finally" statement:
```c#
CloseHandle(outPipe_rd);
CloseHandle(outPipe_w);
```	

When we put the pieces together we get the following result :

![Simple Process Creation With Output Execution](/assets/img/posts/ForkAndRun/exec-simple-creation-with-output.png)


This first article demonstrates how to create a new process in C# using the Windows API and leverage pipe redirection for capturing and displaying the process output.

You can find the complete source code on [Github](https://github.com/Fropops/OffensiveWinAPI/blob/main/TestForBlog/CreateProcessWithOutput.cs)
