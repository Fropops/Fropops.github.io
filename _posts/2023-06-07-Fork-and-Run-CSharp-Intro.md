---
title: Fork and Run Implementation in C# - Intro
author: Fropops
date: 2023-06-07 19:25:00 +0800
categories: [Developpement]
tags: [C#, C2, Red Team, Fork and Run, Injection, WinAPI]
---

Enabling the execution of external programs is a key aspect of a C2 framework. One of the most widely used techniques in the world of C2 is know as "Fork and Run" mecanism. How does it work?

A new host process is created, serving as a shell into which we inject the program we actually want to execute. Contrary to what the name suggests, we do not "fork" the current process; instead, we select an existing executable that ideally raises minimal suspicion.

This process is created in a suspended state, preventing it from terminating prematurely. If the C2 framework needs to capture the output stream, an inter-process communication system must be established during its creation.

Next, we inject the desired program (shellcode) into this "zombie" process and initiate its execution. 

While this practice is increasingly monitored by antivirus and other detection systems, it remains effective in certain situations and presents a valuable learning opportunity.

Let's delve into this in detail in this series of posts, which will be divided into four parts:

1. [Fork and Run Implementation in C# - Process Creation](/posts/Fork-and-Run-CSharp-Process-Creation/)
2. [Fork and Run Implementation in C# - User impersonation & Token Manipulation](/posts/Fork-and-Run-CSharp-User-impersonation-Token-Manipulation)
3. Fork and Run Implementation in C# - Shellcode Injection
4. Fork and Run Implementation in C# - Going further

Throughout this series, we will provide detailed explanations, code examples, and practical insights to help you understand the implementation of Fork and Run in C#.