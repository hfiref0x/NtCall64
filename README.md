[![Build status](https://ci.appveyor.com/api/projects/status/7aio324c7pkmqxfm?svg=true)](https://ci.appveyor.com/project/hfiref0x/ntcall64)
[![Visitors](https://api.visitorbadge.io/api/visitors?path=github.com%2Fhfiref0x%2Fntcall&countColor=%23263759&style=flat)](https://visitorbadge.io/status?path=github.com%2Fhfiref0x%2Fntcall)

# NTCALL64
## Windows NT x64 syscall fuzzer

NTCALL64 is a syscall fuzzer for 64-bit Windows NT 6+ (Windows 7 and later), based on the original [NtCall](http://gl00my.chat.ru/) by Peter Kosyh.  
Its purpose is to port and extend the functionality of NtCall for x64 Windows, enabling researchers to fuzz system call tables (`ntoskrnl` and optionally `win32k`) for vulnerabilities and stability issues.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [Usage](#usage)
- [Configuration](#configuration)
- [Build](#build)
- [Warnings](#warnings)
- [Bugs Found with NtCall64](#bugs-found-with-ntcall64)
- [Authors](#authors)

---

## System Requirements

- x64 version of Windows 10 or 11
- Administrative privileges recommended for full functionality

---

## Usage

```
ntcall64.exe -help [-win32k] [-log [-o <file_or_port>]] [-call Id] [-pc Value] [-wt Value] [-sc Value] [-s] [-h]
```

**Options:**

| Option          | Description                                                                                                  |
|-----------------|-------------------------------------------------------------------------------------------------------------|
| `-help`         | Show help information                                                                                        |
| `-win32k`       | Fuzz the win32k graphical subsystem service table (aka Shadow SSDT); default is ntoskrnl table              |
| `-log`          | Enable logging of call parameters (reduces performance)                                                      |
| `-o Value`      | Output log destination (COM port name like `COM1`, `COM2`, or file name, default: `ntcall64.log` if omitted)|
| `-call Id`      | Fuzz only the syscall with the supplied numeric ID (from any table); disables blacklists                     |
| `-pc Value`     | Set number of passes for each syscall (default: 65536)                                                      |
| `-wt Value`     | Set thread wait timeout in seconds (default: 30; if logging, timeout is 240)                                |
| `-sc Value`     | Start fuzzing from the specified syscall table index (default: 0)                                            |
| `-h`            | Enable heuristics when building syscall parameters                                                           |
| `-s`            | Attempt to run program from LocalSystem account                                                             |

**Examples:**
```
ntcall64.exe -win32k
ntcall64.exe -log -o COM2
ntcall64.exe -win32k -log -pc 1234
ntcall64.exe -call 4097 -log -pc 1000
ntcall64.exe -s
```

**Notes:**
- If run without parameters, fuzzes all ntoskrnl (`KiServiceTable`) services.
- When using `-call`, blacklists are ignored and the thread timeout is set to infinite.
- Logging can be sent to a serial port or a file. COM port logging is for hardware debugging.

---

## Configuration

You can blacklist specific services using the `badcalls.ini` configuration file.  
Add service names (case-sensitive) to the appropriate `[ntos]` or `[win32k]` section.

**Example `badcalls.ini` (snippet):**
```
[ntos]
NtClose
NtContinue
NtDelayExecution
NtInitiatePowerAction
NtMapUserPhysicalPagesScatter
NtPropagationComplete
NtRaiseException
NtRaiseHardError
NtReleaseKeyedEvent
NtReplacePartitionUnit
NtSetDefaultLocale
NtSetDefaultUILanguage
NtSetIoCompletion
NtSetSystemPowerState
NtShutdownSystem
NtSuspendProcess
NtSuspendThread
NtTerminateProcess
NtTerminateThread
NtWaitForAlertByThreadId
NtWaitForKeyedEvent
NtWaitForSingleObject

[win32k]
NtUserDoSoundConnect
NtUserEnumDisplayMonitors
NtUserGetMessage
NtUserLockWorkStation
NtUserMsgWaitForMultipleObjectsEx
NtUserPostMessage
NtUserRealInternalGetMessage
NtUserRealWaitMessageEx
NtUserShowSystemCursor
NtUserSwitchDesktop
NtUserWaitAvailableMessageEx
NtUserWaitMessage
```
The default config is included.

---

## Build

NTCALL64 is written in C with minimal assembler use.  
You need Microsoft Visual Studio 2017 or later.

**Instructions:**
- Open the solution in Visual Studio.
- Set the Platform Toolset:
  - v141 for VS 2017
  - v142 for VS 2019
  - v143 for VS 2022
- Set the Target Platform Version:
  - 8.1 for v140
  - 10 for v141 and above
- Minimum required Windows SDK version: 8.1

---

## Warnings

> **This tool is for research and development. It may crash your system, cause instability, or data loss.**
>
> Use only in a controlled environment.  
> **You are responsible for any damage caused by running NtCall64.**

**Tip:**  
Before using, set up crash dump settings (see [MSDN docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/enabling-a-kernel-mode-dump-file)) for easier debugging.

---

## Bugs Found with NtCall64

- [win32k!NtGdiDdDDISetHwProtectionTeardownRecovery](https://gist.githubusercontent.com/hfiref0x/6901a8e571946e84d8adb1c6f720fdad/raw/63c27cc71828969f7802ad5f7677f2bafe6d84fb/gistfile1.txt)
- [win32k!NtUserCreateActivationObject](https://gist.githubusercontent.com/hfiref0x/23a2331588e7765664f50cac26cf0637/raw/49457ef5e30049b6b4ca392e489aaceaafe2b280/NtUserCreateActivationObject.cpp)
- [win32k!NtUserOpenDesktop](https://gist.githubusercontent.com/hfiref0x/6e726b352da7642fc5b84bf6ebce0007/raw/8df05220f194da4980f401e15a0efdb7694deb26/NtUserOpenDesktop.c)
- [win32k!NtUserSetWindowsHookEx](https://gist.github.com/hfiref0x/8ecfbcc0a7afcc9917cef093ef3a18b2)
- [win32k!NtUserInitialize → win32kbase!Win32kBaseUserInitialize](https://gist.github.com/hfiref0x/f731e690e6155c6763b801ce0e497db7)
- [win32k!NtUserRegisterCoreMessagingEndPoint](https://gist.github.com/hfiref0x/0344e5e99e6eb43bda58c9525418cf30)
- [nt!NtLoadEnclaveData](https://gist.githubusercontent.com/hfiref0x/1ac328a8e73d053012e02955d38e36a8/raw/b26174f8b7b68506d62308ce4327dfc573b8aa26/main.c)
- [nt!NtCreateIoRing](https://gist.github.com/hfiref0x/bd6365a7cfa881da0e9c9e7a917a051b)
- [nt!NtQueryInformationCpuPartition](https://gist.github.com/hfiref0x/48bdc12241d0a981a6da473e979c8aff)

---

## Authors

(c) 2016 - 2025 NTCALL64 Project  
Original NtCall by Peter Kosyh aka Gloomy (c) 2001, [gl00my.chat.ru](http://gl00my.chat.ru/)

---