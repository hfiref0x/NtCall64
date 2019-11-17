
# NTCALL64
## Windows NT x64 syscall fuzzer.

This program based on NtCall by Peter Kosyh. It isn't advanced version and its purpose - port NtCall functionality for x64 Windows NT 6+.

# System Requirements

+ x64 Windows 7/8/8.1/10;
+ Account with administrative privileges (optional).

# Usage
NTCALL64 -help[-win32k][-log][-call Id][-pc Value]

* -help      - show program parameters help;
* -log       - enable logging via COM1 port, service parameters will be logged (slow), default disabled;
* -win32k    - launch W32pServiceTable services fuzzing (sometimes referenced as Shadow SSDT);
* -call Id   - fuzz syscall by supplied id (id can be from any table ntos/win32k);
* -pc Value  - set pass count for each syscall (maximum value is limited to ULONG64 max value), default value 65536.

When used without parameters NtCall64 will start fuzzing services in KiServiceTable (ntos, sometimes referenced as SSDT).

Default timeout of each fuzzing thread is set to 30 sec. If logging enabled then timeout extended to 120 sec.

Note that when used with -call option all blacklists will be ignored and fuzzing thread timeout will be set to INFINITE.

Example: 
+ ntcall64 -log
+ ntcall64 -log -pc 1234
+ ntcall64 -log -pc 1234 -call 4096
+ ntcall64 -win32k
+ ntcall64 -win32k -log
+ ntcall64 -win32k -log -pc 1234
+ ntcall64 -call 4097
+ ntcall64 -call 4097 -log
+ ntcall64 -call 4097 -log -pc 1000
+ ntcall64 -pc 1000

Note: make sure to configure Windows crash dump settings before trying this tool 

(e.g. https://msdn.microsoft.com/en-us/library/windows/hardware/ff542953(v=vs.85).aspx).

# How it work

It brute-force through system services and call them multiple times with input parameters randomly taken from predefined "bad arguments" list.


# Configuration

By using badcalls.ini configuration file you can blacklist certain services. To do this - add service name (case sensitive) to the corresponding section of the badcalls.ini, e.g. if you want to blacklist services from KiServiceTable then use [ntos] section.

Example of badcalls.ini (default config shipped with program)

<pre>[ntos]
NtClose
NtRaiseHardError
NtReleaseKeyedEvent
NtPropagationComplete
NtShutdownSystem
NtSuspendProcess
NtSuspendThread
NtTerminateProcess
NtTerminateThread
NtWaitForAlertByThreadId
NtWaitForSingleObject
NtWaitForKeyedEvent

[win32k]
NtUserRealWaitMessageEx
NtUserShowSystemCursor
NtUserSwitchDesktop
NtUserLockWorkStation
NtUserEnumDisplayMonitors
NtUserGetMessage
NtUserWaitMessage
NtUserDoSoundConnect
NtUserRealInternalGetMessage
NtUserBroadcastThemeChangeEvent
NtUserWaitAvailableMessageEx
NtUserMsgWaitForMultipleObjectsEx</pre>

# Warning

This program may crash the operation system, affect it stability, which may result in data lost or program crash itself. You use it at your own risk.

# Bugs found with NtCall64

* [win32k!NtGdiDdDDISetHwProtectionTeardownRecovery](https://gist.githubusercontent.com/hfiref0x/6901a8e571946e84d8adb1c6f720fdad/raw/63c27cc71828969f7802ad5f7677f2bafe6d84fb/gistfile1.txt)
* [win32k!NtUserCreateActivationObject](https://gist.githubusercontent.com/hfiref0x/23a2331588e7765664f50cac26cf0637/raw/49457ef5e30049b6b4ca392e489aaceaafe2b280/NtUserCreateActivationObject.cpp)
* [win32k!NtUserOpenDesktop](https://gist.githubusercontent.com/hfiref0x/6e726b352da7642fc5b84bf6ebce0007/raw/8df05220f194da4980f401e15a0efdb7694deb26/NtUserOpenDesktop.c)
* [nt!NtLoadEnclaveData](https://gist.githubusercontent.com/hfiref0x/1ac328a8e73d053012e02955d38e36a8/raw/b26174f8b7b68506d62308ce4327dfc573b8aa26/main.c)


# Build

NTCALL64 comes with full source code written in C with tiny assembler usage.
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1 (Note that Windows 8.1 SDK must be installed);
  * If v141 then select 10.0.17763.0 (Note that Windows 10.0.17763 SDK must be installed). 

# Authors

(c) 2016 - 2019 NTCALL64 Project

Original NtCall by Peter Kosyh aka Gloomy (c) 2001, http://gl00my.chat.ru/ 
