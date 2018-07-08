
# NTCALL64
## Windows NT x64 syscall fuzzer.

This program based on NtCall by Peter Kosyh. It isn't advanced version and its purpose - port NtCall functionality for x64 Windows NT 6+.

#### System Requirements

+ x64 Windows 7/8/8.1/10(TH1/TH2/RS1/RS2/RS3/RS4/RS5);
+ Account with administrative privileges (optional).

#### Usage
NTCALL64 -help
NTCALL64 [-log]
NTCALL64 -win32k [-log]
NTCALL64 -call id [-log]
* -help   - show program parameters help;
* -log    - enable logging to file last call parameters;
* -win32k - launch W32pServiceTable services fuzzing (sometimes referenced as Shadow SSDT);
* -call   - fuzz syscall by supplied id (id can be from any table ntos/win32k).

When used without parameters NtCall64 will start fuzzing services in KiServiceTable (sometimes referenced as SSDT).

Example: 
+ ntcall64.exe -log
+ ntcall64.exe -win32k
+ ntcall64.exe -win32k -log
+ ntcall64 -call 4097
+ ntcall64 -call 15 -log

Note: make sure to configure Windows crash dump settings before trying this tool 

(e.g. https://msdn.microsoft.com/en-us/library/windows/hardware/ff542953(v=vs.85).aspx).

#### How it work

It brute-force through system services and call them multiple times with input parameters randomly taken from predefined "bad arguments" list.


#### Configuration

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
NtUserBroadcastThemeChangeEvent</pre>

#### Warning

This program may crash the operation system, affect it stability, which may result in data lost or program crash itself. You use it at your own risk.

#### Build

NTCALL64 comes with full source code written in C with tiny assembler usage.
In order to build from source you need Microsoft Visual Studio 2015 and later versions.

#### Authors

(c) 2016 - 2018 NTCALL64 Project

Original NtCall by Peter Kosyh aka Gloomy (c) 2001, http://gl00my.chat.ru/ 
