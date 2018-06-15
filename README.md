# Injection techniques
I created this repo during my journey in learning more about the various process injection techniques. I did reuse other’s code, but tried to improve on them or modify them to my need and better reading. The source should be indicated in the code.
All of them were created with Visual Studio 2017.

## EarlyBird injection
This is a POC for the EarlyBird injection technique as named by Cyberbit. More details here:
[Hackers Found Using A New Code Injection Technique to Evade Detection](https://thehackernews.com/2018/04/early-bird-code-injection.html)

Use:
1. Put the shellcode of your choice to the source file (the included one will pop cmd.exe)
2. Recompile
3. Run: EarlyBird.exe [any x64 binary]

## CtrlInject injection
This is a POC for the CtrlInjection found by enSilo:
[Ctrl-Inject](https://blog.ensilo.com/ctrl-inject)

Use:
1. Put the shellcode of your choice to the source file (the included one will pop calc)
2. Recompile
3. Run: EarlyBird.exe [PID of x64 Console Application which has a non default HandlerList (e.g.: cmd.exe)]

## Inject DLL - DLL injection
This is a POC for the DLL injection described here (and many other places):
[Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
Usa
Run: injectdll.exe [process name] [dll path] [option number]
option 1 - CreateRemoteThread
option 2 - NtCreateThreadEx
option 3 - RtlCreateUserThread
		
## Inject PE - PE injection
This is a POC for the PE injection described here (and many other places):
[Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
Use:
1. Update the entryThread function as you want - that will be executed in the target
2. Run: injectpe.exe [target process]

## Process Hollowing
This is a POC for the Process Hollowing injection described here (and many other places):
[Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
Works quite reliably in x86 and x64 as well, there are plenty of error checks to avoid failures.
Use:
1. Run: processhollowing.exe [target binary] [to be run binary]

## Thread Execution Hijacking
This is a POC for the Thread Execution Hijacking described here (and many other places):
[Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
Opposite to other POCs available, this version will inject a shell code to the target process (and not a DLL name) and will get the target to Create a thread in itself.
Use:
1. Put your shell code into scx86 and scx64 accordingly.
2. Run: threadexecutionhijack.exe [process name] 
