# Injection techniques
I created this repo during my journey in learning more about the various process injection techniques. I did reuse other’s code, but tried to improve on them or modify them to our need and better reading. The source should be indicated in the code.
All of them were created with Visual Studio 2017.

## Simple Thread Injection
Probably the simples injection, it simply allocates memory in the new process, writes to it, and creates a remote thread. You can do that via 3 different APIs.
Use
Run: SimpleThreadInection.exe [process name] [option number]
option 1 - CreateRemoteThread
option 2 - NtCreateThreadEx
option 3 - RtlCreateUserThread

## Inject DLL - DLL injection
This is a POC for the DLL injection described here (and many other places):
[Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
Use
Run: injectdll.exe [process name] [dll path] [option number]
option 1 - CreateRemoteThread
option 2 - NtCreateThreadEx
option 3 - RtlCreateUserThread

## APC Injection
This injection uses QueueUserAPC API to start a thread in the remote process after writing a shell code to its memory.
Use: APCInjection [process name]

## EarlyBird injection
This is a POC for the EarlyBird injection technique as named by Cyberbit, it’s a corner case of QueueUserAPC. More details here:
[Hackers Found Using A New Code Injection Technique to Evade Detection](https://thehackernews.com/2018/04/early-bird-code-injection.html)

Use:
1. Put the shellcode of your choice to the source file (the included one will pop cmd.exe)
2. Recompile
3. Run: EarlyBird.exe [any x64 binary]

## SetWindowsHook injection
Also described here:
[Ten Process Injection Techniques: A Technical Survey of Common and Trending Process Injection Techniques | Endgame](https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)
Use: SetWindowsHookInjection.exe [window name] [dll path] [function name]

## CtrlInject injection
This is a POC for the CtrlInjection found by enSilo:
[Ctrl-Inject](https://blog.ensilo.com/ctrl-inject)

Use:
1. Put the shellcode of your choice to the source file (the included one will pop calc)
2. Recompile
3. Run: EarlyBird.exe [PID of x64 Console Application which has a non default HandlerList (e.g.: cmd.exe)]
		
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

## PROPagate
This one is described here:
[Hexacorn | Blog](http://www.hexacorn.com/blog/2017/10/26/propagate-a-new-code-injection-trick/)
I decided to release this as malware uses this technique, and we need defense people to understand how this work:
[RIG Exploit Kit Delivering Monero Miner Via PROPagate Injection Technique « RIG Exploit Kit Delivering Monero Miner Via PROPagate Injection Technique | FireEye Inc](https://www.fireeye.com/blog/threat-research/2018/06/rig-ek-delivering-monero-miner-via-propagate-injection-technique.html)
The x64 shell code will crash explorer.exe, but that will restart. I need to rewrite this code to work more generically and without a crash, but so far this is how it is. This POC is very dirty, there was a nicer one on GitHub but it’s no longer available.

## 7 Window message based Injection
The following 7 POCs are based on the following posts. In the light of some recent research and to bring awareness I decided to release them.

[Listplanting – yet another code injection trick](http://www.hexacorn.com/blog/2019/04/25/listplanting-yet-another-code-injection-trick/)

[Treepoline – new code injection technique](http://www.hexacorn.com/blog/2019/04/24/treepoline-new-code-injection-technique/)

[3 (4) new code injection tricks](http://www.hexacorn.com/blog/2019/04/24/3-new-code-injection-tricks/)

[WordWarper – (not a ) new code injection trick](http://www.hexacorn.com/blog/2019/04/23/wordwarper-new-code-injection-trick/)

[Windows Process Injection: WordWarping, Hyphentension, AutoCourgette, Streamception, Oleum, ListPlanting, Treepoline](https://modexp.wordpress.com/2019/04/25/seven-window-injection-methods/)

* AutoCorrectProc_Injection
* EditStreamCallback_injection
* EditWordBreakProc_Injection
* HyphenateProc_Injection
* IRichEditOleCallback_Injection
* ListViewCompare_Injection
* TreeViewCompare_Injection