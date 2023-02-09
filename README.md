# Early bird + Parent Process Id Spoofing

This technique is already well known but still powerfull.
The main idea is to queue an user thread into a suspended process, avoiding the need to create a new thread. Since the process is launch in suspended state, EDR's haven't placed any hooks yet.

For the PPId spoofing, we just copy the attributes of another process. It can be detected if we take a look at the event log.

Compiled with **Visual Studio 2022 Community.**
Sucessfully bypass Windows Defender on Windows 10. I used a meterpreter https reverse shell.

## References:
- https://ph3n1x.com/posts/parse-ntdll-and-peb/
- https://captmeelo.com/redteam/maldev/2021/11/22/picky-ppid-spoofing.html
- https://github.com/paranoidninja/PIC-Get-Privileges/blob/main/addresshunter.h
- https://institute.sektor7.net/rto-maldev-intermediate