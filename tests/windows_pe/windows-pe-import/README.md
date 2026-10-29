Tests DLL import detection via the `windows_pe` keyword. Import DLL names
are specified directly as keyword options (e.g., `windows_pe: ws2_32.dll`).

Uses two PEs: a "malware-like" PE importing WS2_32.dll, WININET.dll,
ADVAPI32.dll, and KERNEL32.dll; and a "benign" PE importing only
KERNEL32.dll and USER32.dll. Tests single-DLL matching, multi-DLL AND logic,
negative tests for absent DLLs, and combinations with `arch`, `subsystem`,
and `sections`.
