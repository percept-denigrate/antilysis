# Antilysis

Rust library implementing state-of-the-art dynamic analysis countering techniques on Windows

## Features

- Checks for processes of
    - common analysis tools (wireshark, process explorer...)
    - VM guest (VMware, Virtualbox, QEMU, Xen   )
    - debuggers (WinDbg, OllyDbg, GDB, Procdump...)
- Detects common antivirus sandbox artifacts
- Reverse Turing test: waits for user to left click
- Checks if the mac address matches patterns of known VM mac addresses
- Detects VM related files
- Anti-debugging:
    - Checks the presence of debuggers by reading the Process Environment Block (PEB)
    - Checks the presence of the "\\.\NTICE" device (named pipe) which is used to communicate with SoftIce, a Windows kernel debugger
    - Ability to hide thread from debuggers

## Inspirations

[Malware Dynamic Analysis Evasion Techniques:
A Survey](https://arxiv.org/pdf/1811.01190)

[Spotless Sandboxes: Evading Malware Analysis
Systems using Wear-and-Tear Artifacts](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7958622)
