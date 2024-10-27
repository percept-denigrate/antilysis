# Antilysis

Rust library implementing state-of-the-art dynamic analysis countering techniques on Windows

- Detects VM guest processes
- Detects common analysis tools like wireshark, process explorer, etc...
- Detects common antivirus sandbox artifacts
- Reverse Turing test: waits for user to left click
- Checks if the mac address matches patterns of known VM mac addresses
- Detects VM related files 

## Inspirations

[Malware Dynamic Analysis Evasion Techniques:
A Survey](https://arxiv.org/pdf/1811.01190)

[Spotless Sandboxes: Evading Malware Analysis
Systems using Wear-and-Tear Artifacts](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7958622)
