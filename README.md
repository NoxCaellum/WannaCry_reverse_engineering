# WannaCry – Cryptographic Module Reverse Engineering


This repository presents a comprehensive reverse engineering analysis of the WannaCry ransomware sample. The objective of this project is to study the malware from a technical perspective in order to understand its internal structure, execution flow, and encryption mechanisms.
The analysis combines multiple approaches, including static analysis, dynamic analysis, and automated triage techniques. 
Static analysis is used to examine the binary structure, embedded resources, and cryptographic routines without execution. Dynamic analysis is performed in an isolated environment to observe runtime behavior, system modifications. Automated triage tools are leveraged to rapidly identify key capabilities, suspicious functions, and relevant indicators of compromise.
In addition, threat intelligence resources are integrated into the analysis process to correlate findings with known malware families, documented TTPs, and publicly available intelligence data.


---


## Extracting and Decrypting the Embedded DLL

The `t.wnry` archive contains an encrypted DLL responsible for WannaCry’s cryptographic operations. To analyze this module, it is necessary to first extract and then decrypt it.

1. **Extraction of the AES Key and DLL**  
A custom script is used to extract the AES encryption key and the encrypted DLL from `t.wnry`. This step isolates the components required for further analysis.

```bash
python twnry_extraction.py
````

```bash
wncry_rsa_key_decryption.exe
```
<img width="899" height="533" alt="wannacry_dll_decryption" src="https://github.com/user-attachments/assets/ad43a697-9910-4318-a324-8dc0311d1e99" />
