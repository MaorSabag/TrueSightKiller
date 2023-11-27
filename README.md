# TrueSightKiller
TrueSightKiller is a CPP AV/EDR Killer. This driver can be used in Windows 23H2 with HVCI enabled, loldrivers blocklist, or WDAC enabled. HVCI is designed to ensure the integrity of code executed in the kernel, but it cannot protect against all possible vulnerabilities or actions that can be performed through drivers or system interfaces.

## Usage
To use TrueSightKiller, you need to have the `truesight.sys` driver located at the same location as the executable. When you run the executable, you will be presented with an options menu where you can specify a process ID or name. The program will then enter an infinite loop, continuously monitoring the specified process. To stop the program and delete the service, send a `ctrl+c` command.

## Recommendations
1) Block this driver through WDAC or wait till Microsoft do it (at your own risk)
2) Limit local privileges, audit and prevent privesc attacks.

## Disclaimer
Please use TrueSightKiller responsibly. It is designed for legitimate security testing and should not be used for malicious purposes.