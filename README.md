# Offline Malware Scanner (OMS) Common Analysis Module

This module scans a file with several malware scanners installed locally.

## Supported Scanners
* Avast
* AVG
* Bitdefender
* ClamAV (needs clamav-daemon and clamdscan)
* Comodo
* Eset
* F-Prot
* F-Secure
* McAfee
* Sophos

## Requriements
At least one AV-scanner must be installed.
We recommand:
ClamAV including ClamAV-Daemon and Clamdscan

## Known Issues
If your system language is not set to english, some scanner plug-ins might not work correctly.