# WindowsUpdateScript
A powershell script that runs Windows Update, reboots if necessary and shut down the computer after it is finished (all depending on parameters provided)

This script is designed to run directly on client computers, for example a scheduled task deployed through GPOs. My recommendation is to run it from a network share where all domain computers have read access, but not write access (like \\domain.com\netlogon). That way no end user can modify the code, even if their computer is compromised.

For example, say you want the computers to run Windows Update during the night, then power off as soon as they are finished updating - then you create a scheduled task that run whenever you prefer to run updates, append the "-Shutdown" parameter at the end and off you go.

Run a Get-Help WindowsUpdateScript.ps1 for more information (or just read it in GitHub code)
