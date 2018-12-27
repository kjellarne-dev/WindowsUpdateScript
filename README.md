# WindowsUpdateScript
A powershell script that runs Windows Update, logging everything to the event log, reboots if necessary and shut down the computer after it is finished (all depending on parameters provided)

This script is designed to run directly on client computers (not remotely), for example through a scheduled task deployed via GPOs or a scheduled deployment in PDQ. My recommendation is to have the code run from a network share where all domain computers have read access, but not write access (like \\\\domain.com\netlogon). That way no end user can modify the code, even if their computer is compromised.

For example, say you want the computers to run Windows Update during the night, then power off as soon as they are finished updating - then you create a scheduled task that run at 3 am, append the "-Shutdown" parameter at the end and off you go.

Run a Get-Help WindowsUpdateScript.ps1 for more information (or just read it in the source code)


This PowerShell Script creates a custom eventlog that it logs to by default. I have not tested if it is possible to write to any of the preexisting event logs, but in theory it should be possible.


# Before use
Please double check the variables section of the script before you run it to make sure that the script write logs to the correct destination. It is kind of annoying to have to clean up the eventlog after botched runs ;)
Protip: Get-Eventlog | Remove-Eventlog is your friend in such cases.


# Known Issues
The script has an issue where if the event log source already exists somewhere else on the system, but the event log doesn't, then it is unable to create the event log. Current workaround is to use the event log where the source already exists (the script does this automatically), but I'm looking to see if there is any possibility of a proper fix. In any case: the default script source does not exist on any system (unless you've added it manually yourself), so it should be fine.
