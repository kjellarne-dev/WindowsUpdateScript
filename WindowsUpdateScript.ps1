#Requires -Version 4
################################################
#WindowsUpdateScript.ps1
#Script which automate checking for Windows Updates, downloading and installing
#
#Written by:    Kjell-Arne Lillevik Dahlen
#Version:       2.0.20181227
#Last Change:   27. Dec 2018
#Note:          Tested on Windows 7, 10 and Server 2019. I've only tested on PowerShell version 4.0 and 5.0, but in theory everything from PSv3.0 and up should work.
#               If you want to test it on 3.0 (again, I take no responsibility for any issues that may arise), edit the top line to "Requires -Version 3"
################################################
#HELP MENU
################################################

    <#
    .SYNOPSIS
        Run Windows Update on client computers and install the most recent updates from the source provided to them (whether that be WSUS or Microsoft Servers)

    .DESCRIPTION
        Windows Update Script intended for automating Windows Update installation, while enabling system administrators to maintain some control over how and when they are installed.
        This script runs Windows Update, documents the updates that are installed to the eventlog, and shuts down if the appropriate parameter is provided.

    .PARAMETER Shutdown
        Switch defining whether or not the script will shutdown the computer after the script is finished.
        If script is ran without -shutdown, the computer will be left running after everything is said and done.
        Default value = $False

    .PARAMETER NoReboot
        Switch defining whether or not the script reboots the computer when required.
        In certain instances (such as if file renames are scheduled, an app has been installed etc) the script will require a reboot before proceeding.
        In these cases the script registeres a scheduled task to start a defined amount of minutes after task creation and restarts the computer.

        If the NoReboot-flag is set the script will not create a scheduled task and will not reboot the computer.
        Default value = $False
        
    .EXAMPLE
        WindowsUpdateScript.ps1

        Will run Windows Update on the local machine and will not shut down the computer after Windows Update finishes.
    .EXAMPLE
        WindowsUpdateScript.ps1 -Shutdown

        Will run Windows Update on the local machine and shut down the computer after Windows Update finishes.
    .EXAMPLE
        WindowsUpdateScript.ps1 -NoReboot

        Will run Windows Update and will not reboot computer if required. This might cause Windows Update not to run!
        (increasingly more likely the longer the computer has been powered on and file system has queued changes).
    .NOTES
        You need to run this script with administrator rights to the local computer (such as the "NT AUTHORITY\SYSTEM" user)
        This script has been tested on Windows 7, Windows 10 and Server 2019 running PowerShell version 5.0 and greater

        Written by Kjell-Arne Lillevik Dahlen
        I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
        Runs Windows Update on local machine.
    #>

################################################
#PARAMETERS
################################################

Param (
    [Parameter(Mandatory=$False)]
    [Switch] $Shutdown = $False ,

    [Parameter(Mandatory=$False)]
    [Switch] $NoReboot = $False
    )

################################################
#VARIABLES
################################################

#EventLogName details what eventlog you want to save the logs in (will be created if it does not exist)
$EventLogName = "CompanyName"

#EventLogSource details what name will appear as 'source' in the event log (will be created if it does not exist)
#Note that if the source already exists on the computer, the script will not create the event log from the above variable.
#It errors out if it tries to create a source that already exists. Instead the script will log to the eventlog that the source is already connected to
$EventLogSource = "Windows Update Script"

#This details the location and name of the script - used when the script needs to reboot the computer. 
#If you are having issues with the script not resuming after a reboot - try uncommenting this line and pointing the script in the right direction
#If you run the script using a scheduled task, you will have to uncomment this line OR specify the Location variable in the task
$ScriptPath = "\\NetworkFileShare\Script\WindowsUpdateScript.ps1"

#Task name for the Scheduled task that is created if script requires a reboot
$ScheduledTaskName = "RunWUScriptAfterReboot"

#Set which executionpolicy you want the scheduled task to run the script as. Bypass is default since that's how I have been testing it
$ScheduledTaskExecutionPolicy = "Bypass"

#ScheduledTaskWaitMinutes defines how many minutes the scheduled task should wait until it starts (the timer starts counting as soon as the task is created in the script)
#If you are having issues with the script not resuming after a reboot, you might want to adjust this number
#It should at minimum be the time it takes from running Restart-Computer until you are logged in again and your applications have loaded (just to be on the safe side).
$ScheduledTaskWaitMinutes = 5

################################################
#FUNCTIONS
################################################

Function Initialize-EventLog {
    Param (
        [String] $Source ,

        [String] $LogName
    )

    #Check if Source exists
    If ([System.Diagnostics.EventLog]::SourceExists($Source)) {
        #Source Exists
        #Check if Eventlog exists
        If (Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue) {
            #Eventlog Exists
            #Check if source is part of eventlog
            If ($Source -Contains $(Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue)) {
                #Event Log Source exists and is part of the Event Log. Script is happy!
            } Else {
                #Event Log Source exists but is not part of the event log. Using whatever eventlog it is connected to
                $LogName = [System.Diagnostics.EventLog]::LogNameFromSourceName("$Source",".")
            }
        } Else {
            #EventLog Does not exist. Using whatever eventlog the source is connected to
            $LogName = [System.Diagnostics.EventLog]::LogNameFromSourceName("$Source",".")
        }
    } Else {
        #Source does not exist
        If (Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue) {
            #Event Log exists. Adding this script to the list of sources available
            New-EventLog -LogName $LogName -Source $Source
        } Else {
           #Event Log does not exist. Creating event log along with the source
           New-EventLog -LogName $LogName -Source $Source
           Limit-EventLog -LogName $LogName -RetentionDays 90 -OverFlowAction OverwriteOlder -MaximumSize 150MB
        }
    }

    #Return the (potentially new) logname and source to the script

    $EventLogVariable = [PSCustomObject]@{
        LogName = $LogName
        Source = $Source
    }
    Write-Output $EventLogVariable
}

Function Out-Log {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String] $LogMessage ,
        
        [Parameter(Mandatory=$False)]
        [ValidateScript({"Information", "Warning", "Error" -Contains $_})]
        [String] $LogLevel = "Information" ,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Int] $EventID = 2000
    )

    #$LogLevel valid entries are "Information", "Warning" and "Error", detailing which type of event log entry you want to log
    #If no LogLevel is defined, LogLevel defaults to Information
    #If EventID is not defined, the Event ID defaults to 2000

    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType $LogLevel -EventId $EventID -Message $LogMessage
}

Function Exit-Script {
    #Cleaning up scheduled task, in case the script had to reboot the computer
    Unregister-ScriptScheduledTask -TaskName $ScheduledTaskName
    
    If ($Shutdown) {
        Out-Log -LogMessage "Exiting Windows Update Script and shutting down the computer" -EventID 2003
        Stop-Computer -Force

        #Sleeping script for 30 seconds. Should not interfere with the previous shutdown command
        Start-Sleep -Seconds 30
        
        #There is a bug in certain versions of Windows 10 where the Stop-Computer command won't work as intended.
        #This command is put here in case of that scenario - it obviously won't run if the computer is already shutting down.
        #Run Shutdown.exe /? for an explanation of the different options available (/s = Shutdown, /t 0 = Immediately, /f = Force)
        Shutdown.exe /s /t 0 /f
    } Else {
        #Shutdown switch was not supplied to the script - a simple exit will do
        Out-Log -LogMessage "Exiting Windows Update Script"  -EventID 2002
        Exit
    }
}

Function Get-WIAStatusValue($value) {
    #Function for translating the Windows Update result codes into something readable
   Switch -exact ($value)
   {
      0   {"NotStarted"}
      1   {"InProgress"}
      2   {"Succeeded"}
      3   {"SucceededWithErrors"}
      4   {"Failed"}
      5   {"Aborted"}
   } 
}

Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Gets the pending reboot status on a local or remote computer.

    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from either Microsoft Patching or a Software Installation.
        For Windows 2008+ the function will query the CBS registry key as another factor in determining
        pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed
        as being consistant across Windows Server 2003 & 2008.
        
        CBServicing = Component Based Servicing (Windows 2008)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)

    .PARAMETER ComputerName
        A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

    .PARAMETER ErrorLog
        A single path to send error data to a log file.

    .EXAMPLE
        PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
        
        Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
        -------- ----------- ------------- ------------ -------------- -------------- -------------
        DC01           False         False                       False                        False
        DC02           False         False                       False                        False
        FS01           False         False                       False                        False

        This example will capture the contents of C:\ServerList.txt and query the pending reboot
        information from the systems contained in the file and display the output in a table. The
        null values are by design, since these systems do not have the SCCM 2012 client installed,
        nor was the PendingFileRenameOperations value populated.

    .EXAMPLE
        PS C:\> Get-PendingReboot
        
        Computer       : WKS01
        CBServicing    : False
        WindowsUpdate  : True
        CCMClient      : False
        PendFileRename : False
        PendFileRenVal : 
        RebootPending  : True
        
        This example will query the local machine for pending reboot information.
        
    .EXAMPLE
        PS C:\> $Servers = Get-Content C:\Servers.txt
        PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
        
        This example will create a report that contains pending reboot information.

    .LINK
        Component-Based Servicing:
        http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
        
        PendingFileRename/Auto Update:
        http://support.microsoft.com/kb/2723674
        http://technet.microsoft.com/en-us/library/cc960241.aspx
        http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

        SCCM 2012/CCM_ClientSDK:
        http://msdn.microsoft.com/en-us/library/jj902723.aspx

    .NOTES
        Author:  Brian Wilhite
        Email:   bwilhite1@carolina.rr.com
        Date:    08/29/2012
        PSVer:   2.0/3.0
        Updated: 05/30/2013
        UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only
                Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
                Removed $Data variable from the PSObject - it is not needed
                Bug with the way CCMClientSDK returned null value if it was false
                Removed unneeded variables
                Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias("CN","Computer")]
        [String[]]$ComputerName="$env:COMPUTERNAME",
        [String]$ErrorLog
        )

    Begin
        {
            # Adjusting ErrorActionPreference to stop on all errors, since using [Microsoft.Win32.RegistryKey]
            # does not have a native ErrorAction Parameter, this may need to be changed if used within another
            # function.
            $TempErrAct = $ErrorActionPreference
            $ErrorActionPreference = "Stop"
        }#End Begin Script Block
    Process
        {
            Foreach ($Computer in $ComputerName)
                {
                    Try
                        {
                            # Setting pending values to false to cut down on the number of else statements
                            $PendFileRename,$Pending,$SCCM = $false,$false,$false
                            
                            # Setting CBSRebootPend to null since not all versions of Windows has this value
                            $CBSRebootPend = $null
                            
                            # Querying WMI for build version
                            $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer

                            # Making registry connection to the local/remote computer
                            $RegCon = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"LocalMachine",$Computer)
                            
                            # If Vista/2008 & Above query the CBS Reg Key
                            If ($WMI_OS.BuildNumber -ge 6001)
                                {
                                    $RegSubKeysCBS = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\").GetSubKeyNames()
                                    $CBSRebootPend = $RegSubKeysCBS -contains "RebootPending"
                                        
                                }#End If ($WMI_OS.BuildNumber -ge 6001)
                                
                            # Query WUAU from the registry
                            $RegWUAU = $RegCon.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
                            $RegWUAURebootReq = $RegWUAU.GetSubKeyNames()
                            $WUAURebootReq = $RegWUAURebootReq -contains "RebootRequired"
                            
                            # Query PendingFileRenameOperations from the registry
                            $RegSubKeySM = $RegCon.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager\")
                            $RegValuePFRO = $RegSubKeySM.GetValue("PendingFileRenameOperations",$null)
                            
                            # Closing registry connection
                            $RegCon.Close()
                            
                            # If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
                            If ($RegValuePFRO)
                                {
                                    $PendFileRename = $true

                                }#End If ($RegValuePFRO)

                            # Determine SCCM 2012 Client Reboot Pending Status
                            # To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
                            $CCMClientSDK = $null
                            $CCMSplat = @{
                                NameSpace='ROOT\ccm\ClientSDK'
                                Class='CCM_ClientUtilities'
                                Name='DetermineIfRebootPending'
                                ComputerName=$Computer
                                ErrorAction='SilentlyContinue'
                                }
                            $CCMClientSDK = Invoke-WmiMethod @CCMSplat
                            If ($CCMClientSDK)
                                {
                                    If ($CCMClientSDK.ReturnValue -ne 0)
                                        {
                                            Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"
                                
                                        }#End If ($CCMClientSDK -and $CCMClientSDK.ReturnValue -ne 0)

                                    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)
                                        {
                                            $SCCM = $true

                                        }#End If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending)

                                }#End If ($CCMClientSDK)
                            Else
                                {
                                    $SCCM = $null

                                }                        
                            
                            # If any of the variables are true, set $Pending variable to $true
                            If ($CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename){
                                    $Pending = $true

                            }#End If ($CBS -or $WUAU -or $PendFileRename)
                                
                            # Creating Custom PSObject and Select-Object Splat
                            $SelectSplat = @{
                                Property=('Computer','CBServicing','WindowsUpdate','CCMClientSDK','PendFileRename','PendFileRenVal','RebootPending')
                            }
                            New-Object -TypeName PSObject -Property @{
                                    Computer=$WMI_OS.CSName
                                    CBServicing=$CBSRebootPend
                                    WindowsUpdate=$WUAURebootReq
                                    CCMClientSDK=$SCCM
                                    PendFileRename=$PendFileRename
                                    PendFileRenVal=$RegValuePFRO
                                    RebootPending=$Pending
                            } | Select-Object @SelectSplat

                        }#End Try

                    Catch
                        {
                            Write-Warning "$Computer`: $_"
                            
                            # If $ErrorLog, log the file to a user specified location/path
                            If ($ErrorLog)
                                {
                                    Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append

                                }#End If ($ErrorLog)
                                
                        }#End Catch
                        
                }#End Foreach ($Computer in $ComputerName)
                
        }#End Process
        
    End {
            # Resetting ErrorActionPref
            $ErrorActionPreference = $TempErrAct
    }#End End
        
}

Function Start-WindowsService {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
    	[String]$ServiceName
    )

    #Check whether service is running or not
    If ((Get-Service -Name $ServiceName).Status -ne "Running") {
        Out-Log -LogMessage "$ServiceName is not started - Configuring service to start automatically at boot and manually firing it up" -EventID 2020
        Set-Service  $ServiceName -StartupType Automatic

        #Attempting to start the service
        While ((Get-Service -Name $ServiceName).Status -ne "Running") {
            Start-Service -Name $ServiceName

            #Keep count of the number of attempts
            $ServiceStartAttempts ++
            Start-Sleep -Seconds 5

            If ($ServiceStartAttempts -ge 6) {
                #Exit the script if $ServiceName service hasn't started in 5 attempts (30 seconds)
                Out-Log -LogLevel "Error" -LogMessage "Unable to start $ServiceName... Terminating script" -EventID 2022
                Exit-Script

                #In case the exit function misbehaves, breaks out of the current while loop
                Break
            }
        }

        #The service was successfully started - otherwise the script would have exited itself by now
        Out-Log -LogMessage "$ServiceName was successfully started" -EventID 2021

        #Clearing attempts variable in case the script has to start this or another service again
        Clear-Variable ServiceStartAttempts
    }
}

Function Get-WindowsVersion {
    #This function retrieves the version from the hal.dll file in System32 directory
    #Version 5.0 is XP, 6.0 is Vista, 6.1 is W7, 6.2 is W8, 6.3 is W8.1 and 10 is W10
    #Her is a list of different int variables returned:

    #Windows XP: 50
    #Windows Vista: 60
    #Windows 7: 61
    #Windows 8.0: 62
    #Windows 8.1: 63
    #Windows 10: 100

    $ProductVersion = ((Get-ItemProperty -Path C:\Windows\System32\hal.dll).VersionInfo.ProductVersion) -Split "\."
    $OSVersion = $ProductVersion | Select-Object -Index 0
    $OSVersion += $ProductVersion | Select-Object -Index 1
    Return [Int]$OSVersion
}

Function Get-ScriptScheduledTask {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String] $TaskName
    )

    If ($OSVersion -ge "100") {
    #OS is Windows 10 or higher
        $ScheduledTask = Get-ScheduledTask | Where-Object TaskName -Contains $TaskName
    } Else {
    #OS is Windows 8.1 or lower
        #Retrieving the scheduled task as an XML
        [XML]$SchTask = schtasks.exe /query /TN $TaskName /XML

        #Yes, this solution is kinda hacky, but it works regardless of what language and region settings the windows computer is configured with, and is compatible with the existing solutions in the script
        #My reasoning for doing it this way is that this script is written with 'W10 first' in mind, and then the parts that add backwards compatibility to older Windows editions is adapted to fit that code.

        If ($SchTask) {
            #Get-ScheduledTask format the StartBoundary (date&time that the scheduled task will be ran) like $ScheduledTask.Triggers.StartBoundary
            #While schtasks.exe /XML formats it like $ScheduledTask.Task.Triggers.TimeTrigger.StartBoundary
            #Here the script weave together two custom PSObjects in order to replicate the Windows 10/PowerShell way of formatting Scheduled Tasks.

            #Building the custom object for Triggers
            $SchTaskTriggers = [PSCustomObject]@{
                StartBoundary = $SchTask.Task.Triggers.TimeTrigger.StartBoundary
            }

            #Weaving the custom trigger object into a larger custom ScheduledTask object
            $ScheduledTask = [PSCustomObject]@{
                Triggers = $SchTaskTriggers
                TaskName = $TaskName
            }
        }

    }

    If ($ScheduledTask) {
        Return $ScheduledTask
    } Else {
        Return $False
    }
}

Function Register-ScriptScheduledTask {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String] $TaskName
    )

    #This function sets up a scheduled task that runs once at startup
    Out-Log -LogMessage "Registering scheduled task before rebooting" -EventID 2030

    #First check if scriptpath is defined. If not it tries to retrieve the value from Powershell
    If (!$ScriptPath) {
        $ScriptPath = $MyInvocation.MyCommand.Path
    }

    #Check if executionpolicy exists, appending to argument list in case it is
    If ($ScheduledTaskExecutionPolicy) {
        $ArgumentList = " -ExecutionPolicy "+$ScheduledTaskExecutionPolicy
    }
    $ArgumentList += " -File "+$ScriptPath

    #Check if shutdown switch was provided, piping it through to the temporary scheduled task in case it is
    If ($ShutDown) {
        $ArgumentList += " -Shutdown"
    }

    If ($OSVersion -ge "100") {
    #OS is Windows 10 or higher
        #Execute PowerShell with the same shutdown flag that the script was originally ran with
        $TaskAction = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument $ArgumentList
        #Run the task once, $TaskWaitMinutes minutes after task creation
        $TaskTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes($ScheduledTaskWaitMinutes))
        #Set the task permissions to run as SYSTEM user
        $TaskPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        #Registers the Scheduled Task with parameters defined above
        Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal
    } Else {
    #OS is Windows 8.1 or lower
        $SchTaskDate = $(Get-Date -Format d)
        $SchTaskTime = $(Get-Date(Get-Date).AddMinutes($ScheduledTaskWaitMinutes) -Format T)
        $SchTaskArgs = "Powershell.exe"+$ArgumentList

        #Create the scheduled task
        schtasks.exe /Create /TN $TaskName /TR $SchTaskArgs /SC "ONCE" /SD $SchTaskDate /ST $SchTaskTime /RU "NT AUTHORITY\SYSTEM" /RL "HIGHEST" /V1 /F
    }

    If (Get-ScriptScheduledTask -TaskName $TaskName) {
        Out-Log -LogMessage "Scheduled task $TaskName successfully registered" -EventID 2031
        Return $True
    } Else {
        Out-Log -LogLevel "Error" -LogMessage "Could not register scheduled task $TaskName" -EventID 2032
        Return $False
    }
}

Function Unregister-ScriptScheduledTask {
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String] $TaskName
    )

    #Check if Scheduled task exist
    If (Get-ScriptScheduledTask -TaskName $TaskName) {
        Out-Log -LogMessage "Scheduled Task $TaskName exists. Unregistering task" -EventID 2033

        If ($OSVersion -ge "100") {
        #OS is Windows 10 or higher
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$False
        } Else {
        #OS is Windows 8.1 or lower
            schtasks.exe /Delete /TN $TaskName /F
        }

        If (Get-ScriptScheduledTask -TaskName $TaskName) {
            Out-Log -LogLevel "Error" -LogMessage "Scheduled Task $TaskName could not be unregistered due to an error" -EventID 2035
            Return $False
        } Else {
            Out-Log -LogMessage "Scheduled Task $TaskName was successfully unregistered" -EventID 2034
            Return $True
        }
    }
}

################################################
#START SCRIPT
################################################

#Set up the event log logging destination
$NewEventLogVariable = Initialize-EventLog -LogName $EventLogName -Source $EventLogSource

#Applying the logname and source once more, in case they changed in the initialize-eventlog function
$EventLogName = $NewEventLogVariable.LogName
$EventLogSource = $NewEventLogVariable.Source

#Start of script, writing a start point to the log
Out-Log -LogMessage "Starting Windows Update Script" -EventID 2001

#Check what version of Windows is running. Ref the Get-WindowsVersion function for which value corresponds to which version of Windows
$OSVersion = Get-WindowsVersion

#Check if computer needs a reboot
If ($(Get-PendingReboot).RebootPending) {  
    Out-Log -LogMessage "The system requires a reboot before Windows Update is able to run" -EventID 2010
    
    If ($NoReboot) {
        #NoReboot flag was set. Skipping reboot and terminating script
        Out-Log -LogLevel "Warning" -LogMessage "NoReboot flag was set. Please reboot the computer and try again. Terminating script" -EventID 2012
        Exit-Script
    }

    #Checking if the scheduled task already exist on the computer, indicating that the script already tried to reboot it once previously
    If (Get-ScriptScheduledTask -TaskName $ScheduledTaskName) {
        #Check if computer already tried to reboot within the past two hours (approximately)
        If ((Get-ScriptScheduledTask -Taskname $ScheduledTaskName).Triggers.StartBoundary -ge (Get-Date).AddHours(-2)) {
            #Script has already tried to reboot in the past two hours. Cleaning up and exiting
            Out-Log -LogLevel "Error" -LogMessage "Script has already tried to reboot once. Assuming that there is something faulty with client and terminating this session" -EventID 2013
            Exit-Script
        } Else {
            #The scheduled task is older than two hours, assuming that it's a remnant from a previous run, cleaning up and rebooting computer
            If (!(Unregister-ScriptScheduledTask -TaskName $ScheduledTaskName)) {
                #The unregister function failed due to an error, exiting script
                Exit-Script
            }
        }
    }
    
    #Script has not forced a reboot and noreboot flag has not been set.
    #Creating scheduled task and rebooting
    Out-Log -LogMessage "Script does not have the NoReboot flag set and has not tried a reboot yet" -EventID 2011
    If (Register-ScriptScheduledTask -TaskName $ScheduledTaskName) {
        #Successfully registered a scheduled task
        Out-Log -LogMessage "Restarting Computer" -EventID 2004

        Restart-Computer -Force

        Start-Sleep -Seconds 5
        
        #Exiting the script in case the restart computer-command fails or is delayed for some reason
        Exit
    } Else {
        #Scheduled Task registration failed. Exiting script
        Exit-Script
    }
}

#Verifying that wuauserv service is running, required for installing Windows Updates
Start-WindowsService -ServiceName "wuauserv"

#Checking for, downloading and installing updates from Windows Update
Try {
    #Retrieving a list of updates available for the computer
    Out-Log -LogMessage "Searching for available updates" -EventID 2040
	$UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    
    #Narrow the list of updates to only include the ones applicable to the machine, not hidden from installation and are not currently installed
	$SearchResult = ($UpdateSearcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0")).Updates

    If (!($SearchResult) -Or $SearchResult.Count -eq 0) {
        Out-Log -LogMessage "0 new updates have been made available for this computer" -EventID 2042
        Exit-Script
    } Else {
        Out-Log -LogMessage "$($SearchResult.Count) new updates found. Processing..." -EventID 2041
    }

    $SearchResult = $SearchResult | Sort-Object LastDeploymentChangeTime -Descending # Sort updates

    #Going through the updates one by one, downloading, installing and logging
    Foreach ($Update in $SearchResult) {
        #Increment update counter to keep track of the number of updates processed
        $UpdateCounter++
        #Add Update to Collection
        $UpdatesCollection = New-Object -ComObject Microsoft.Update.UpdateColl
        If ( $Update.EulaAccepted -eq 0 ) { 
            $Update.AcceptEula() 
        }
        $UpdatesCollection.Add($Update)

        #Download update
        Out-Log -LogMessage "Downloading - Update [$UpdateCounter/$($SearchResult.Count)] - $($Update.Title)" -EventID 2050
        $UpdatesDownloader = $UpdateSession.CreateUpdateDownloader()
        $UpdatesDownloader.Updates = $UpdatesCollection
        $UpdatesDownloader.Priority = 3
        $DownloadResult = $UpdatesDownloader.Download()

        $Message = "Download {0} - Update [$UpdateCounter/$($SearchResult.Count)] - $($Update.Title)" -f (Get-WIAStatusValue $DownloadResult.ResultCode)
        Out-Log -LogMessage $Message -EventID $(2051 + $DownloadResult.ResultCode)

        #Resultcode 4 and 5 indicates failed or aborted downloads
        If (4,5 -notcontains $DownloadResult.ResultCode) {
            #Download succeeded, attempting to install

            #Install update
            Out-Log -LogMessage "Installing - Update [$UpdateCounter/$($SearchResult.Count)] - $($Update.Title)" -EventID 2060
            $UpdatesInstaller = $UpdateSession.CreateUpdateInstaller()
            $UpdatesInstaller.Updates = $UpdatesCollection
            $InstallResult = $UpdatesInstaller.Install()

            $Message = "Install {0} - Update [$UpdateCounter/$($SearchResult.Count)] - $($Update.Title)" -f (Get-WIAStatusValue $InstallResult.ResultCode)
            Out-Log -LogMessage $Message -EventID $(2061 + $InstallResult.ResultCode)

            #Check if the failed to install
            If (4,5 -contains $InstallResult.ResultCode) {
                #Install failed, adding to failed counter
                $FailedInstallCounter++
            }

            $NeedsReboot += @($installResult.rebootRequired)
        } Else {
            #Download failed, adding to failed counter
            $FailedDownloadCounter++
        }
    
        #Verifying that wuauserv service is still running
        Start-WindowsService -ServiceName "wuauserv"
    }

    #Checking if any updates failed to download
    If ($FailedDownloadCounter) {
        Out-Log -LogLevel "Error" -LogMessage "$FailedDownloadCounter updates failed to download" -EventID 2067
    }
    
    #Checking if any updates failed to install
    If ($FailedInstallCounter) {
        Out-Log -LogLevel "Error" -LogMessage "$FailedInstallCounter updates failed to install" -EventID 2068
    }
    
    Out-Log -LogMessage "Finished downloading and installing updates" -EventID 2070

    If ($NeedsReboot -Contains $True) {
        If ($NoReboot -and !$Shutdown) {
            #Write message to event log in case the computer is not going to reboot or shut down
            Out-Log -LogLevel "Warning" -LogMessage "Some updates require a reboot. Please do so at your earliest convenience" -EventID 2069
        }
    }

} Catch {
    #Catching error messages and writing them alongside script stack trace to the event log
    $exceptionMessage = "$($_.Exception.Message) `($($_.ScriptStackTrace)`)" 
    Out-Log -LogLevel "Error" -LogMessage $exceptionMessage -EventID 2043
}

Exit-Script

################################################
#END SCRIPT 
################################################