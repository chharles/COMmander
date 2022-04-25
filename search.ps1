# references:
# https://pentestlab.blog/2020/05/20/persistence-com-hijacking/
#   List of lots of different techniques


# looks for scheduled tasks that are hijackable
function Get-Scheduled-Tasks-Missing-HKCU {
    $tasks = Get-ScheduledTask
    $fields = @()
    $targets = New-Object System.Collections.Generic.Dictionary"[String,[System.Collections.ArrayList]]"
    foreach ($task in $tasks) {
        if ($task.Triggers -match "MSFT_TaskLogonTrigger") {
            if ($task.Actions -match "MSFT_TaskComHandlerAction") {
                foreach ($trigger in $task.Triggers) {
                    if ($trigger.Delay -And -Not ($targets.containskey("$($task.TaskName)"))) {
                        $targets.Add("$($task.TaskName)",@($trigger.Delay, $task.Actions.classId))
                    }
                }
            }
        }
    }
    
    $HKLM_targets = New-Object System.Collections.Generic.Dictionary"[String,String]"
    $HKCU_targets = New-Object System.Collections.Generic.Dictionary"[String,String]"
    foreach($field in $targets.keys)
    {
        $dll = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$($targets.$field[1])\InProcServer32" -ErrorAction SilentlyContinue
        $exe = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$($targets.$field[1])\LocalServer32" -ErrorAction SilentlyContinue
    
        if ($dll -ne $null) { 
            $HKCU_targets.Add("$($targets.$field[1])", (Get-ItemProperty $dll.PSPath).'(default)') 
        }
        if ($exe -ne $null) { 
            $HKCU_targets.Add("$($targets.$field[1])",(Get-ItemProperty $exe.PSPath).'(default)') 
        }
    
        $dll = Get-Item -path "Registry::HKLM\Software\Classes\CLSID\$($targets.$field[1])\InProcServer32" -ErrorAction SilentlyContinue
        $exe = Get-Item -path "Registry::HKLM\Software\Classes\CLSID\$($targets.$field[1])\LocalServer32" -ErrorAction SilentlyContinue
    
        if ($dll -ne $null) { 
            $HKLM_targets.Add("$($targets.$field[1])", (Get-ItemProperty $dll.PSPath).'(default)') 
        }
        if ($exe -ne $null) { 
            $HKLM_targets.Add("$($targets.$field[1])",(Get-ItemProperty $exe.PSPath).'(default)') 
        }
    
    }
    
    foreach ($val in $HKLM_targets.keys)
    {
        if ($HKCU_targets.ContainsKey($val)) {
            "HKCU and HKLM both contain pathes to COM Objects"   
        }
        else {
            "$($val) ($($HKLM_targets.$val)) may be vulnerable to COM Hijacking"
        }
    }
    
}

# Source : https://github.com/nccgroup/acCOMplice/blob/master/COMHijackToolkit/COMHijackToolkit.ps1
function Get-RegistrySubkeys {
    $HKCR_CLSID = "Registry::HKCR\CLSID"
    # grabs all of the HKCR CLSIDs
    $HKCR_Keys = Get-ChildItem -Path $HKCR_CLSID
    # iterate over all of the HKCR CLSIDs
    foreach ($Key in $HKCR_Keys) {
        # get the Subkeys for each CLSID
        $Subkeys = $key.GetSubkeyNames()
        foreach ($subkey in $Subkeys) {
            Write-Output "$key\$subkey"
        }
    }
}



function Missing-Libraries {
    $User = $env:USERNAME
    
    # grab all of the HKCR CLSIDs subkeys
    $HKCR_CLSID_Subkeys = Get-RegistrySubkeys
    foreach ($key in $HKCR_CLSID_Subkeys) {
        $Subkeys = Get-Item -Path "Registry::$key"
        foreach ($subkey in $Subkeys) {
            # look for keys with InprocServer32 or localServer32 (exes and dlls)
            if ($subkey.Name -like "*procserver*" -or $subkey.Name -like "*localserver*") {
                $guid = ($subkey.Name).Split('\')[2]
                # grab the binary associated with the subkey
                $binary = (Get-ItemProperty $subkey.PSPath).'(default)'
                # if the binary string is empty, move on to the next subkey
                if (!$binary) {
                    continue
                }
                # check if the binary exists
                $binary =  "$binary".replace('"','')
                
                # deal with rundll32.exe
                if ($binary -like "*C:\Windows\System32\rundll32*") {
                    $rundll = $binary -split "rundll32.exe"
                    $rundll_dll_and_parms = $rundll[1].trim()
                    
                    #grab the dll being run by rundll32.exe
                    if ($rundll_dll_and_parms.contains(".dll")) {
                        # split on the comma, to grab dll and not the function being called on
                        if ($rundll_dll_and_parms.contains(',')) {
                            $rundll_dll = $rundll_dll_and_parms.Split(',')[0]
                        } else {
                            $rundll_dll = $rundll_dll_and_parms
                        }
    
                    # if rundll32.exe /sta is being used to load and run GUIDs directly
                    # This is VERY suspicious
                    } elseif ($rundll_dll_and_parms.contains("sta")) {
                        "`n`n!!!!! WARNING THIS IS SUSPICIOUS !!!!!"
                        $binary
                        $rundll32_sta_guid = ($rundll_dll_and_parms -split "sta")[1].trim()
                        $sta_guid_subkeys = Get-ChildItem -Path "Registry::HKCR\CLSID\$rundll32_sta_guid"
                        foreach ($sta_guid_subkey in $sta_guid_subkeys) {
                            if ($sta_guid_subkey.Name -like "*procserver*" -or $sta_guid_subkey.Name -like "*localserver*") {
                                $binary = (Get-ItemProperty $sta_guid_subkey.PSPath).'(default)'
                                "$rundll32_sta_guid -> $binary`n`n"
                            }
                        }
                    }
                    
                    $binary = $rundll_dll
                }
                
                # split on exes with parameters
                if ($binary -like "*.exe /*" -or $binary -like "*.exe -*" -or $binary -like "*.exe *") {
                
                    # explorer.exe /factory,{GUID} LOLBAS https://twitter.com/sbousseaden/status/1365038669447524358?lang=en
                    if ($binary -like "*explorer.exe /factory*") {
                        $explorer_guid = $binary.Split(',')[1]
                        $explorer_guid_subkeys = Get-ChildItem -Path "Registry::HKCR\CLSID\$explorer_guid"
                        foreach ($explorer_guid_subkey in $explorer_guid_subkeys) {
                            if ($explorer_guid_subkey.Name -like "*procserver*" -or $explorer_guid_subkey.Name -like "*localserver*") {
                                $directed_binary = (Get-ItemProperty $explorer_guid_subkey.PSPath).'(default)'
                                if ($directed_binary -ne $binary) {
                                    "`n`n!!!!! WARNING THIS IS SUSPICIOUS !!!!!"
                                    "https://twitter.com/sbousseaden/status/1365038669447524358?lang=en"
                                    $binary
                                    "$explorer_guid -> $directed_binary`n`n"
                                } else {
                                    $binary = "explorer.exe"
                                }
                            }
                        }
                    }

                    # split on '.exe -'
                    if ($binary -like "*.exe -*") {
                        $binary_exe = $binary -split ".exe -"
                        $binary = $binary_exe[0] + '.exe'
                    }
                    #split on '.exe /'
                    elseif ($binary -like "*.exe /*") {
                        $binary_exe = $binary -split ".exe /"
                        $binary = $binary_exe[0] + '.exe'
                    } 
                    # split on '.exe ' MAY BE TROUBLESOME
                    elseif ($binary -like "*.exe *") {
                        $binary_exe = $binary -split ".exe "
                        $binary = $binary_exe[0] + '.exe'
                    }

                }

                #check to see if thi binary exists
                if (!(Test-Path -Path "$binary")) {
                    # if the binary can't be found in the current path
                    if (!(Get-Command "$binary") 2>$null) {
                        # need to add a check to see if the path can be modified by the current user context
                        "$guid -> $binary"
                        $path = Split-Path $binary
                        while ($path) {
                            if (!(Test-Path -Path "$path")) {
                                #Write-Output "$path does not exist"
                            } else {
                                try{
                                    New-Item -Path $path -Name "COMPermissionTest.txt" -ItemType "file" -Value "test" | Out-Null
                                    Remove-Item -Path "$path\COMPermissionTest.txt" | Out-Null
                                    Write-Output "current user context can write to $path"
                                    break
                                } catch {
                                    # do nothing
                                }
                            }
                            $path = Split-Path $path
                        }
                    }
                }

                
            }
        }
    }
}

function Create_Malicious_GUID($GUID, $binary) {
    #check if the binary for the target of the GUID exists
    if (!($GUID.contains("{")) -and !($GUID.contains("}"))) {
        $GUID = "{" + $GUID + "}"
    }
    if (!(Test-Path -Path "$binary")) {
        return "`"$binary`" does not exist - check the path"
    }
    # check the extension of the binary
    $dll = $False
    $exe = $False
    if ($binary.contains(".exe")) {
        $exe = $True
    } 
    elseif ($binary.contains(".dll")) {
        $dll = $True
    }
    else {
        return "target binary must be either a dll or executable" 
    }

    # determine if the target thread type matches to the binary
    $dll_obj = $null
    $exe_obj = $null
    $dll_obj = Get-Item -LiteralPath Registry::HKCR\CLSID\$GUID\InProcServer32 -ErrorAction SilentlyContinue
    $exe_obj = Get-Item -LiteralPath Registry::HKCR\CLSID\$GUID\LocalServer32 -ErrorAction SilentlyContinue

    if ($dll -and !($dll_obj)) {
        return "the target COM object does not appear to use dlls"
    }
    if ($exe -and !($exe_obj)) {
        return "the target COM object does not appear to use exes"
    }

    $InHKLM = $False
    $InHKCU = $False

    $HKLM_CLSID_exists = $False
    $HKCU_CLSID_exists = $False

    $HKLM_obj = $null
    $HKCU_obj = $null
    $HKLM_obj = Get-Item -path Registry::HKLM\Software\Classes\CLSID\$GUID -ErrorAction SilentlyContinue
    if ($HKLM_obj){
        $HKLM_CLSID_exists = $True
    }
    $HKCU_obj = Get-Item -path Registry::HKCU\Software\Classes\CLSID\$GUID -ErrorAction SilentlyContinue
    if ($HKCU_obj) {
        $HKCU_CLSID_exists = $True
    }


    if ($dll_obj) {
        $HKLM_dll_obj = $null
        $HKCU_dll_obj = $null
        $HKLM_dll_obj = Get-Item -path Registry::HKLM\Software\Classes\CLSID\$GUID\InProcServer32 -ErrorAction SilentlyContinue
        if ($HKLM_dll_obj){
            $InHKLM = $True
        }
        $HKCU_dll_obj = Get-Item -path Registry::HKCU\Software\Classes\CLSID\$GUID\InProcServer32 -ErrorAction SilentlyContinue
        if ($HKCU_dll_obj) {
            $InHKCU = $True
        }
    }
    if ($exe_obj) {
        $HKLM_exe_obj = $null
        $HKCU_exe_obj = $null
        $HKLM_exe_obj = Get-Item -path Registry::HKLM\Software\Classes\CLSID\$GUID\LocalServer32 -ErrorAction SilentlyContinue
        if ($HKLM_exe_obj) {
            $InHKLM = $True
        }
        $HKCU_exe_obj = Get-Item -path Registry::HKCU\Software\Classes\CLSID\$GUID\LocalServer32 -ErrorAction SilentlyContinue
        if ($HKCU_exe_obj) {
            $InHKCU = $True
        }
    }

    if (!($InHKCU)) {
        #check if the CLSID exists
        # if the CLSID does not exist, create it
        if(!($HKCU_CLSID_exists)) {
            New-Item -Path "HKCU:\Software\Classes\CLSID" -Name "$GUID"
        }
        if ($dll) {
            # create the inprocserver32 subkey
            New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "InProcServer32"
            Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32" -Name '(default)' -Value "$binary"
            return "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32 set to $binary"
        } 
        elseif ($exe) {
            # create the inprocserver32 subkey
            New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "LocalServer32"
            Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32" -Name '(default)' -Value "$binary"
            return "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32 set to $binary"
        } 
        else {
            break
        }
    } else {
        return "$GUID already exists in HKLM"
    }

}

# requires administative privs
#inspired by https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Get-ScheduledTaskComHandler.ps1
function Hijackable-Scheduled-Tasks {

    param (
        [Parameter(ParameterSetName = 'OnLogon')]
        [Switch]
        $OnLogon,
        [Parameter(ParameterSetName = 'PersistenceLocations')]
        [Switch]
        $PersistenceLocations,
        [Parameter(ParameterSetName = 'OrderHijack')]
        [Switch]
        $OrderHijack
    )
    

    $path = "$env:windir\System32\Tasks"
    # requires administative privs
    # Get-ChildItem -Path $path -Recurse 
    # does not require administrative privs
    $tasks = Get-ScheduledTask
    foreach ($task in $tasks) {
        $task_name = $task.TaskName
        $task_path = "$path" + $task.URI # full Path of the task
        $taskXML = [xml] (Get-Content $task_path)
        if ($taskXML.Task.Actions.ComHandler) {
            $TaskTrigger = $taskXML.Task.Triggers.OuterXML
            $COM = $taskXML.Task.Actions.ComHandler.ClassID
            
            $dll = ""
            $exe = ""
            $dll_obj = Get-Item -LiteralPath Registry::HKCR\CLSID\$COM\InProcServer32 -ErrorAction SilentlyContinue
            $exe_obj = Get-Item -LiteralPath Registry::HKCR\CLSID\$COM\LocalServer32 -ErrorAction SilentlyContinue

            if ($dll_obj){
                $dll = (Get-ItemProperty -LiteralPath Registry::HKCR\CLSID\$COM\InProcServer32).'(default)'
            }
            if ($exe_obj) {
                $exe = (Get-ItemProperty -LiteralPath Registry::HKCR\CLSID\$COM\LocalServer32).'(default)' # this was not included
            }

            $InHKLM = $False
            $InHKCU = $False
            if ($dll_obj) {
                $HKLM_dll_obj = Get-Item -path Registry::HKLM\Software\Classes\CLSID\$COM\InProcServer32 -ErrorAction SilentlyContinue
                if ($HKLM_dll_obj){
                    $InHKLM = $True
                }
                $HKCU_dll_obj = Get-Item -path Registry::HKCU\Software\Classes\CLSID\$COM\InProcServer32 -ErrorAction SilentlyContinue
                if ($HKCU_dll_obj) {
                    $InHKCU = $True
                }
            }
            if ($exe_obj) {
                $HKLM_exe_obj = Get-Item -path Registry::HKLM\Software\Classes\CLSID\$COM\LocalServer32 -ErrorAction SilentlyContinue
                if ($HKLM_exe_obj) {
                    $InHKLM = $True
                }
                $HKCU_exe_obj = Get-Item -path Registry::HKCU\Software\Classes\CLSID\$COM\LocalServer32 -ErrorAction SilentlyContinue
                if ($HKCU_exe_obj) {
                    $InHKCU = $True
                }
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'Taskname' $task_name
            $Out | Add-Member Noteproperty 'CLSID' $COM
            $Out | Add-Member Noteproperty 'dll' $dll
            $Out | Add-Member Noteproperty 'exe' $exe
            $Out | Add-Member Noteproperty 'Logon' $False
            $Out | Add-Member Noteproperty 'InHKCU' $InHKCU
            $Out | Add-Member Noteproperty 'InHKLM' $InHKLM

            $null = $TaskXML.Task.InnerXml -match 'Context="(?<Context>InteractiveUsers|AllUsers|AnyUser)"'

            $IsUserContext = $False
            if ($Matches -and $Matches['Context']) { $IsUserContext = $True}
            $Out | Add-Member Noteproperty 'IsUserContext' $IsUserContext

            if ($TaskTrigger -and $TaskTrigger.Contains('LogonTrigger')) {
                $Out.Logon = $True
            }
        }
        if ($OnLogon) {
            if ($Out.Logon) {
                $Out
            }
        } elseif ($PersistenceLocations) {
            if ($Out.Logon -and $Out.IsUserContext) {
                $Out
            }
        } elseif ($OrderHijack) {
            if ($Out.Logon -and !($Out.InHKCU) -and $Out.InHKLM) {
                $Out
            }
        } else {
            $Out
        }
    }
}


