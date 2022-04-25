# references:
# https://pentestlab.blog/2020/05/20/persistence-com-hijacking/
#   List of lots of different techniques


# looks for scheduled tasks that are hijackable
function Hijackable-Scheduled-Tasks {
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
    # grab all of the HKCR CLSIDs subkeys
    $HKCR_CLSID_Subkeys = Get-RegistrySubkeys
    foreach ($key in $HKCR_CLSID_Subkeys) {
        $Subkeys = Get-Item -Path "Registry::$key"
        foreach ($subkey in $Subkeys) {
            # look for keys with InprocServer32 or localServer32 (exes and dlls)
            if ($subkey.Name -like "*procserver*" -or $subkey.Name -like "*localserver*") {
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
                    } elseif ($rundll_dll_and_parms.contains("sta")) {
                        "!!!!! WARNING! THIS IS SUSPICIOUS !!!!!"
                        $rundll32_sta_guid = ($rundll_dll_and_parms -split "sta")[1].trim()
                        $sta_guid_subkeys = Get-ChildItem -Path "Registry::HKCR\CLSID\$rundll32_sta_guid"
                        foreach ($sta_guid_subkey in $sta_guid_subkeys) {
                            if ($sta_guid_subkey.Name -like "*procserver*" -or $sta_guid_subkey.Name -like "*localserver*") {
                                $binary = (Get-ItemProperty $sta_guid_subkey.PSPath).'(default)'
                            }
                        }
                    }
                    
                    $binary = $rundll_dll
                    #$binary = $rundll_parms[0]
                }
                


                if (!(Test-Path -Path "$binary")) {
                    $binary
                }


                
            }
        }
    }
}


