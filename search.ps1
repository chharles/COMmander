# references:
# https://pentestlab.blog/2020/05/20/persistence-com-hijacking/
#   List of lots of different techniques
# good explanation of missing libraries use https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/

# Source : https://github.com/nccgroup/acCOMplice/blob/master/COMHijackToolkit/COMHijackToolkit.ps1
# TODO: build this out to deal with HKLM and HKCU as well
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

# added checks for rundll32.exes and recursive calls to check the writability of pathes given current user context
function Missing-Libraries {

    "========================================`nMissing Libraries`n========================================"
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
                # if the binary string is empty, move on to the next subkey...
                # TODO: This should be looked into
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
                                    New-Item -Path $path -Name "COMPermissionTest.txt" -ItemType "file" -Value "test" 2>$null| Out-Null
                                    Remove-Item -Path "$path\COMPermissionTest.txt" 2>$null | Out-Null
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

function Create-COM-Object($GUID, $binary, $CLSID_name) {
    if (!($GUID)) {
        return "GUID must be provided"
    }
    if (!($binary)) {
        return "binary must be provided"
    }
        
    #check if the binary for the target of the GUID exists
    if (!($GUID.contains("{"))) {
        $GUID = "{" + $GUID
    }
    if (!($GUID.contains("}"))) {
        $GUID = $GUID + "}"
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

    # check for the existence of the HKLM COM Object
    $HKCU_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID" -ErrorAction SilentlyContinue
    if ($HKCU_obj) {
        return "$GUID already exists in HKLM. Try a different GUID"
    }

    #Create a new COM Object
    New-Item -Path "HKCU:\Software\Classes\CLSID" -Name "$GUID" | Out-Null
    if ($CLSID_name) {
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name '(default)' -Value "$CLSID_name" | Out-Null
    }
    if ($dll) {
        # create the inprocserver32 subkey
        New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "InProcServer32" | Out-Null
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32" -Name '(default)' -Value "$binary" | Out-Null
        return "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32 set to $binary"
    } 
    elseif ($exe) {
        # create the inprocserver32 subkey
        New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "LocalServer32" | Out-Null
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32" -Name '(default)' -Value "$binary" | Out-Null
        return "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32 set to $binary"
    } else {
        "Something went wrong"
    }
}

function Modify-COM-Object-binary($GUID, $binary) {
    if (!($GUID)) {
        return "GUID must be provided"
    }
    if (!($binary)) {
        return "binary must be provided"
    }
        
    #check if the binary for the target of the GUID exists
    if (!($GUID.contains("{"))) {
        $GUID = "{" + $GUID
    }
    if (!($GUID.contains("}"))) {
        $GUID = $GUID + "}"
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

    # check for the existence of the HKLM COM Object
    $HKCU_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID" -ErrorAction SilentlyContinue
    if (!($HKCU_obj)) {
        return "$GUID does not exist in HKLM"
    }

    if ($dll) {
        # create the inprocserver32 subkey
        $HKCU_dll_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID\InProcServer32" -ErrorAction SilentlyContinue
        # if the InProcServer32 subkey does not exist, make it
        $old_dll_val = $False
        if (!($HKCU_dll_obj)) {
            New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "InProcServer32" | Out-Null
        } else {
            $old_dll_val = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$GUID\InProcServer32").'(default)'
        }
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32" -Name '(default)' -Value "$binary" | Out-Null
        if ($old_dll_val) {
            return "HKCU:\Software\Classes\CLSID\$GUID\InprocServer32 was present. InProcServer32 was changed from $old_dll_val to $binary"
        } else {
            return "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32 was created. InProcServer32 was set to $binary"
        }
    } 
    elseif ($exe) {
        # create the inprocserver32 subkey
        $HKCU_exe_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID\LocalServer32" -ErrorAction SilentlyContinue
        # if the InProcServer32 subkey does not exist, make it
        $old_exe_val = $False
        if (!($HKCU_exe_obj)) {
            New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "LocalServer32" | Out-Null
        } else {
            $old_exe_val = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$GUID\LocalServer32").'(default)'
        }
        Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32" -Name '(default)' -Value "$binary" | Out-Null
        if ($old_exe_val) {
            return "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32 was present. LocalServer32 was changed from $old_exe_val to $binary"
        } else {
            return "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32 was created. LocalServer32 was set to $binary"
        }
    } else {
        "Something went wrong"
    }
}

function Modify-COM-Object-remove-subkey($GUID, [Switch] $InProcServer32, [Switch] $LocalServer32, [Switch] $TreatAs) {

    if (!($GUID)) {
        return "GUID must be provided"
    }
        
    #check if the binary for the target of the GUID exists
    if (!($GUID.contains("{"))) {
        $GUID = "{" + $GUID
    }
    if (!($GUID.contains("}"))) {
        $GUID = $GUID + "}"
    }

    # check for the existence of the HKLM COM Object
    $HKCU_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID" -ErrorAction SilentlyContinue
    if (!($HKCU_obj)) {
        return "$GUID does not exist in HKLM"
    }

    if ($InProcServer32) {
        # check if the inprocserver32 subkey exists
        $HKCU_dll_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID\InProcServer32" -ErrorAction SilentlyContinue
        if (!($HKCU_dll_obj)) {
            return "InProcServer32 does not exist for $GUID"
        }
        #remove it
        Remove-Item "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32" -Recurse | Out-Null
        return "HKCU:\Software\Classes\CLSID\$GUID\InProcServer32 removed"
    } 
    elseif ($LocalServer32) {
        # check if the inprocserver32 subkey exists
        $HKCU_exe_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID\LocalServer32" -ErrorAction SilentlyContinue
        if (!($HKCU_exe_obj)) {
            return "InProcServer32 does not exist for $GUID"
        }
        Remove-Item "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32" -Recurse | Out-Null
        return "HKCU:\Software\Classes\CLSID\$GUID\LocalServer32 removed"
    } elseif ($TreatAs) {
        # check if the treatas subkey exists
        $HKCU_treatas_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID\TreatAs" -ErrorAction SilentlyContinue
        if (!($HKCU_treatas_obj)) {
            return "InProcServer32 does not exist for $GUID"
        }
        Remove-Item "HKCU:\Software\Classes\CLSID\$GUID\TreatAs" -Recurse | Out-Null
        return "HKCU:\Software\Classes\CLSID\$GUID\Treatas removed"
    } else {
        "Something went wrong"
    }
}

function Modify-COM-Object-add-TreatAs($GUID, $target_GUID) {
    if (!($GUID)) {
        return "GUID must be provided"
    }
    if (!($target_GUID)) {
        return "treatas GUID must be provided"
    }
        
    if (!($GUID.contains("{"))) {
        $GUID = "{" + $GUID
    }
    if (!($GUID.contains("}"))) {
        $GUID = $GUID + "}"
    }

    if (!($target_GUID.contains("{"))) {
        $target_GUID = "{" + $target_GUID
    }
    if (!($target_GUID.contains("}"))) {
        $target_GUID = $target_GUID + "}"
    }

    # check for the existence of the HKLM COM Object
    $HKCU_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID" -ErrorAction SilentlyContinue
    if (!($HKCU_obj)) {
        return "$GUID does not exist in HKCU"
    }

    # check for the existence of the TreatAs subkey
    $HKCU_treatas_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$GUID\TreatAs" -ErrorAction SilentlyContinue
    # if the TreatAs subkey does not exist, make it
    $old_TreatAs_val = $False
    if (!($HKCU_treatas_obj)) {
        New-Item -Path "HKCU:\Software\Classes\CLSID\$GUID" -Name "TreatAs" | Out-Null
    } else {
        $old_TreatAs_val = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$GUID\TreatAs").'(default)'
    }
    Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$GUID\TreatAs" -Name '(default)' -Value "$target_GUID" | Out-Null
    if ($old_TreatAs_val) {
        return "HKCU:\Software\Classes\CLSID\$GUID\TreatAs was present. TreatAs was changed from $old_TreatAs_val to $target_GUID"
    } else {
        return "HKCU:\Software\Classes\CLSID\$GUID\TreatAs was created. TreatAs was set to $target_GUID"
    }
}

function Find-All-Suspicious-COM-Objects {
    $Paths = [System.Collections.ArrayList]@() 
    $Paths.Add("Registry::HKCR\CLSID") | Out-Null
    $Paths.Add("Registry::HKLM\Software\Classes\CLSID") | Out-Null
    $Paths.Add("Registry::HKCU\Software\Classes\CLSID") | Out-Null


    # grab all of the objects
    $COM_Objects = [System.Collections.ArrayList]@()
    foreach ($path in $Paths) {
        foreach ($obj in Get-ChildItem -Path $path) {
            $COM_Objects.Add($obj) | Out-Null
        }
    }
    foreach ( $obj in $COM_Objects ) {
        #$obj.Name # HKEY_CLASSES_ROOT\CLSID\{FD215A13-A26A-44FF-BA3A-9109F278E28F}
        $guid = ($obj.Name).Split('\')[-1]
        $hasexe = $False
        $hasdll = $False
        $hkcr_clsid_name = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$guid").'(default)'
        # Check if there is a dll or executable in InProcServer32 or LocalServer32 subkeys, respectively
        $hkcr_dll_path = ""
        $hkcr_exe_path = ""
        $dll_obj = Get-Item -LiteralPath "Registry::HKCR\CLSID\$guid\InProcServer32" -ErrorAction SilentlyContinue
        $exe_obj = Get-Item -LiteralPath "Registry::HKCR\CLSID\$guid\LocalServer32" -ErrorAction SilentlyContinue
        if ($dll_obj){
            $hkcr_dll_path = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$guid\InProcServer32").'(default)'
            $hasdll = $True
        }
        if ($exe_obj) {
            $hkcr_exe_path = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$guid\LocalServer32").'(default)' # this was not included
            $hasexe = $True
        }

        $hkcu_dll_path = ""
        $hkcu_exe_path = ""
        $hkcu_clsid_name = ""
        $InHKCU = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$guid" -ErrorAction SilentlyContinue 
        if ($InHKCU) {
            $InHKCU = $True
            $hkcu_clsid_name = (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$guid").'(default)'
            $dll_obj = Get-Item -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$guid\InProcServer32" -ErrorAction SilentlyContinue 
            $exe_obj = Get-Item -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$guid\LocalServer32" -ErrorAction SilentlyContinue 
            if ($dll_obj){
                $hkcu_dll_path = (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$guid\InProcServer32").'(default)' 
                $hasdll = $True
            }
            if ($exe_obj) {
                $hkcu_exe_path = (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$guid\LocalServer32").'(default)'
                $hasexe = $True
            }
        } else {
            $InHKCU = $False
        } 

        $hklm_dll_path = ""
        $hklm_exe_path = ""
        $hklm_clsid_name = ""
        $InHKLM = Get-Item -path "Registry::HKLM\Software\Classes\CLSID\$guid" -ErrorAction SilentlyContinue
        if ($InHKLM) {
            $InHKLM = $True
            $hklm_clsid_name = (Get-ItemProperty -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$guid").'(default)'
            $dll_obj = Get-Item -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$guid\InProcServer32" -ErrorAction SilentlyContinue 
            $exe_obj = Get-Item -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$guid\LocalServer32" -ErrorAction SilentlyContinue 
            if ($dll_obj){
                $hklm_dll_path = (Get-ItemProperty -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$guid\InProcServer32").'(default)' 
                $hasdll = $True
            }
            if ($exe_obj) {
                $hklm_exe_path = (Get-ItemProperty -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$guid\LocalServer32").'(default)' 
                $hasexe = $True
            }
        } else {
            $InHKLM = $False
        } 

        # add treatas search

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'HKCR_CLSID_Name' $hkcr_clsid_name
        $Out | Add-Member Noteproperty 'HKLM_CLSID_Name' $hklm_clsid_name 
        $Out | Add-Member Noteproperty 'HKCU_CLSID_Name' $hkcu_clsid_name
        $Out | Add-Member Noteproperty 'CLSID' $guid
        $Out | Add-Member NoteProperty 'has_dll' $hasdll
        $Out | Add-Member Noteproperty 'HKCR_dll' $hkcr_dll_path
        $Out | Add-Member Noteproperty 'HKLM_dll' $hklm_dll_path
        $Out | Add-Member Noteproperty 'HKCU_dll' $hkcu_dll_path
        $Out | Add-Member NoteProperty 'has_exe' $hasexe
        $Out | Add-Member Noteproperty 'HKCR_exe' $hkcr_exe_path
        $Out | Add-Member Noteproperty 'HKLM_exe' $hklm_exe_path
        $Out | Add-Member Noteproperty 'HKCU_exe' $hkcu_exe_path
        $Out | Add-Member Noteproperty 'InHKCU' $InHKCU
        $Out | Add-Member Noteproperty 'InHKLM' $InHKLM
        #$Out | Add-Member Noteproperty 'has_TreatAs' $has_treatas


        # suspicious. implies that the HKLM value is being overwritten by HKCU
        if ($Out.InHKLM -and $Out.InHKCU) {
            "`n!!!!! WARNING !!!!!`n$guid is defined in HKLM AND HKCU"
            "HKLM CLSID Name: " + $Out.HKLM_CLSID_Name
            "HKCU CLSID Name: " + $Out.HKCU_CLSID_Name
            if ($Out.has_exe) {
                "HKLM binary: " + $Out.HKLM_exe
                "HKCU binary: " + $Out.HKCU_exe
            } elseif ($Out.has_dll) {
                "HKLM binary: " + $Out.HKLM_dll
                "HKCU binary: " + $Out.HKCU_dll
            }
            "`n"
        }

        # Could be an indication of user persistence  
        if ($Out.InHKCU -and !($Out.InHKLM)) {
            "`n!!!!! WARNING !!!!!`n$guid is defined in HKCU AND NOT HKLM"
            "HKCU CLSID Name: " + $Out.HKCU_CLSID_Name
            if ($Out.has_exe) {
                "HKCU binary: " + $Out.HKCU_exe
            } elseif ($Out.has_dll) {
                "HKCU binary: "+ $Out.HKCU_dll
            }
            "`n"
        }

    }
}

function Remove-COM-Object($GUID) {
    #check if the binary for the target of the GUID exists
    if (!($GUID)) {
        return "GUID must be provided"
    }

    if (!($GUID.contains("{"))) {
        $GUID = "{" + $GUID
    }
    if (!($GUID.contains("}"))) {
        $GUID = $GUID + "}"
    }

    # check for the existence of the HKLM COM Object
    $HKCU_obj = Get-Item -path Registry::HKCU\Software\Classes\CLSID\$GUID -ErrorAction SilentlyContinue
    if (!($HKCU_obj)) {
        return "$GUID does not exist in HKLM"
    }
    Remove-Item "HKCU:\Software\Classes\CLSID\$GUID" -Recurse | Out-Null
    return "HKCU:\Software\Classes\CLSID\$GUID removed"
}

#inspired by https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Get-ScheduledTaskComHandler.ps1
# added the capability to search for exes (localserver32) in addition to dlls
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
    
    "========================================`nHijackackable Scheduled Tasks`n========================================"

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
            $dll_obj = Get-Item -LiteralPath "Registry::HKCR\CLSID\$COM\InProcServer32" -ErrorAction SilentlyContinue
            $exe_obj = Get-Item -LiteralPath "Registry::HKCR\CLSID\$COM\LocalServer32" -ErrorAction SilentlyContinue

            if ($dll_obj){
                $dll = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$COM\InProcServer32").'(default)'
            }
            if ($exe_obj) {
                $exe = (Get-ItemProperty -LiteralPath "Registry::HKCR\CLSID\$COM\LocalServer32").'(default)' # this was not included
            }

            $InHKLM = $False
            $InHKCU = $False
            if ($dll_obj) {
                $HKLM_dll_obj = Get-Item -path "Registry::HKLM\Software\Classes\CLSID\$COM\InProcServer32" -ErrorAction SilentlyContinue
                if ($HKLM_dll_obj){
                    $InHKLM = $True
                }
                $HKCU_dll_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$COM\InProcServer32" -ErrorAction SilentlyContinue
                if ($HKCU_dll_obj) {
                    $InHKCU = $True
                }
            }
            if ($exe_obj) {
                $HKLM_exe_obj = Get-Item -path "Registry::HKLM\Software\Classes\CLSID\$COM\LocalServer32" -ErrorAction SilentlyContinue
                if ($HKLM_exe_obj) {
                    $InHKLM = $True
                }
                $HKCU_exe_obj = Get-Item -path "Registry::HKCU\Software\Classes\CLSID\$COM\LocalServer32" -ErrorAction SilentlyContinue
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

        # suspicious. implies that the HKLM value is being overwritten by HKCU
        if ($InHKLM -and $InHKCU) {
            "`n!!!!! WARNING !!!!!`n$COM is defined in HKLM AND HKCU"
            if ($exe_obj) {
                "HKLM binary: " + (Get-ItemProperty -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$COM\LocalServer32").'(default)' 
                "HKCU binary: " + (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$COM\LocalServer32").'(default)' 
            } else {
                "HKLM binary: " + (Get-ItemProperty -LiteralPath "Registry::HKLM\Software\Classes\CLSID\$COM\InProcServer32").'(default)' 
                "HKCU binary: " + (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$COM\InProcServer32").'(default)' 
            }
            "`n"
        }

        # Could be an indication of user persistence  
        if ($InHKCU -and !($InHKLM)) {
            "`n!!!!! WARNING !!!!!`n$COM is defined in HKCU AND NOT HKLM"
            if ($exe_obj) {
                "HKCU binary: " + (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$COM\LocalServer32").'(default)' 
            } else {
                "HKCU binary: " + (Get-ItemProperty -LiteralPath "Registry::HKCU\Software\Classes\CLSID\$COM\InProcServer32").'(default)' 
            }
            "`n"
        }
    }
}

# consider adding HKLM and HKCU
function Get-All-TreatAs-Objects {
    $HKCR_CLSID_Subkeys = Get-RegistrySubkeys
    foreach ($key in $HKCR_CLSID_Subkeys) {
        $Subkey = Get-Item -Path "Registry::$key"
        if ($Subkey.Name -like "*treatas*") {
            Write-Output $Subkey.Name
        }     
    } 
}

function Check-All-TreatAs-Objects {
    # search for COM objects with TreatAS key
    "========================================`nCheck All TreatAs Objects`n========================================"

    $all_treatas_targets = @{}
    $All_TreatAs_Objects = Get-All-TreatAs-Objects
    foreach ($obj_name in $All_TreatAs_Objects) {
        $obj = Get-Item -path "Registry::$obj_name" 
        $treatas_target = (Get-ItemProperty $obj.PSPath).'(default)'
        if ($all_treatas_targets.containskey($treatas_target)) {
            ($all_treatas_targets[$treatas_target]).Add($obj_name) | Out-Null
        } else {
            $all_treatas_targets[$treatas_target] = [System.Collections.ArrayList]@()
            ($all_treatas_targets[$treatas_target]).Add($obj_name) | Out-Null
        }
    }
    foreach ($target in $all_treatas_targets.Keys) {
        # TODO: Consider adding for both HKLM and HKCU, to compare the values contained within them
        $referers = $all_treatas_targets[$target]
        # check if it exists
        $HKCR_CLSID_exists = $False
        $HKCR_obj = Get-Item -path Registry::HKCR\CLSID\$target -ErrorAction SilentlyContinue
        if ($HKCR_obj){
            $HKCR_CLSID_exists = $True
        }
        if (!($HKCR_CLSID_exists)) {
            "`n!!!!! WARNING !!!!!`n$target does not exist and is referenced by $referers"
            "Hijack this is you want to be ESPECIALLY sneaky`n"
            continue
        }
        $target_subkeys = Get-ChildItem -Path "Registry::HKCR\CLSID\$target"
        foreach ($subkey in $target_subkeys) {
            if ($subkey.Name -like "*procserver*" -or $subkey.Name -like "*localserver*") {
                # grab the binary associated with the subkey
                $guid = ($subkey.Name).Split('\')[2]
                $binary = (Get-ItemProperty $subkey.PSPath).'(default)'
                if (!$binary) {
                    continue
                }
                # check if the binary exists
                $binary =  "$binary".replace('"','')
                
                foreach ($referer in $referers) {
                    $referer
                }
                "all redirect to $binary ($guid)`n"
            }
        }
    }
}


#Heavily referenced: https://github.com/nccgroup/acCOMplice/blob/master/COMHijackToolkit/COMHijackToolkit.ps1
function Missing-COM-Objects($CSV) {
    if (!($CSV)) {
        return "CSV file exported from procmon must be provided"
    }
    if (!(Test-Path -Path "$CSV")) {
        return "`"$CSV`" does not exist - check the path"
    }

    "========================================`nMissing COM Objects`n========================================"

    $Entries = Get-Content $CSV | ConvertFrom-Csv
    $proc_to_GUID = @{}
    foreach ($entry in $Entries) {
        $proc_name = $entry.'Process Name'
        $missing_path = $entry.'Path'
        $guid = $missing_path.Split('\')[-2]
        if ($proc_to_GUID.contains($proc_name)){
            ($proc_to_GUID[$proc_name]).Add($guid) | Out-Null
        } else {
            $proc_to_GUID[$proc_name] = [System.Collections.ArrayList]@() 
            ($proc_to_GUID[$proc_name]).Add($guid) | Out-Null
        }
    }
    foreach ($entry in $proc_to_GUID.Keys) {
        "`n$entry tries to use"
        $proc_to_GUID[$entry] | Sort-Object -Unique
    }
}


function capture-csv($procmon_path, $backingfile_path, $csvfile_path, $time_to_run) { 

    if (!(Test-Path -Path "$procmon_path")) {
        return "`"$procmon_path`" does not exist - check the path"
    }
    $backingfile_ext = ($backingfile_path).Split('.')[-1]
    if (!($backingfile_ext -like "*pml*")) {
        return "`"$backingfile_path`" must end with '.pml'"
    }
    $csvfile_ext = ($csvfile_path).Split('.')[-1]
    if (!($csvfile_ext -like "*csv*")) {
        return "`"$csvfile_path`" must end with '.csv'"
    }
	# start procmon via powershell
	start-process -filepath "$procmon_path" -argumentlist "/accepteula /quiet /minimized /backingfile $backingfile_path" -Passthru | out-null
	
	if (!($time_to_run)) {
		$time_to_run = 6
	}
	Start-Sleep -Seconds $time_to_run
	#end procmon via powershell
	start-process -filepath "$procmon_path" -argumentlist "/terminate" -wait
    Start-Sleep -Seconds 1
	#convert pmc file into csv
	start-process -filepath "$procmon_path" -argumentlist "/SaveApplyFilter /OpenLog $backingfile_path /SaveAs1 $csvfile_path"
}

function check-for-missing-com-objects ($procmon_path, $backingfile_path, $csvfile_path, $time_to_run) {
    capture-csv $procmon_path $backingfile_path $csvfile_path $time_to_run
    Missing-COM-Objects($csvfile_path)
}