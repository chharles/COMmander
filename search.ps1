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
            "$($val) may be vulnerable to COM Hijacking"
        }
    }
    
}


