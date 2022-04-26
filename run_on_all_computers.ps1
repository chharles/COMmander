#Check if domain
$InDomain = Get-ADDomain 
$Path_to_Script = ""

if ($InDomain) {
	#Grab all computers
	$Computers = (Get-ADComputer -Filter 'OperatingSystem -like "*Windows*"' -Properties OperatingSystem)

	foreach ($computer in $Computers) {
        $Outfile_path = $Computer.Name
		Invoke-Command -ComputerName $Computer.DNSHostName -FilePath C:\Users\Administrator\Desktop\script.ps1 2>$null | Out-File -FilePath ".\$Outfile_path.txt"
	}
}