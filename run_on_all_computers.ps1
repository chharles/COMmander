#Check if domain
$InDomain = Get-ADDomain 
$Path_to_Script = ""

if ($InDomain) {
	#Grab all computers
	$Computers = (Get-ADComputer -Filter 'OperatingSystem -like "*Windows*"' -Properties OperatingSystem)

	foreach ($computer in $Computers) {
		Invoke-Command -ComputerName $Computer.DNSHostName -FilePath $Path_to_Script 2>$null
	}
}