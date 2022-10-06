echo "secedit setting"
echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "[System Access]" | Out-File -FilePath .\test.inf
Add-Content -Path test.inf -Value "MinimumPasswordAge = 1"
Add-Content -Path test.inf -Value "MaximumPasswordAge = 90"
Add-Content -Path test.inf -Value "MinimumPasswordLength = 8"
Add-Content -Path test.inf -Value "LockoutBadCount = 5"
Add-Content -Path test.inf -Value "ResetLockoutCount = 60"
Add-Content -Path test.inf -Value "LockoutDuration = 60"
Add-Content -Path test.inf -Value "[Registry Values]"
Add-Content -Path test.inf -Value "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,0"
Add-Content -Path test.inf -Value "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM=4,1"
Add-Content -Path test.inf -Value 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0"'
Add-Content -Path test.inf -Value "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1"
Add-Content -Path test.inf -Value "[Privilege Rights]"
Add-Content -Path test.inf -Value "SeInteractiveLogonRight = *S-1-5-32-544"
Add-Content -Path test.inf -Value "[Version]"
Add-Content -Path test.inf -Value 'signature="$CHICAGO$"'
Add-Content -Path test.inf -Value "Revision=1"

secedit /configure /db test.sdb /cfg test.inf
secedit /export /cfg securitypolicy.txt

Select-String "MinimumPasswordAge" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1
Select-String "MinimumPasswordLength" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1
Select-String "PasswordHistorySize" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1
Select-String "LockoutBadCount" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1
Select-String "ResetLockoutCount" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1
Select-String "LockoutDuration" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1
Select-String "SeInteractiveLogonRight" securitypolicy.txt | foreach{$_.line} >> ./$env:computername.txt 2>&1

del ".\test.sdb"
del ".\test.inf"
del ".\securitypolicy.txt"
echo "secedit setting end"

echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-04,47,49,51,55 account set"

$check_list = @("MinimumPasswordAge", "MaximumPasswordAge", "MinimumPasswordLength", "PasswordHistorySize","LockoutBadCount", "ResetLockoutCount", "LockoutDuration", "SeInteractiveLogonRight")

$check_value = 1,90,8,4,5,60,60,"*S-1-5-32-544"

$w_num = "W-51","W-50","W-49","W-55","W-04","W-47","W-47","W-53"

for($index = 0; $index -lt $check_list.Length; $index++){
	$temp = findstr $check_list[$index] ./$env:computername.txt
	if (-Not $temp){
		$value_of_list += "not $index"
	}
	else{
		$value_of_list += $temp.Replace(" ", "").split("=").Get(1)
	}
	$value_of_list += "/"
}

for($index = 0; $index -lt $check_value.Length; $index++){
	if ($check_value.Get($index) -eq ($value_of_list.split("/").Get($index))){
		$check_list[$index]
		echo "success"
	}
	else{
		$check_list[$index]
		$w_num[$index]
		echo "failed"
	}
}
echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-08 HDD autoshare"

net share C$ /delete
net share D$ /delete
net share ADMIN$ /delete

$AutoShareServerValue = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters  -Name AutoShareServer
if ( -Not $AutoShareServerValue ){
	New-ItemProperty  -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareServer -PropertyType DWORD -Value 0
}
else{
	Set-ItemProperty  -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -Name AutoShareServer -PropertyType DWORD -Value 0
}

$AutoShareServerValue = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters  -Name AutoShareServer

echo "AutoShareServer, $AutoShareServerValue"

if ($AutoShareServerValue -eq 0){
	echo "HDD autoshare success"	
}else{
	echo "HDD autoshare failed"	
}

echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-24 NetBIOS binding"
wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" call SetTcpipNetbios 2

$NetbiosOptions = wmic nicconfig where "TcpipNetbiosOptions<>null and ServiceName<>'VMnetAdapter'" get TcpipNetbiosOptions | findstr 2

echo "NetbiosOptions : $NetbiosOptions"
if ([int]$NetbiosOptions -eq 2)  {
	echo "NetBIOS Binding success"
}
else
{
	echo "NetBIOS Binding failed"
}
echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-38 ScreenSave"

Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value 1
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -Value 1
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveTimeOut' -Value 600


$ScreenSaveActive = Get-ItemPropertyValue -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive
$ScreenSaverIsSecure = Get-ItemPropertyValue -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure
$ScreenSaveTimeOut = Get-ItemPropertyValue -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut

echo "ScreenSaveActive, $ScreenSaveActive"
echo "ScreenSaverIsSecure, $ScreenSaverIsSecure"
echo "ScreenSaveTimeOut, $ScreenSaveTimeOut"

if ($ScreenSaveActive -eq 1 -and $ScreenSaverIsSecure -eq 1 -and $ScreenSaveTimeOut -eq 600){
	echo "ScreenSaveActive success"	
}
else
{
	echo "ScreenSaveActive failed"
}

echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-42 RestrictAnonymous SAM"
#Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name 'RestrictAnonymousSAM' -Value 1
#Set-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name 'RestrictAnonymous' -Value 0

$RestrictAnonymousSAM = Get-ItemPropertyValue -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name RestrictAnonymousSAM
$RestrictAnonymous = Get-ItemPropertyValue -Path HKLM:\System\CurrentControlSet\Control\Lsa\ -Name RestrictAnonymous

echo "RestrictAnonymousSAM, $RestrictAnonymousSAM"
echo "RestrictAnonymous, $RestrictAnonymous"

if ($RestrictAnonymousSAM -eq 1 -and $RestrictAnonymous -eq 0){
	echo "SAM success"	
}
else
{
	echo "SAM failed"
}
echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-44 AllocateDASD"

#Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateDASD' -Value 0

$AllocateDASD = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AllocateDASD'

echo "AllocateDASD, $AllocateDASD"

if ($AllocateDASD -eq 0) {
	echo "AllocateDASD success"	
}
else
{
	echo "AllocateDASD failed"
}
echo "-------------------------------------------------------------------------------------"
echo "-------------------------------------------------------------------------------------"
echo "w-52 DontDisplayLastUserName"

$DontDisplayLastUserName = Get-ItemPropertyValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ -Name 'DontDisplayLastUserName'

echo "DontDisplayLastUserName, $DontDisplayLastUserName"

if ($DontDisplayLastUserName -eq 1) {
	echo "DontDisplayLastUserName success"	
}
else
{
	echo "DontDisplayLastUserName failed"
}

del ./$env:computername.txt

