# RMLog
RMLog is a powershell script which it uses windows event logs to gather information about internal network in a pentration testing engagment. It is not only useful for blue teams but also for red teams because some of its functionalities can be used for lateral movement. You will be able to use RMLog not only on a localhost machine but also in a remote machine using WinRM protocol which is by default enabled in a newly Windows versions. 


## Usage

Use can use the following event types:

1) Information EventID (4624) - An account was successfully logged on
2) Information EventID (4625) - An account failed to log on
3) Information EventID (4728) - A member was added to a security-enabled global group 
4) Information EventID (4732) - A member was added to a security-enabled local group
5) Information EventID (4733) - A member was removed from a security-enabled local group
6) Information EventID (4738) - A user account was changed
7) Information EventID (4647) - User initiated logoff
8) Information EventID (4688) - A new process has been created
9) Information EventID (4776) - The domain controller attempted to validate the credentials for an account

### Examples

The RMLog searching into newest 10(default value) entries into all event types.

```
PS> RMLog -user <username> -pass <password> -ip <remote winrm ip>
PS> RMLog -user <username> -pass <password> -fips <file with ips>
PS> RMLog -ip 127.0.0.1
```

Search into specific eventID using -eventID parameter
```
PS> RMLog -user <username> -pass <password> -ip <remote winrm ip> -eventID <eventID>
PS> RMLog -user <username> -pass <password> -fips <file with ips> -eventID <eventID>
PS> RMLog -ip 127.0.0.1 -eventID <eventID> 
```

If you use -newest parameter then you will be able to search into a specific quantity of entries and in many cases your results will be more accurate.

```
PS> RMLog -user <username> -pass <password> -ip <remote winrm ip> -newest <number>
PS> RMLog -user <username> -pass <password> -fips <file with ips> -newest <number>
PS> RMLog -ip 127.0.0.1 -newest <number>
```

Providing the -users flag you will get as a result some valid usernames. The RMLog searches into these event IDs 4624,4625,4776 

```
PS> RMLog -user <username> -pass <password> -ip <remote winrm ip> -users
PS> RMLog -user <username> -pass <password> -fips <file with ips> -users
PS> RMLog -ip 127.0.0.1 -users
```

##Time Bomb 

TimeBomb is useful when you landed on a network host and you want to get a notification when the user is logged of and be able to use an RDP (Remote Desktop) connection. In the background function uses 4624,4647 events and search for current login users. You can create a timer without creating or editing windows schedules and leave the host untouched. You have 3 option when you create a timeBob:

1) now
2) once
3) trigger

Tip: Give as much as possible amount of entries in -newest parameter. For example: 5000

The task is going to run "now"
```
timeBomb -task now -ip 127.0.0.1 -newest <give a big number>
```


