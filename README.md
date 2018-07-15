# RMLog
RMLog is a powershell script which it uses windows events logs to gather information about internal network in a pentration testing engagment. It is not only useful for blue teams but also for red teams because some of its functionalities can be used for lateral movement. You will be able to use RMLog not only on a localhost machine but also in a remote machine using WinRM protocol which is by default enabled in a newly Windows versions. 


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

The RMLog searching into newest 10(default value) entries in all event types.

```
PS> RMLog -user <username> -pass <password> -ip <host ip>
```
