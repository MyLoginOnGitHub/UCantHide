# UCantHide

__UCantHide__ is an open source application used to __detect anomalies__ in linux __authorization log files__ such as /var/log/auth.log, /var/log/lastlog and etc...  
This anomalies could happens if someone has __illegal access__ to your system and used some __techniques to clean authorisation logs__.

__List of detection techniques:__  
* Find sessions in auth.log which was closed but has never been opened.
> This anomaly could happens if an attacker has authenticated by ssh, and has cleaned auth.log. Then an attacker logout, hence the record 'session closed' has appeared in the log file.
