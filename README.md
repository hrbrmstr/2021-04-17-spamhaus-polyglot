```
                                   888                             
 dP"Y 888 88e   ,"Y88b 888 888 8e  888 ee   ,"Y88b 8888 8888  dP"Y 
C88b  888 888b "8" 888 888 888 88b 888 88b "8" 888 8888 8888 C88b  
 Y88D 888 888P ,ee 888 888 888 888 888 888 ,ee 888 Y888 888P  Y88D 
d,dP  888 88"  "88 888 888 888 888 888 888 "88 888  "88 88"  d,dP  
      888                                                          
      888                           
```

Ref: [ISC Diary: Querying Spamhaus for IP reputation, Author: Rick Wanner](https://isc.sans.edu/diary/rss/27320)

Go, Swift, & R (mebbe more at some point) implementations of a command line tool to lookup IP reputation in Spamhaus.

Does ndjson if IPs are piped from stdin, otherwise does more human readable output.

```bash
$ cat test/ips | swift/spamhaus
{"code":"127.0.0.2","zone":"SBL","ip":"196.16.11.222","desc":"Spamhaus SBL Data"}
{"code":"127.0.0.9","zone":"SBL","ip":"196.16.11.222","desc":"Spamhaus DROP\/EDROP"}
{"code":"NA","zone":"NA","ip":"x","desc":"Not a valid IPv4 address"}
{"code":"nbl","zone":"NA","ip":"8.8.8.8","desc":"Not on any Spamhaus blocklist"}
```

```bash
$ golang/spamhaus 196.16.11.222 x 8.8.8.8
196.16.11.222 SBL Spamhaus SBL Data
196.16.11.222 SBL Spamhaus DROP/EDROP
x NA Not a valid IPv4 address
8.8.8.8 nbl Not on any Spamhaus blocklist
```

```
$ R/spamhaus.R 196.16.11.222 x 8.8.8.8
Warning message:
1 invalid IPv4 addresses in input.
             ip      code zone                          desc
1 196.16.11.222 127.0.0.2  SBL             Spamhaus SBL Data
2 196.16.11.222 127.0.0.9  SBL      Spamhaus DROP/EDROP Data
3       8.8.8.8       nbl <NA> Not on any Spamhaus blocklist
```