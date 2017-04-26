# Hyrad

A simple tool to implement RADIUS protocol, and provide command line options to brute force authentication via RADIUS protocol.

HYdra for RADius (not related to the much more powerful hydra. just an admirer)

```
./hyrad.py -h

usage: hyrad.py [-h] [-P PORT] [-u USER] [--userlist USERLIST] [-p PASSWORD]
                [--passlist PASSLIST] -s SECRET [-t THREAD]
                IP

Hyrad - v0.2
An utility tool to brute force authentication service using Radius protocol.

positional arguments:
  IP                    Required. The IP address where the radius service is
                        running

optional arguments:
  -h, --help            show this help message and exit
  -P PORT, --port PORT  The port of the radius service. Default 1812
  -u USER, --username USER
                        The username to be used.
  --userlist USERLIST   The list of users to be used.
  -p PASSWORD, --password PASSWORD
                        The list of password to be used.
  --passlist PASSLIST   The list of passwords to be tried.
  -s SECRET, --secret SECRET
                        Required. The shared secret to be used
  -t THREAD, --thread THREAD
                        The number of threads to be used. Default 4
```

## Sample usage

```
./hyrad.py 192.168.1.191 -u admin --passlist /path/to/passwords.txt -s $ALTm3 -t 10
./hyrad.py -p2812 --userlist /path/to/users.txt -p Password1 -s my$ecretT0ken 192.168.1.191
```