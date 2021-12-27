# TecArt Server install script

Helps with quickly installing base dependencies and setting up the 
configuration of a server to use with the TecArt Business software.

You will need access to the TecArt Enterprise Repositories. To gain access please [contact your customer service representative](https://www.tecart.de/kontakt)

```
Usage: install.sh [-l LOGPATH] [--log-path LOGPATH] [--repo-user REPO-USER] [--repo-pass REPO-PASS] [--no-production-repo] (check|install)

Options:
-h, --help                  Display this usage message and exit
    --repo-user             Username for the Enterprise Repositories
    --repo-pass             Password for the Enterprise Repositories
-l, --log-path [DIR]        Write logs into given directory
    --no-production-repo    Force the use of untested repositories

Installer for the TecArt Business Software and all of it's dependencies.

This program is supposed to be run on a clean Debian 11 Installation. Please 
do not run this script on a server that has already been configured for other 
software!

Copyright (c) by TecArt GmbH, 2021
```
