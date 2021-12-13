#!/bin/bash
#
# Installer for the TecArt Business Software and all of it's dependencies.
#
# This program is supposed to be run on a clean Debian 10 Installation. Please 
# do not run this script on a server that has already been configured for other 
# software!
#
# Copyright (c) by TecArt GmbH, 2021

set -euo pipefail
exec 4>&2
exec 3>&1

if [ "$EUID" -ne 0 ]
  then echo "Please run this script as root"
  exit
fi

export PATH=$PATH:/usr/sbin

ACTION=""
repo_user=""
repo_pass=""
RELEASE=v52_80
LOG_PATH=/var/log/tecart
mkdir -p "$LOG_PATH"
MEMORY=$(($(awk '/^MemTotal:/{print $2}' /proc/meminfo)/1024))

PROGNAME=$(basename $0)
die() {
    echo "$PROGNAME: $*" >&2
    exit 1
}
usage() {
    if [ "$*" != "" ] ; then
        echo -e "\e[31m\e[1m[Error]\e[0m $*\n"
    fi
    local yll='\e[33m'
    local rst='\e[39m'
    echo -e "$(cat << EOF
Usage: $PROGNAME [-l LOGPATH] [--log-path LOGPATH] [--repo-user REPO-USER] [--repo-pass REPO-PASS] (check|install)

Options:
-h, --help            Display this usage message and exit
    --repo-user       Username for the Enterprise Repositories
    --repo-pass       Password for the Enterprise Repositories
-l, --log-path [DIR]  Write logs into given directory

Installer for the TecArt Business Software and all of it's dependencies.

${yll}This program is supposed to be run on a clean Debian 10 Installation. Please 
do not run this script on a server that has already been configured for other 
software!${rst}

Copyright (c) by TecArt GmbH, 2021
EOF
)"
    exit 1
}

while [ $# -gt 0 ] ; do
    case "$1" in
    -h|--help)
        usage
        ;;
    --repo-user)
        repo_user="$2"
        shift
        ;;
    --repo-pass)
        repo_pass="$2"
        shift
        ;;
    -l|--log-path)
        LOG_PATH="$2"
        shift
        ;;
    -*)
        usage "Unknown option '$1'"
        ;;
    *)
        if [ -z "$ACTION" ]; then
            ACTION="${1:-}"
        else
            usage "Too many arguments"
        fi
        ;;
    esac
    shift
done

if [ -z "$ACTION" ]
then
    usage "No action specified"
    exit 1
fi

if [ -z "$LOG_PATH" ]
then
    usage "Log Path is empty!"
    exit 1
fi

if [ -f "/etc/tecart-installer-version" ] && [ "$(wc -c /etc/tecart-installer-version)" -gt 0 ]
then
    die "It looks like this installer ran already!"
fi

if [ -z "$repo_user" ]
then
    read -p "TecArt Enterprise Repository User: " repo_user 1>&3
fi

if [ -z "$repo_pass" ]
then
    read -p "TecArt Enterprise Repository Password: " repo_pass
fi

# TODO: Ask for proxy settings

repo_test=0
if ! wget -q -O/dev/null https://${repo_user}:${repo_pass}@customer.mirror.tecart.de/
then
    echo "Could not connect to TecArt Enterprise Repository"
    exit 1
else
    repo_test=1
fi

if [ "$repo_test" -eq 1 ] && [ "$(lsb_release -is)" == "Debian" ] && \
    [ "$(lsb_release -rs)" = "10" ]
then
    echo "Enterprise repository is available and system running on Debian 10"
    if [ "$ACTION" = "check" ]
    then
        exit 0
    fi
else
    echo "Could not confirm that enterprise repository is available and system running on Debian 10"
    exit 1
fi

# /proc/meminfo sometimes reports a little bit less than actually installed, 
# so we give some headroom here to the actual 2G
if [ "$MEMORY" -lt 1900 ]
then
    echo "System reports to only have ${MEMORY}MiB of RAM. Minimum requirement is 2048MiB"
    exit 1
fi

#
# Actual installation ahead
# Logs will be written to $LOG_PATH
#
{
echo "Debug log will be written in $LOG_PATH" >&3
echo "Updating apt config" >&3

cat << EOL > /etc/apt/auth.conf.d/tecart.conf
machine customer.mirror.tecart.de
 login ${repo_user}
 password ${repo_pass}
EOL

apt update
apt install -y apt-transport-https dirmngr wget pwgen debconf

cat << EOL > /etc/apt/sources.list
deb https://customer.mirror.tecart.de/ftp.de.debian.org/debian/ bullseye main contrib non-free
deb https://customer.mirror.tecart.de/security.debian.org/debian-security bullseye-security main contrib non-free
deb https://customer.mirror.tecart.de/ftp.de.debian.org/debian/ bullseye-updates main contrib non-free
EOL

cat <<<EOL > /etc/apt/sources.list.d/tecart-bullseye.sources
Types: deb
URIs: https://customer.mirror.tecart.de/repo.tecart.de/apt/debian/
Suites: bullseye
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/tecart-archive-keyring.gpg
EOL

cat <<<EOL > /etc/apt/sources.list.d/tecart-php8.sources
Types: deb
URIs: https://customer.mirror.tecart.de/packages.sury.org/php/
Suites: bullseye
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/sury-archive-keyring.gpg
EOL

wget -O /usr/share/keyrings/tecart-archive-keyring.gpg https://repo.tecart.de/tecart-archive-keyring.gpg
wget -O /usr/share/keyrings/sury-archive-keyring.gpg https://packages.sury.org/php/apt.gpg

apt-get update

echo "Installing dependencies. This might take a while..." >&3
apt install -y tecart-archive-keyring tecart-essentials-server-5.2

echo "Configuring timezone and locale" >&3
echo "Europe/Berlin" > /etc/timezone
dpkg-reconfigure -f noninteractive tzdata
sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' \
       -e 's/# de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
echo 'LANG="de_DE.UTF-8"'>/etc/default/locale
dpkg-reconfigure --frontend=noninteractive locales
update-locale LANG=de_DE.UTF-8

echo "Updating system settings" >&3
echo 'vm.swappiness=0' >> /etc/sysctl.d/90-tecart.conf

echo "Installing atd fix" >&3
set +H
test -f /etc/rc.local || echo -e "#!/bin/sh\n\nfor i in \`atq | awk '{print \$1}'\`;do atrm \$i;done\n\nexit 0" > /etc/rc.local
grep 'atrm' /etc/rc.local || sed -i "s/exit 0/for i in \`atq | awk '{print \$1}'\`;do atrm \$i;done\n\nexit 0/" /etc/rc.local
chmod +x /etc/rc.local

echo "Configuring clamav" >&3
sed -i -e 's:LocalSocketGroup clamav:LocalSocketGroup www-data:' -e 's:User clamav:User www-data:' /etc/clamav/clamd.conf
sed -i -e 's:create 640  clamav adm:create 640  www-data adm:' /etc/logrotate.d/clamav-daemon
chown www-data.clamav /var/log/clamav/clamav.log
service clamav-freshclam stop
freshclam
service clamav-daemon restart
service clamav-freshclam restart

echo "Configuring MariaDB" >&3
MYSQLMEMORY=$(($MEMORY/10*4))
MYSQLCONNECTIONS=$(($MEMORY/5))

cat <<MYSQLCONF > /etc/mysql/mariadb.conf.d/tecart.cnf
[client]
default-character-set = utf8
 
[mysqld]
tmpdir = /data/tmp/
character-set-server  = utf8
collation-server      = utf8_general_ci
character_set_server   = utf8
collation_server       = utf8_general_ci
 
skip-external-locking
skip-name-resolve
 
default_storage_engine = InnoDB
 
key_buffer_size        = 1M
max_allowed_packet     = 64M
table_cache            = 1024
sort_buffer_size       = 4M
net_buffer_length      = 8K
read_buffer_size       = 4M
read_rnd_buffer_size   = 4M
thread_cache_size      = $MYSQLCONNECTIONS                # etwa 1 pro aktiver, 
                                            # gleichzeitiger Nutzer
 
max_connections        = $MYSQLCONNECTIONS                # Max. Verbindungen, etwa 1 - 2 je
                                            # aktiver Nutzer; etwa 5 bei Verwendung
                                            # persistenter Verbindungen
open_files_limit       = 16384
tmp_table_size         = 64M
max_heap_table_size    = 64M
table_definition_cache = 20480
 
connect_timeout        = 30
wait_timeout           = 300
max_connect_errors     = 10000000
 
join_buffer_size       = 1M
 
# ACHTUNG: Bei grossen Lasten sollte der Query Cache mit 
# 'query_cache_size = 0' deaktiviert werden
query_cache_limit      = 4M                 # Max. Grösse eines gecacheten 
                                            # Queries
query_cache_size       = 128M               # Gesamtgrösse des Querycaches
                                            # ~5 - 10% des RAM, maximal 128M
query_cache_type       = 1
query_prealloc_size    = 16384
query_alloc_block_size = 16384
 
# INNODB PERFORMANCE
innodb_buffer_pool_size         = $MYSQLMEMORY        # Maximal ~40% des RAM
innodb_log_buffer_size          = 8M
innodb_log_file_size            = 256M      # Nach Änderung dieses Wertes
                                            # müssen die alten logfiles 
                                            # gelöscht werden
innodb_log_files_in_group       = 2
innodb_flush_log_at_trx_commit  = 2
innodb_flush_method             = O_DIRECT
innodb_file_per_table                       # Erstellt pro Tabelle eine Datei
                                            # anstatt alles in einer grossen 
                                            # Datei zu speichern
innodb_thread_concurrency       = 8
 
long_query_time                = 2
log_error                      = /var/log/mysql/mysql.err
slow_query_log                 = 1
slow_query_log_file            = /var/log/mysql/mysql-slow.log
 
old_passwords = false
 
log_bin                 = /var/log/mysql/mysql-bin.log
expire_logs_days        = 3
max_binlog_size         = 1024M
 
low_priority_updates    = 1
 
[mysqldump]
quick
max_allowed_packet = 64M
 
[mysql]
no-auto-rehash
 
[isamchk]
key_buffer = 256M
sort_buffer_size = 256M
read_buffer = 2M
write_buffer = 2M
 
[myisamchk]
key_buffer = 256M
sort_buffer_size = 256M
read_buffer = 2M
write_buffer = 2M
 
[mysqlhotcopy]
interactive-timeout

MYSQLCONF

mkdir -p /data/tmp/
chmod 1777 /data/tmp
service mysql stop
rm /var/lib/mysql/ib_logfile*
service mysql start

echo "Creating database" >&3

MYSQLPASS=$(pwgen -s 24)
echo "$MYSQLPASS" > /root/mysql-crmpass
echo "MySQL-User: tecart"
echo "MySQL-Password: $MYSQLPASS"

mysql -e "CREATE USER 'tecart'@'localhost' IDENTIFIED BY '$MYSQLPASS';"
mysql -e "GRANT USAGE ON *.* TO 'tecart'@'localhost' IDENTIFIED BY '$MYSQLPASS' WITH MAX_QUERIES_PER_HOUR 0 MAX_CONNECTIONS_PER_HOUR 0 MAX_UPDATES_PER_HOUR 0 MAX_USER_CONNECTIONS 0;"
mysql -e "CREATE DATABASE tecart DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_german2_ci;"
mysql -e "GRANT ALL PRIVILEGES ON tecart.* TO 'tecart'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"


echo "Configuring memcached" >&3

mkdir -p /etc/systemd/system/memcached.service.d/
cat <<MEMCACHEDCONF > /etc/systemd/system/memcached.service.d/override.conf
[Service]
PermissionsStartOnly=true
ExecStartPre=/usr/bin/install -d -g www-data -o www-data -m 1755 -v /run/memcached
ExecStopPost=/bin/rm -rf /run/memcached
MEMCACHEDCONF

echo -en "-d\n-m $((${MEMORY}/32*4))\n-u www-data\n-s /run/memcached/memcached.sock" > /etc/memcached.conf
systemctl daemon-reload
service memcached restart

echo "Configuring apache2" >&3

mkdir -p /etc/systemd/system/apache2.service.d/
cat <<APACHECONF > /etc/systemd/system/apache2.service.d/override.conf
[Service]
PrivateTmp=false
APACHECONF

sed -i -e 's:ServerSignature On:ServerSignature Off:' \
       -e 's:ServerTokens OS:ServerTokens Prod:' /etc/apache2/conf-enabled/security.conf

a2enmod php7.3 || true
systemctl daemon-reload
service apache2 restart

sed -i -E '/<policy domain="coder" rights="none" pattern="(PS|PS2|PS3|EPS|PDF|XPS)" \/>/d' /etc/ImageMagick-6/policy.xml

echo "Downloading latest TecArt Software release" >&3

cd /usr/src
wget "https://crmsrv.tecart.de/release/crm_${RELEASE}.tar.gz"

echo "Installing latest release" >&3

mkdir -p /var/www/crm
tar -C /var/www/crm/ --strip-components 1 -pxf "crm_${RELEASE}.tar.gz"

echo "Creating /data directories" >&3

mkdir -p {/var/www/crm/config,/data/crm}
chown -R www-data.www-data {/var/www/crm,/data/crm}
chmod -R 0700 {/var/www/crm,/data/crm}

echo "Setting up apache2" >&3

APACHE_WORKERS=$((${MEMORY}/100))
cat <<APACHECONF > /etc/apache2/conf-available/tecart.conf
Timeout 60
MaxKeepAliveRequests 0
KeepAliveTimeout 60

StartServers             10
MinSpareServers           5
MaxSpareServers          10
MaxConnectionsPerChild 1000

# Hauptspeicher in MB / 100 MB ( z.B. 16384 / 100 = 163 )
MaxRequestWorkers       ${APACHE_WORKERS}

# Hauptspeicher in MB / 100 MB ( z.B. 16384 / 100 = 163 )
ServerLimit ${APACHE_WORKERS}
APACHECONF

cat <<APACHECONF > /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@crmsrv

        DocumentRoot /var/www/crm/
        <Directory />
            Options -Indexes -FollowSymLinks -MultiViews
            AllowOverride None
            Require all granted
        </Directory>

        <Directory /var/www/crm/data>
            Require all denied
        </Directory>

        <Directory /var/www/crm/upload>
            php_value upload_max_filesize 1M
            php_value post_max_size 1M
        </Directory>

        Alias /Microsoft-Server-ActiveSync /var/www/crm/zpush/index.php
        AliasMatch (?i)/Autodiscover/Autodiscover.xml /var/www/crm/zpush/autodiscover/autodiscover.php

        ErrorLog /var/log/apache2/error.log

        LogLevel error
</VirtualHost>
APACHECONF

cat <<APACHECONF > /etc/apache2/sites-available/default-ssl.conf
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
        ServerAdmin webmaster@crmsrv
        DocumentRoot /var/www/crm/
        <Directory />
            Options -Indexes -FollowSymLinks -MultiViews
            AllowOverride None
            Require all granted
        </Directory>

        <Directory /var/www/crm/data>
            Require all denied
        </Directory>

        <Directory /var/www/crm/upload>
            php_value upload_max_filesize 1M
            php_value post_max_size 1M
        </Directory>

        Alias /Microsoft-Server-ActiveSync /var/www/crm/zpush/index.php
        AliasMatch (?i)/Autodiscover/Autodiscover.xml /var/www/crm/zpush/autodiscover/autodiscover.php

        ErrorLog /var/log/apache2/error.log
        LogLevel error

        SSLEngine on

        SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
        SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

        SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
        SSLProtocol All -SSLv2 -SSLv3
        SSLHonorCipherOrder On
        Header always set Strict-Transport-Security "max-age=63072000"
        #Header always set X-Frame-Options DENY
        Header always set X-Content-Type-Options nosniff
        # Requires Apache >= 2.4
        SSLCompression off 
        # Requires Apache >= 2.4.11
        SSLSessionTickets Off

        <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
                SSLOptions +StdEnvVars
        </Directory>

</VirtualHost>
</IfModule>
APACHECONF

a2enconf tecart || true
a2dismod -f auth_basic authn_file authz_default authz_groupfile authz_user autoindex cgi deflate || true
a2dismod -f env negotiation reqtimeout setenvif rewrite status || true
a2enmod ssl headers || true
a2ensite default-ssl || true

service apache2 restart

echo "Base installation done." >&3
echo "Configuring TecArt Software" >&3

MYSQLPASS_B64=$(echo -en "$MYSQLPASS" | base64)
MYSQLUSER_B64=$(echo -en "tecart" | base64)

cp /var/www/crm/class/action/setup/config.tpl.php /var/www/crm/config/conf.inc.php
sed -i -e 's|{$setup_pass}||' \
	-e 's|{$setup_root}|root|' \
	-e 's|{$logosrc}|../themes/blue/icons/tlogo.gif|' \
	-e 's|{$logolink}|https://www.tecart.de/|' \
	-e 's|{$logotitle}|TecArt GmbH - TecArt-System|' \
	-e 's|{$dbdriver}|mysqli_innodb|' \
	-e 's|{$dbname}|tecart|' \
	-e "s|{\$dbuser}|$MYSQLUSER_B64|" \
	-e "s|{\$dbpass}|$MYSQLPASS_B64|" \
	-e 's|{$dbhost}|localhost|' \
	-e 's|{$memcache}|unix:///run/memcached/memcached.sock:0|' \
	-e 's|{$dataroot}|/data/crm|' \
	-e 's|{$phpcli}|/usr/bin/php|' \
	-e 's|{$phpini}|/etc/php/7.3/cli/php.ini|' \
	-e 's|{$crm_title}|TecArt CRM Professional - |' \
	-e "s|\$config\['php_path'\]|\$config['data_paths']['tcucd_dir'] = '/data/crm/tcucd';\n\$config['php_path']|" \
	/var/www/crm/config/conf.inc.php

mkdir "/data/crm/tcucd"
chown www-data.www-data "/var/www/crm/config/conf.inc.php"
chown www-data.www-data "/data/crm/tcucd"

echo "Running TecArt Software setup" >&3

cd /var/www/crm/setup
sudo -u www-data ./setup

} >"${LOG_PATH}/tecart-install.log" 2>"${LOG_PATH}/tecart-install.err"

echo "5.0" > /etc/tecart-installer-version

echo ""
echo ""
echo "Installation succeeded"
echo ""
echo -e "\tHOST-ID: $(ip l | grep link/ether | awk '{print $2}')"

echo "Please specify the passwort for the system's 'root' user:"
/var/www/crm/tools/pw_reset root