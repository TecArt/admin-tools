#!/bin/bash
#
# Installer for the TecArt Business Software and all of it's dependencies.
#
# This program is supposed to be run on a clean Debian 11 Installation. Please
# do not run this script on a server that has already been configured for other 
# software!
#
# Copyright (c) by TecArt GmbH, 2023

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
production_repo="true"
RELEASE=v53_80
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
Usage: $PROGNAME [-l LOGPATH] [--log-path LOGPATH] [--repo-user REPO-USER] [--repo-pass REPO-PASS] [--no-production-repo] (check|install)

Options:
-h, --help                  Display this usage message and exit
    --repo-user             Username for the Enterprise Repositories
    --repo-pass             Password for the Enterprise Repositories
-l, --log-path [DIR]        Write logs into given directory
    --no-production-repo    Force the use of untested repositories

Installer for the TecArt Business Software and all of it's dependencies.

${yll}This program is supposed to be run on a clean Debian 11 Installation. Please 
do not run this script on a server that has already been configured for other 
software!${rst}

Copyright (c) by TecArt GmbH, 2023
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
    --no-production-repo)
        production_repo="false"
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

if [ -f "/etc/tecart-installer-version" ] && [ "$(wc -c /etc/tecart-installer-version | awk '{print $1}')" -gt 0 ]
then
    die "It looks like this installer ran already!"
fi

if [ -z "$repo_user" ] && [ "$production_repo" = "true" ]
then
    read -p "TecArt Enterprise Repository User: " repo_user 1>&3
fi

if [ -z "$repo_pass" ] && [ "$production_repo" = "true" ]
then
    read -p "TecArt Enterprise Repository Password: " repo_pass
fi

# TODO: Ask for proxy settings

repo_test=0
if [ "$production_repo" = "true" ] && ! wget -q -O/dev/null https://${repo_user}:${repo_pass}@customer.mirror.tecart.de/
then
    echo "Could not connect to TecArt Enterprise Mirrors"
    exit 1
elif [ "$production_repo" = "false" ] && ! wget -q -O/dev/null https://mirror.tecart.de/
then
    echo "Could not connect to Free TecArt Mirrors"
    exit 1
else
    repo_test=1
fi

if [ "$repo_test" -eq 1 ] && [ "$(lsb_release -is)" == "Debian" ] && \
    [ "$(lsb_release -rs)" = "11" ]
then
    echo "Mirror is available and system running on Debian 11"
    if [ "$ACTION" = "check" ]
    then
        exit 0
    fi
else
    echo "Could not confirm that mirros is available and system running on Debian 11"
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

mirror_host="mirror.tecart.de"
if [ "$production_repo" = "true" ]; then
mirror_host="customer.mirror.tecart.de"
cat << EOL > /etc/apt/auth.conf.d/tecart.conf
machine customer.mirror.tecart.de
 login ${repo_user}
 password ${repo_pass}
EOL
fi

apt update
apt install -y apt-transport-https dirmngr wget pwgen debconf ssl-cert

cat << EOL > /etc/apt/sources.list
deb https://${mirror_host}/ftp.de.debian.org/debian/ bullseye main contrib non-free
deb https://${mirror_host}/security.debian.org/debian-security bullseye-security main contrib non-free
deb https://${mirror_host}/ftp.de.debian.org/debian/ bullseye-updates main contrib non-free
EOL

cat << TECARTREPO > /etc/apt/sources.list.d/tecart-bullseye.sources
Types: deb
URIs: https://${mirror_host}/repo.tecart.de/apt/debian/
Suites: bullseye
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/tecart-archive-keyring.gpg
TECARTREPO

cat << PHPREPO > /etc/apt/sources.list.d/tecart-php8.sources
Types: deb
URIs: https://${mirror_host}/packages.sury.org/php/
Suites: bullseye
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/sury-archive-keyring.gpg
PHPREPO

wget -O /usr/share/keyrings/tecart-archive-keyring.gpg https://repo.tecart.de/tecart-archive-keyring.gpg
wget -O /usr/share/keyrings/sury-archive-keyring.gpg https://packages.sury.org/php/apt.gpg

apt-get update

# Debian installs without systemd-resolved enabled but some packages require
# it to be active. We'll back up the original resolv.conf for quick access.
cp /etc/resolv.conf{,.dist}
systemctl enable systemd-resolved.service
systemctl start systemd-resolved.service

echo "Installing dependencies. This might take a while..." >&3
apt install -y tecart-archive-keyring tecart-essentials-server-5.3

# Restore the resolv.conf in case the systemd resolver didn't work fast enough
cp /etc/resolv.conf{.dist,}

echo "Configuring timezone and locale" >&3
echo "Europe/Berlin" > /etc/timezone
dpkg-reconfigure -f noninteractive tzdata
sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' \
       -e 's/# de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
echo 'LANG="de_DE.UTF-8"'>/etc/default/locale
dpkg-reconfigure --frontend=noninteractive locales
update-locale LANG=de_DE.UTF-8

# This is needed so www-data can run resource-limited scripts via systemd-run
loginctl enable-linger www-data

echo "Updating system settings" >&3
echo 'vm.swappiness=0' >> /etc/sysctl.d/90-tecart.conf

echo "Installing atd fix" >&3
set +H
test -f /etc/rc.local || echo -e "#!/bin/sh\n\nfor i in \`atq | awk '{print \$1}'\`;do atrm \$i;done\n\nexit 0" > /etc/rc.local
grep 'atrm' /etc/rc.local || sed -i "s/exit 0/for i in \`atq | awk '{print \$1}'\`;do atrm \$i;done\n\nexit 0/" /etc/rc.local
chmod +x /etc/rc.local

echo "Configuring MariaDB" >&3
MYSQLMEMORY=$(($MEMORY/10*4))
MYSQLCONNECTIONS=$(($MEMORY/5))

cat <<MYSQLCONF > /etc/mysql/mariadb.conf.d/tecart.cnf
[client]
default-character-set = utf8mb4
 
[mysqld]
tmpdir = /data/tmp/
character-set-server  = utf8mb4
collation-server      = utf8mb4_general_ci
character_set_server   = utf8mb4
collation_server       = utf8mb4_general_ci
 
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
 
# Query cache is disabled by default as the overhead it imposes
# outweighs any benefits gained by it by far
query_cache_size       = 0
query_cache_type       = 0

query_prealloc_size    = 16384
query_alloc_block_size = 16384
 
# INNODB PERFORMANCE
innodb_buffer_pool_size         = ${MYSQLMEMORY}M        # Maximal ~40% des RAM
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

performance_schema = ON

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

echo "Generating snakeoil certificate" >&3
/usr/sbin/make-ssl-cert generate-default-snakeoil || true

echo "Configuring apache2" >&3

mkdir -p /etc/systemd/system/apache2.service.d/
cat <<APACHECONF > /etc/systemd/system/apache2.service.d/override.conf
[Service]
PrivateTmp=false
APACHECONF

sed -i -e 's:ServerSignature On:ServerSignature Off:' \
       -e 's:ServerTokens OS:ServerTokens Prod:' /etc/apache2/conf-enabled/security.conf

a2enmod php8.0 || true
systemctl daemon-reload
service apache2 restart

echo "Configuring alternatives: php" >&3
update-alternatives --set php /usr/bin/php8.0 || true

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

cat <<APACHECONF > /etc/apache2/conf-available/proto.conf
Protocols h2 http/1.1

SSLEngine on

SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

SSLProtocol             all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2
SSLHonorCipherOrder     off
SSLSessionTickets       off
SSLCompression          off

Header always set Strict-Transport-Security "max-age=63072000"
Header always set X-Content-Type-Options nosniff
APACHECONF

cat <<APACHECONF > /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@crmsrv
        RewriteEngine On
        RewriteCond %{HTTPS} !=on
        RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
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

        Include /etc/apache2/conf-available/proto.conf

        <FilesMatch "\.(cgi|shtml|phtml|php)$">
                SSLOptions +StdEnvVars
        </FilesMatch>
</VirtualHost>
</IfModule>
APACHECONF

a2enconf tecart || true
a2dismod -f auth_basic authn_file authz_user autoindex cgi env \
    negotiation reqtimeout setenvif status || true
a2enmod ssl headers rewrite http2 || true
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
	-e 's|{$phpini}|/etc/php/8.0/cli/php.ini|' \
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

echo "5.3" > /etc/tecart-installer-version

echo ""
echo ""
echo "Installation succeeded"
echo ""
echo -e "\tHOST-ID: $(ip l | grep link/ether | awk '{print $2}')"

echo "Please specify the passwort for the system's 'root' user:"
/var/www/crm/tools/pw_reset root
