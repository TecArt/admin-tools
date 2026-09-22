#!/bin/bash
#
# Installer for the TecArt Business Software and all of it's dependencies.
#
# This program is supposed to be run on a clean Debian 13 Installation. Please
# do not run this script on a server that has already been configured for other 
# software!
#
# Copyright (c) by TecArt GmbH, 2026

set -euo pipefail
exec 4>&2
exec 3>&1

fatal () {
    echo -e "⛔ \e[1;31;1;40m[FATAL]:\e[0m   $*" >&2
    exit 1
}

warn() {
    echo -e "⚠️ \e[1;33;1;40m[WARNING]:\e[0m $*"
}

info() {
    echo -e "ℹ️ \e[1;32;1;40m[INFO]:\e[0m    $*"
}

if [ "$EUID" -ne 0 ]
  then fatal "Please run this script as root"
fi

export PATH=$PATH:/usr/sbin

ACTION=""
repo_user=""
repo_pass=""
acme_domain=""
production_repo="true"
install_icinga="true"
PHP_VERSION="8.4"
CRM_VERSION="5.5"
POSTGRES_VERSION="17"
RELEASE="v${CRM_VERSION/./}_${PHP_VERSION/./}"
DEBIAN_DIST="trixie"
DEBIAN_VERSION=13
LOG_PATH="/var/log/tecart"
TECART_CRM_DIR="/var/www/crm"
mkdir -p "$LOG_PATH"
MEMORY=$(($(awk '/^MemTotal:/{print $2}' /proc/meminfo)/1024))
PROGNAME=$(basename "$0")

usage() {
    if [ "$*" != "" ] ; then
        echo -e "\e[31m\e[1m[Error]\e[0m $*\n"
    fi
    local yll='\e[33m'
    local rst='\e[39m'
    echo -e "$(cat << EOF
Usage: $PROGNAME [-l LOGPATH] [--log-path LOGPATH] [--repo-user REPO-USER] [--repo-pass REPO-PASS] [--no-production-repo] [--acme-domain DOMAIN] [-i] [-p] (check|install)

Options:
-h, --help                  Display this usage message and exit
    --repo-user             Username for the Enterprise Repositories
    --repo-pass             Password for the Enterprise Repositories
-l, --log-path [DIR]        Write logs into given directory
    --no-production-repo    Force the use of untested repositories
-i, --no-icinga             Skip the installation of Icinga2 and Monitoring Plugins
    --acme-domain DOMAIN    Enable ACME TLS Certificate generation for DOMAIN

Installer for the TecArt Business Software and all of it's dependencies.

${yll}This program is supposed to be run on a clean Debian 13 Installation. Please 
do not run this script on a server that has already been configured for other 
software!${rst}

Copyright (c) by TecArt GmbH, 2026
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
    -i|--no-icinga)
        install_icinga="false"
        ;;
    --acme-domain)
        acme_domain="$2"
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
fi

if [ -z "$LOG_PATH" ]
then
    usage "Log Path is empty!"
fi

if [ -f "/etc/tecart-installer-version" ] && [ "$(wc -c /etc/tecart-installer-version | awk '{print $1}')" -gt 0 ]
then
    fatal "It looks like this installer ran already!"
fi

DEB_ARCH="$(dpkg --print-architecture)"
if [ "${DEB_ARCH}" != "amd64" ]
then
    fatal "Architecture ${DEB_ARCH} is not supported, please use amd64."
fi

if [ -z "$repo_user" ] && [ "$production_repo" = "true" ]
then
    read -r -p "TecArt Enterprise Repository User: " repo_user 1>&3
fi

if [ -z "$repo_pass" ] && [ "$production_repo" = "true" ]
then
    read -r -p "TecArt Enterprise Repository Password: " repo_pass
fi

# TODO: Ask for proxy settings

repo_test=0
if [ "$production_repo" = "true" ] && ! wget -q -O/dev/null "https://${repo_user}:${repo_pass}@customer.mirror.tecart.de/"
then
    fatal "Could not connect to TecArt Enterprise Mirrors"
elif [ "$production_repo" = "false" ] && ! wget -q -O/dev/null https://mirror.tecart.de/
then
    fatal "Could not connect to Free TecArt Mirrors"
else
    repo_test=1
fi

if [ "$repo_test" -eq 1 ] && [ "$(lsb_release -is)" == "Debian" ] && \
    [ "$(lsb_release -rs)" = "${DEBIAN_VERSION}" ]
then
    info "Mirror is available and system running on Debian ${DEBIAN_VERSION}"
    if [ "$ACTION" = "check" ]
    then
        exit 0
    fi
else
    fatal "Could not confirm that mirros is available and system running on Debian ${DEBIAN_VERSION}"
fi

# /proc/meminfo sometimes reports a little bit less than actually installed, 
# so we give some headroom here to the actual 2G
if [ "$MEMORY" -lt 1900 ]
then
    fatal "System reports to only have ${MEMORY}MiB of RAM. Minimum requirement is 2048MiB"
fi

#
# Actual installation ahead
# Logs will be written to $LOG_PATH
#
{
info "Debug log will be written in $LOG_PATH" >&3
info "Updating apt config" >&3

mirror_host="mirror.tecart.de"
if [ "$production_repo" = "true" ]; then
mirror_host="customer.mirror.tecart.de"
cat << EOL > /etc/apt/auth.conf.d/tecart.conf
machine customer.mirror.tecart.de
 login ${repo_user}
 password ${repo_pass}
EOL
fi

apt-get update
apt-get install -y apt-transport-https dirmngr wget pwgen debconf ssl-cert rsyslog

# Install resolvconf prior to everything else, otherwise we risk breaking 
# Packages that download external resources like ttf-mscorefonts-installer
# due to the loss of DNS during installation
apt-get install -y resolvconf 
resolvconf -u

cat << EOL > /etc/apt/sources.list
deb https://${mirror_host}/ftp.de.debian.org/debian/ ${DEBIAN_DIST} main contrib non-free non-free-firmware
deb https://${mirror_host}/security.debian.org/debian-security ${DEBIAN_DIST}-security main contrib non-free non-free-firmware
deb https://${mirror_host}/ftp.de.debian.org/debian/ ${DEBIAN_DIST}-updates main contrib non-free non-free-firmware
EOL

cat << TECARTREPO > /etc/apt/sources.list.d/tecart.sources
Types: deb
URIs: https://${mirror_host}/repo.tecart.de/apt/debian/
Suites: ${DEBIAN_DIST}
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/tecart-archive-keyring.gpg
TECARTREPO

wget -q -O /usr/share/keyrings/tecart-archive-keyring.gpg https://repo.tecart.de/tecart-archive-keyring.gpg

if [ "${install_icinga}" = "true" ]
then
    # shellcheck disable=SC1091
    wget -O /tmp/icinga-archive-keyring.deb "https://packages.icinga.com/icinga-archive-keyring_latest+debian$(. /etc/os-release; echo "$VERSION_ID").deb"
    apt-get install -y --no-install-recommends /tmp/icinga-archive-keyring.deb && rm -f /tmp/icinga-archive-keyring.deb
    echo "deb [signed-by=/usr/share/keyrings/icinga-archive-keyring.gpg] https://${mirror_host}/packages.icinga.com/debian icinga-${DEBIAN_DIST} main" > /etc/apt/sources.list.d/icinga.list
    chmod 644 /etc/apt/sources.list.d/icinga.list
fi

apt-get update

wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgres-archive-keyring.gpg
cat << POSTGRESREPO > /etc/apt/sources.list.d/postgresql.sources
Types: deb
URIs: https://${mirror_host}/apt.postgresql.org/pub/repos/apt 
Suites: ${DEBIAN_DIST}-pgdg
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/postgres-archive-keyring.gpg
POSTGRESREPO

apt-get update
info "Installing PosgreSQL..." >&3
apt-get install -y "tecart-essentials-server-${CRM_VERSION}-pgsql"

info "Installing dependencies. This might take a while..." >&3

apt-get install -y tecart-archive-keyring redis-server "tecart-essentials-server-${CRM_VERSION}"

if [ "${install_icinga}" = "true" ]
then
    info "Installing Icinga2 and monitoring plugins." >&3
    apt-get install -y --no-install-recommends icinga2 monitoring-plugins tecart-monitoring-plugins check-postgres
fi

info "Configuring timezone and locale" >&3
echo "Europe/Berlin" > /etc/timezone
dpkg-reconfigure -f noninteractive tzdata
sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' \
       -e 's/# de_DE.UTF-8 UTF-8/de_DE.UTF-8 UTF-8/' /etc/locale.gen
echo 'LANG="de_DE.UTF-8"'>/etc/default/locale
dpkg-reconfigure --frontend=noninteractive locales
update-locale LANG=de_DE.UTF-8

# This is needed so www-data can run resource-limited scripts via systemd-run
loginctl enable-linger www-data

info "Updating system settings" >&3
echo 'vm.swappiness=0' >> /etc/sysctl.d/90-tecart.conf

info "Installing atd fix" >&3
set +H
test -f /etc/rc.local || echo -e "#!/bin/sh\n\nfor i in \`atq | awk '{print \$1}'\`;do atrm \$i;done\n\nexit 0" > /etc/rc.local
grep 'atrm' /etc/rc.local || sed -i "s/exit 0/for i in \`atq | awk '{print \$1}'\`;do atrm \$i;done\n\nexit 0/" /etc/rc.local
chmod +x /etc/rc.local

mkdir -p /data/tmp/
chmod 1777 /data/tmp

info "Configuring PostgreSQL" >&3
PSQLMEMORY=$((MEMORY/8))
PSQLCONNECTIONS=$((MEMORY/5))

cat <<PSQLCONF > "/etc/postgresql/${POSTGRES_VERSION}/main/conf.d/tecart.conf"
search_path = '"\$user"'

max_connections = ${PSQLCONNECTIONS}

shared_buffers = ${PSQLMEMORY}MB                  # min 128kB
                                        # (change requires restart)

track_activities = on
track_activity_query_size = 1024       # (change requires restart)
track_counts = on
track_io_timing = on

autovacuum = on                        # Enable autovacuum subprocess?  'on'
                                        # requires track_counts to also be on.
autovacuum_max_workers = 6             # max number of autovacuum subprocesses
                                        # (change requires restart)

wal_buffers = 16MB
wal_compression = zstd
min_wal_size = 1GB
max_wal_size = 4GB

# If CPU cores for the whole machine exceeds 8, uncomment the lines below and replace 
# <CPU cores> with half the available cores and <CPU cores / 2> with a quarter of the
# available cores in the system
#max_worker_processes = <CPU cores>
#max_parallel_workers_per_gather = <CPU cores / 2>
#max_parallel_workers = <CPU cores>
#max_parallel_maintenance_workers = <CPU cores / 2>

huge_pages = try
jit = off

PSQLCONF

systemctl restart postgresql

info "Creating database" >&3

DBPASS=$(pwgen -s 24)
echo "$DBPASS" > /root/database-crmpass
echo "Database-User: tecart"
echo "Database-Password: $DBPASS"

PGEXEC="sudo -iu postgres psql "
$PGEXEC postgres -c "CREATE ROLE tecart WITH LOGIN PASSWORD '${DBPASS}' VALID UNTIL 'infinity';"
$PGEXEC postgres -c "CREATE DATABASE \"tecart\" TEMPLATE template0 OWNER tecart ENCODING 'UTF8' LC_COLLATE 'de_DE.UTF-8' CONNECTION LIMIT -1;"
$PGEXEC postgres -c "REVOKE ALL ON DATABASE tecart FROM public;"
$PGEXEC tecart   -c "CREATE SCHEMA tecart AUTHORIZATION tecart;"
$PGEXEC tecart   -c "ALTER DATABASE tecart SET SEARCH_PATH TO tecart;"

info "Configuring redis" >&3

echo "maxmemory $((4*MEMORY/32))mb" >> /etc/redis/redis.conf
echo "maxmemory-policy allkeys-lru" >> /etc/redis/redis.conf

systemctl enable --now redis-server

info "Generating snakeoil certificate" >&3
/usr/sbin/make-ssl-cert generate-default-snakeoil || true

info "Configuring apache2" >&3

mkdir -p /etc/systemd/system/apache2.service.d/
cat <<APACHECONF > /etc/systemd/system/apache2.service.d/override.conf
[Service]
PrivateTmp=false
APACHECONF

sed -i -e 's:ServerSignature On:ServerSignature Off:' \
       -e 's:ServerTokens OS:ServerTokens Prod:' /etc/apache2/conf-enabled/security.conf

a2enmod "php${PHP_VERSION}" || true
systemctl daemon-reload
service apache2 restart

info "Configuring alternatives: php" >&3
update-alternatives --set php "/usr/bin/php${PHP_VERSION}" || true

info "Downloading latest TecArt Software release" >&3

cd /usr/src
wget -q "https://crmsrv.tecart.de/release/crm_${RELEASE}_latest.tar.gz"

info "Installing latest release" >&3

mkdir -p "${TECART_CRM_DIR}"
tar -C "${TECART_CRM_DIR}/" --strip-components 1 -pxf "crm_${RELEASE}_latest.tar.gz"

info "Creating /data directories" >&3

mkdir -p {${TECART_CRM_DIR}/config,/data/crm}
chown -R www-data:www-data {${TECART_CRM_DIR},/data/crm}
chmod -R 0700 {${TECART_CRM_DIR},/data/crm}

info "Setting up apache2" >&3

APACHE_WORKERS=$((MEMORY/100))
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
Protocols h2 http/1.1 acme-tls/1

SSLEngine on

SSLCertificateFile    /etc/ssl/certs/ssl-cert-snakeoil.pem
SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

https://configurator.tlsref.org/#server=apache&version=2.4.68&config=modern&openssl=3.5.7&hsts&ocsp&guideline=6.0
SSLProtocol             -all +TLSv1.3
SSLOpenSSLConfCmd       Curves X25519MLKEM768:X25519:prime256v1:secp384r1
SSLCipherSuite          TLSv1.3 TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
SSLHonorCipherOrder     off
SSLSessionTickets       off

SSLUseStapling On
SSLStaplingCache "shmcb:logs/ssl_stapling(32768)"

Header always set Strict-Transport-Security "max-age=63072000"
Header always set X-Content-Type-Options nosniff

IncludeOptional /etc/apache2/conf-available/proto-local.conf
APACHECONF

cat <<APACHECONF > /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@crmsrv
        RewriteEngine On
        RewriteCond %{REQUEST_URI} !^/.well-known/acme-challenge/
        RewriteRule ^.*$ https://%{HTTP_HOST}%{REQUEST_URI} [R=308,QSA,L]
        LogLevel error
</VirtualHost>
APACHECONF

cat <<APACHECONF > /etc/apache2/conf-available/tecart-system.conf

<Directory /var/www/crm/upload>
    php_value upload_max_filesize 1M
    php_value post_max_size 1M
</Directory>

Alias /Microsoft-Server-ActiveSync \${TECART_CRM_DIR}/app/zpush/index.php
AliasMatch (?i)/Autodiscover/Autodiscover.xml \${TECART_CRM_DIR}/app/zpush/autodiscover/autodiscover.php

APACHECONF

cat <<APACHECONF > /etc/apache2/sites-available/default-ssl.conf
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
        ServerAdmin webmaster@crmsrv

        DocumentRoot \${TECART_CRM_DIR}/www_root

        <Directory />
            Options -Indexes -FollowSymLinks -MultiViews
            AllowOverride None
            Require all granted
        </Directory>

        ErrorLog /var/log/apache2/error.log
        LogLevel error

        Include /etc/apache2/conf-available/tecart-system.conf
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

info "Base installation done." >&3
info "Configuring TecArt Software" >&3

DBPASS_B64=$(echo -en "$DBPASS" | base64)
DBUSER_B64=$(echo -en "tecart" | base64)

cp "${TECART_CRM_DIR}/class/action/setup/config.tpl.php" "${TECART_CRM_DIR}/config/conf.inc.php"
# shellcheck disable=SC2016
sed -i -e 's|{$setup_pass}||' \
	-e 's|{$setup_root}|root|' \
	-e 's|{$logosrc}|../themes/blue/icons/tlogo.gif|' \
	-e 's|{$logolink}|https://www.tecart.de/|' \
	-e 's|{$logotitle}|TecArt GmbH - TecArt-System|' \
	-e "s|{\$dbdriver}|postgresql|" \
	-e 's|{$dbname}|tecart|' \
	-e "s|{\$dbuser}|${DBUSER_B64}|" \
	-e "s|{\$dbpass}|${DBPASS_B64}|" \
	-e 's|{$dbhost}|localhost|' \
	-e 's|{$memcache}|127.0.0.1:6379|' \
	-e 's|{$memcache_type}|redis|' \
	-e 's|{$dataroot}|/data/crm|' \
	-e 's|{$phpcli}|/usr/bin/php|' \
	-e "s|{\$phpini}|/etc/php/${PHP_VERSION}/cli/php.ini|" \
	-e 's|{$crm_title}|TecArt CRM Professional - |' \
	/var/www/crm/config/conf.inc.php

chown www-data:www-data "/var/www/crm/config/conf.inc.php"
chown www-data:www-data "/data/crm/tcucd"

info "Running TecArt Software setup" >&3

cd /var/www/crm/setup
sudo -u www-data ./setup

} >"${LOG_PATH}/tecart-install.log" 2> >(grep -Ev '([\.]{10} ){2,}' > "${LOG_PATH}/tecart-install.err")

echo "${CRM_VERSION}" > /etc/tecart-installer-version

echo -e "\n"
info "Installation succeeded\n"
echo -e "\n\tHOST-ID: $(ip l | grep link/ether | awk '{print $2}')"

echo "Please specify the passwort for the system's 'root' user:"
/var/www/crm/tools/pw_reset root
