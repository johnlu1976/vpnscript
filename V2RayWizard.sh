#!/bin/bash

#====================================================
#	System Request: Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author: wulabing
#	Description: V2ray ws+tls one-key management
#	Version: 1.0
#	Email: admin@wulabing.com
#	Official document: www.v2ray.com
#   Optimizer: https://www.sysosx.com
#====================================================

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit

# Font colors
Green="\033[32m"
Red="\033[31m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

# Notification information
OK="${Green}[OK]${Font}"
Error="${Red}[Error]${Font}"

# Version
shell_version="1.1.9.0"
shell_mode="None"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
v2ray_bin_dir_old="/usr/bin/v2ray"
v2ray_bin_dir="/usr/local/bin/v2ray"
v2ctl_bin_dir="/usr/local/bin/v2ctl"
v2ray_info_file="$HOME/v2ray_info.inf"
v2ray_qr_config_file="/usr/local/vmess_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
v2ray_access_log="/var/log/v2ray/access.log"
v2ray_error_log="/var/log/v2ray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="/usr/bin/ssl_update.sh"
nginx_version="1.20.1"
openssl_version="1.1.1k"
jemalloc_version="5.2.1"
old_config_status="off"

# Move old version configuration information for versions below 1.1.0
[[ -f "/etc/v2ray/vmess_qr.json" ]] && mv /etc/v2ray/vmess_qr.json $v2ray_qr_config_file

# Simple random number
random_num=$((RANDOM%12+4))
# Generate camouflage path
camouflage="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

THREAD=$(grep 'processor' /proc/cpuinfo | sort -u | wc -l)

source '/etc/os-release'

# Extract the English name of the distribution system from VERSION for adding the corresponding Nginx apt source in Debian/Ubuntu
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} Current system is Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        rm /var/lib/dpkg/lock
        dpkg --configure -a
        rm /var/lib/apt/lists/lock
        rm /var/cache/apt/archives/lock
        $INS update
    else
        echo -e "${Error} ${RedBG} Current system is ${ID} ${VERSION_ID}, not supported. Installation aborted. ${Font}"
        exit 1
    fi

    $INS install dbus

    systemctl stop firewalld
    systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld has been disabled ${Font}"

    systemctl stop ufw
    systemctl disable ufw
    echo -e "${OK} ${GreenBG} ufw has been disabled ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} Current user is root, proceeding with installation ${Font}"
    else
        echo -e "${Error} ${RedBG} Current user is not root. Please switch to root and re-run the script ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 completed ${Font}"
    else
        echo -e "${Error} ${RedBG} $1 failed ${Font}"
        exit 1
    fi
}

dependency_install() {
    ${INS} install wget git lsof bind9-dnsutils -y

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi
    judge "Installed crontab"

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron
    fi
    judge "Configured crontab auto-start"

    ${INS} -y install bc
    judge "Installed bc"

    ${INS} -y install unzip
    judge "Installed unzip"

    ${INS} -y install qrencode
    judge "Installed qrencode"

    ${INS} -y install curl
    judge "Installed curl"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y groupinstall "Development tools"
    else
        ${INS} -y install build-essential
    fi
    judge "Installed build tools"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install pcre pcre-devel zlib-devel epel-release
    else
        ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
    fi

    ${INS} -y install haveged
    systemctl start haveged && systemctl enable haveged

    mkdir -p /usr/local/bin >/dev/null 2>&1
}

basic_optimization() {
    # Maximum file open count
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # Disable Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi
}

port_alterid_set() {
    if [[ "on" != "$old_config_status" ]]; then
        read -rp "Enter connection port (default:443):" port
        [[ -z ${port} ]] && port="443"
        alterID="0"
    fi
}

modify_path() {
    if [[ "on" == "$old_config_status" ]]; then
        camouflage="$(grep '\"path\"' $v2ray_qr_config_file | awk -F '"' '{print $4}')"
    fi
    sed -i "/\"path\"/c \\\t  \"path\":\"${camouflage}\"" ${v2ray_conf}
    judge "Modified V2ray camouflage path"
}

modify_inbound_port() {
    if [[ "on" == "$old_config_status" ]]; then
        port="$(info_extraction '\"port\"')"
    fi
    if [[ "$shell_mode" != "h2" ]]; then
        PORT=$((RANDOM + 10000))
        sed -i "/\"port\"/c  \    \"port\":${PORT}," ${v2ray_conf}
    else
        sed -i "/\"port\"/c  \    \"port\":${port}," ${v2ray_conf}
    fi
    judge "Modified V2ray inbound port"
}

modify_UUID() {
    [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
    if [[ "on" == "$old_config_status" ]]; then
        UUID="$(info_extraction '\"id\"')"
    fi
    sed -i "/\"id\"/c \\\t  \"id\":\"${UUID}\"," ${v2ray_conf}
    judge "Modified V2ray UUID"
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"id\"/c \\  \"id\": \"${UUID}\"," ${v2ray_qr_config_file}
    echo -e "${OK} ${GreenBG} UUID:${UUID} ${Font}"
}

modify_nginx_port() {
    if [[ "on" == "$old_config_status" ]]; then
        port="$(info_extraction '\"port\"')"
    fi
    sed -i "/ssl http2;$/c \\\tlisten ${port} ssl http2;" ${nginx_conf}
    sed -i "3c \\\tlisten [::]:${port} http2;" ${nginx_conf}
    judge "Modified V2ray port"
    [ -f ${v2ray_qr_config_file} ] && sed -i "/\"port\"/c \\  \"port\": \"${port}\"," ${v2ray_qr_config_file}
    echo -e "${OK} ${GreenBG} Port:${port} ${Font}"
}

modify_nginx_other() {
    sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
    sed -i "/location/c \\\tlocation ${camouflage}" ${nginx_conf}
    sed -i "/proxy_pass/c \\\tproxy_pass http://127.0.0.1:${PORT};" ${nginx_conf}
    sed -i "/return/c \\\treturn 301 https://${domain}\$request_uri;" ${nginx_conf}
}

web_camouflage() {
    rm -rf /home/wwwroot
    mkdir -p /home/wwwroot
    cd /home/wwwroot || exit
    git clone https://github.com/wulabing/3DCEList.git
    judge "Web site camouflage"
}

v2ray_install() {
    if [[ -d /root/v2ray ]]; then
        rm -rf /root/v2ray
    fi
    if [[ -d /etc/v2ray ]]; then
        rm -rf /etc/v2ray
    fi
    mkdir -p /root/v2ray
    cd /root/v2ray || exit
    wget -N --no-check-certificate https://raw.githubusercontent.com/johnlu1976/vpnscript/${github_branch}/v2ray.sh

    if [[ -f v2ray.sh ]]; then
        rm -rf $v2ray_systemd_file
        systemctl daemon-reload
        bash v2ray.sh --force
        judge "Installed V2ray"
    else
        echo -e "${Error} ${RedBG} Failed to download V2ray installation file. Please check the download URL. ${Font}"
        exit 4
    fi
    rm -rf /root/v2ray
}

nginx_exist_check() {
    if [[ -f "/etc/nginx/sbin/nginx" ]]; then
        echo -e "${OK} ${GreenBG} Nginx already exists. Skipping compilation and installation. ${Font}"
    elif [[ -d "/usr/local/nginx/" ]]; then
        echo -e "${OK} ${GreenBG} Detected Nginx installed by another package. Continuing installation may cause conflicts. Please resolve before proceeding. ${Font}"
        exit 1
    else
        nginx_install
    fi
}

nginx_install() {
    wget -nc --no-check-certificate http://nginx.org/download/nginx-${nginx_version}.tar.gz -P ${nginx_openssl_src}
    judge "Downloaded Nginx"
    wget -nc --no-check-certificate https://www.openssl.org/source/openssl-${openssl_version}.tar.gz -P ${nginx_openssl_src}
    judge "Downloaded OpenSSL"
    wget -nc --no-check-certificate https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2 -P ${nginx_openssl_src}
    judge "Downloaded jemalloc"

    cd ${nginx_openssl_src} || exit

    [[ -d nginx-"$nginx_version" ]] && rm -rf nginx-"$nginx_version"
    tar -zxvf nginx-"$nginx_version".tar.gz

    [[ -d openssl-"$openssl_version" ]] && rm -rf openssl-"$openssl_version"
    tar -zxvf openssl-"$openssl_version".tar.gz

    [[ -d jemalloc-"${jemalloc_version}" ]] && rm -rf jemalloc-"${jemalloc_version}"
    tar -xvf jemalloc-"${jemalloc_version}".tar.bz2

    [[ -d "$nginx_dir" ]] && rm -rf ${nginx_dir}

    echo -e "${OK} ${GreenBG} Starting jemalloc compilation and installation ${Font}"

    cd jemalloc-${jemalloc_version} || exit
    ./configure
    judge "Compilation check"
    make -j "${THREAD}" && make install
    judge "Installed jemalloc"
    echo '/usr/local/lib' >/etc/ld.so.conf.d/local.conf
    ldconfig

    echo -e "${OK} ${GreenBG} Starting Nginx compilation and installation. This may take some time. Please wait patiently. ${Font}"

    cd ../nginx-${nginx_version} || exit

    ./configure --prefix="${nginx_dir}" \
        --with-http_ssl_module \
        --with-http_sub_module \
        --with-http_gzip_static_module \
        --with-http_stub_status_module \
        --with-pcre \
        --with-http_realip_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_secure_link_module \
        --with-http_v2_module \
        --with-cc-opt='-O3' \
        --with-ld-opt="-ljemalloc" \
        --with-openssl=../openssl-"$openssl_version"
    judge "Compilation check"
    make -j "${THREAD}" && make install
    judge "Installed Nginx"

    # Modify basic configuration
    sed -i 's/#user  nobody;/user  root;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/worker_processes  1;/worker_processes  3;/' ${nginx_dir}/conf/nginx.conf
    sed -i 's/    worker_connections  1024;/    worker_connections  4096;/' ${nginx_dir}/conf/nginx.conf
    sed -i '$i include conf.d/*.conf;' ${nginx_dir}/conf/nginx.conf

    # Delete temporary files
    rm -rf ../nginx-"${nginx_version}"
    rm -rf ../openssl-"${openssl_version}"
    rm -rf ../nginx-"${nginx_version}".tar.gz
    rm -rf ../openssl-"${openssl_version}".tar.gz

    # Add configuration folder to adapt to older scripts
    mkdir ${nginx_dir}/conf/conf.d
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 12 ]]; then
        ${INS} install socat netcat-openbsd -y
    else
        ${INS} install socat netcat-traditional -y
    fi
    judge "Installed SSL certificate generation script dependencies"

    # Install or update acme.sh
    curl https://get.acme.sh | sh
    judge "Installed SSL certificate generation script"

    # Ensure Let's Encrypt is set as the default CA
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force
    if [[ $? -ne 0 ]]; then
        echo -e "${Error} ${RedBG} Failed to set Let's Encrypt as the default CA. Please check permissions or set manually. ${Font}"
        exit 1
    fi
    judge "Set Let's Encrypt as the default CA"
}

domain_check() {
    read -rp "Enter your domain (e.g., www.example.com):" domain
    domain_ipv4="$(dig +short "${domain}" a)"
    domain_ipv6="$(dig +short "${domain}" aaaa)"
    echo -e "${OK} ${GreenBG} Retrieving public IP information. Please wait. ${Font}"
    wgcfv4_status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    wgcfv6_status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ ${wgcfv4_status} =~ "on"|"plus" ]] || [[ ${wgcfv6_status} =~ "on"|"plus" ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        echo -e "${OK} ${GreenBG} Disabled wgcf-warp ${Font}"
    fi
    local_ipv4=$(curl -s4m8 http://ip.sb)
    local_ipv6=$(curl -s6m8 http://ip.sb)
    if [[ -z ${local_ipv4} && -n ${local_ipv6} ]]; then
        echo -e nameserver 2a01:4f8:c2c:123f::1 > /etc/resolv.conf
        echo -e "${OK} ${GreenBG} Detected IPv6-only VPS. Automatically added DNS64 server. ${Font}"
    fi
    echo -e "Domain DNS resolved IP: ${domain_ip}"
    echo -e "Local IPv4: ${local_ipv4}"
    echo -e "Local IPv6: ${local_ipv6}"
    if [[ ${domain_ipv4} == ${local_ipv4} ]]; then
        echo -e "${OK} ${GreenBG} Domain DNS resolved IP matches local IPv4 ${Font}"
    elif [[ ${domain_ipv6} == ${local_ipv6} ]]; then
        echo -e "${OK} ${GreenBG} Domain DNS resolved IP matches local IPv6 ${Font}"
    else
        echo -e "${Error} ${RedBG} Ensure the domain has correct A/AAAA records. Otherwise, V2ray will not work properly. ${Font}"
        echo -e "${Error} ${RedBG} Domain DNS resolved IP does not match local IPv4/IPv6. Continue installation? (y/n) ${Font}" && read -r install
        case $install in
        [yY][eE][sS] | [yY])
            echo -e "${GreenBG} Continuing installation ${Font}"
            ;;
        *)
            echo -e "${RedBG} Installation aborted ${Font}"
            exit 2
            ;;
        esac
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} Port $1 is not in use ${Font}"
    else
        echo -e "${Error} ${RedBG} Port $1 is in use. Below are the details: ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} Attempting to kill processes using port $1 in 5 seconds ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} Processes killed ${Font}"
    fi
}

acme() {
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Generate the certificate
    if "$HOME/.acme.sh/acme.sh" --issue --standalone -d "${domain}" --keylength ec-256 --force; then
        echo -e "${OK} ${GreenBG} SSL certificate generated successfully ${Font}"
        mkdir -p /data
        if "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc --force; then
            echo -e "${OK} ${GreenBG} Certificate configured successfully ${Font}"
            if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
                wg-quick up wgcf >/dev/null 2>&1
                echo -e "${OK} ${GreenBG} Enabled wgcf-warp ${Font}"
            fi
        fi
    else
        echo -e "${Error} ${RedBG} SSL certificate generation failed ${Font}"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        if [[ -n $(type -P wgcf) && -n $(type -P wg-quick) ]]; then
            wg-quick up wgcf >/dev/null 2>&1
            echo -e "${OK} ${GreenBG} Enabled wgcf-warp ${Font}"
        fi
        exit 1
    fi
}

v2ray_conf_add_tls() {
    cd /etc/v2ray || exit
    wget --no-check-certificate https://raw.githubusercontent.com/johnlu1976/vpnscript/${github_branch}/tls/config.json -O config.json
    modify_path
    modify_inbound_port
    modify_UUID
}

v2ray_conf_add_h2() {
    cd /etc/v2ray || exit
    wget --no-check-certificate https://raw.githubusercontent.com/johnlu1976/vpnscript/${github_branch}/http2/config.json -O config.json
    modify_path
    modify_inbound_port
    modify_UUID
}

old_config_exist_check() {
    if [[ -f $v2ray_qr_config_file ]]; then
        echo -e "${OK} ${GreenBG} Detected old configuration file. Use old configuration? [Y/N] ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            echo -e "${OK} ${GreenBG} Retained old configuration ${Font}"
            old_config_status="on"
            port=$(info_extraction '\"port\"')
            ;;
        *)
            rm -rf $v2ray_qr_config_file
            echo -e "${OK} ${GreenBG} Deleted old configuration ${Font}"
            ;;
        esac
    fi
}

nginx_conf_add() {
    touch ${nginx_conf_dir}/v2ray.conf
    cat >${nginx_conf_dir}/v2ray.conf <<EOF
    server {
        listen 443 ssl http2;
        listen [::]:443 http2;
        ssl_certificate       /data/v2ray.crt;
        ssl_certificate_key   /data/v2ray.key;
        ssl_protocols         TLSv1.3;
        ssl_ciphers           TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
        server_name           serveraddr.com;
        index index.html index.htm;
        root  /home/wwwroot/3DCEList;
        error_page 400 = /400.html;

        # Config for 0-RTT in TLSv1.3
        ssl_early_data on;
        ssl_stapling on;
        ssl_stapling_verify on;
        add_header Strict-Transport-Security "max-age=31536000";

        location /ray/
        {
        proxy_redirect off;
        proxy_read_timeout 1200s;
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;

        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data \$ssl_early_data;
        }
}
    server {
        listen 80;
        listen [::]:80;
        server_name serveraddr.com;
        return 301 https://use.shadowsocksr.win\$request_uri;
    }
EOF

    modify_nginx_port
    modify_nginx_other
    judge "Modified Nginx configuration"
}

start_process_systemd() {
    systemctl daemon-reload
    chown -R root:root /var/log/v2ray/
    if [[ "$shell_mode" != "h2" ]]; then
        systemctl restart nginx
        judge "Restarted Nginx"
    fi
    systemctl restart v2ray
    judge "Restarted V2ray"
}

enable_process_systemd() {
    systemctl enable v2ray
    judge "Enabled V2ray auto-start"
    if [[ "$shell_mode" != "h2" ]]; then
        systemctl enable nginx
        judge "Enabled Nginx auto-start"
    fi
}

stop_process_systemd() {
    if [[ "$shell_mode" != "h2" ]]; then
        systemctl stop nginx
    fi
    systemctl stop v2ray
}

nginx_process_disabled() {
    [ -f $nginx_systemd_file ] && systemctl stop nginx && systemctl disable nginx
}

acme_cron_update() {
    wget -N -P /usr/bin --no-check-certificate "https://raw.githubusercontent.com/johnlu1976/vpnscript/refs/heads/main/ssl_update.sh"
    if [[ $(crontab -l | grep -c "ssl_update.sh") -lt 1 ]]; then
      if [[ "${ID}" == "centos" ]]; then
          sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/root
      else
          sed -i "/acme.sh/c 0 3 * * 0 bash ${ssl_update_file}" /var/spool/cron/crontabs/root
      fi
    fi
    judge "Updated cron job"
}

vmess_qr_config_tls_ws() {
    cat >$v2ray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "ws",
  "type": "none",
  "host": "${domain}",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF
}

vmess_qr_config_h2() {
    cat >$v2ray_qr_config_file <<-EOF
{
  "v": "2",
  "ps": "wulabing_${domain}",
  "add": "${domain}",
  "port": "${port}",
  "id": "${UUID}",
  "aid": "${alterID}",
  "net": "h2",
  "type": "none",
  "path": "${camouflage}",
  "tls": "tls"
}
EOF
}

vmess_qr_link_image() {
    vmess_link="vmess://$(base64 -w 0 $v2ray_qr_config_file)"
    {
        echo -e "$Red QR Code: $Font"
        echo -n "${vmess_link}" | qrencode -o - -t utf8
        echo -e "${Red} URL Import Link:${vmess_link} ${Font}"
    } >>"${v2ray_info_file}"
}

vmess_quan_link_image() {
    echo "$(info_extraction '\"ps\"') = vmess, $(info_extraction '\"add\"'), \
    $(info_extraction '\"port\"'), chacha20-ietf-poly1305, "\"$(info_extraction '\"id\"')\"", over-tls=true, \
    certificate=1, obfs=ws, obfs-path="\"$(info_extraction '\"path\"')\"", " > /tmp/vmess_quan.tmp
    vmess_link="vmess://$(base64 -w 0 /tmp/vmess_quan.tmp)"
    {
        echo -e "$Red QR Code: $Font"
        echo -n "${vmess_link}" | qrencode -o - -t utf8
        echo -e "${Red} URL Import Link:${vmess_link} ${Font}"
    } >>"${v2ray_info_file}"
}

vmess_link_image_choice() {
        echo "Choose the type of link to generate"
        echo "1: V2RayNG/V2RayN"
        echo "2: Quantumult"
        read -rp "Enter your choice:" link_version
        [[ -z ${link_version} ]] && link_version=1
        if [[ $link_version == 1 ]]; then
            vmess_qr_link_image
        elif [[ $link_version == 2 ]]; then
            vmess_quan_link_image
        else
            vmess_qr_link_image
        fi
}

info_extraction() {
    grep "$1" $v2ray_qr_config_file | awk -F '"' '{print $4}'
}

basic_information() {
    {
        echo -e "${OK} ${GreenBG} V2ray+ws+tls installed successfully"
        echo -e "${Red} V2ray Configuration Information ${Font}"
        echo -e "${Red} Address:${Font} $(info_extraction '\"add\"') "
        echo -e "${Red} Port:${Font} $(info_extraction '\"port\"') "
        echo -e "${Red} User ID (UUID):${Font} $(info_extraction '\"id\"')"
        echo -e "${Red} Extra ID (alterId):${Font} $(info_extraction '\"aid\"')"
        echo -e "${Red} Encryption Method:${Font} Adaptive "
        echo -e "${Red} Transport Protocol:${Font} $(info_extraction '\"net\"') "
        echo -e "${Red} Camouflage Type:${Font} none "
        echo -e "${Red} Path:${Font} $(info_extraction '\"path\"') "
        echo -e "${Red} Security:${Font} tls "
    } >"${v2ray_info_file}"
}

show_information() {
    cat "${v2ray_info_file}"
}

ssl_judge_and_install() {
    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; then
        echo "/data directory already contains certificate files"
        echo -e "${OK} ${GreenBG} Delete them? [Y/N] ${Font}"
        read -r ssl_delete
        case $ssl_delete in
        [yY][eE][sS] | [yY])
            rm -rf /data/v2ray.crt /data/v2ray.key
            echo -e "${OK} ${GreenBG} Deleted ${Font}"
            ;;
        *) ;;

        esac
    fi

    if [[ -f "/data/v2ray.key" || -f "/data/v2ray.crt" ]]; then
        echo "Certificate files already exist"
    elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
        echo "Certificate files already exist"
        "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
        judge "Applied certificate"
    else
        ssl_install
        acme
    fi
}

nginx_systemd() {
    cat >$nginx_systemd_file <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/etc/nginx/logs/nginx.pid
ExecStartPre=/etc/nginx/sbin/nginx -t
ExecStart=/etc/nginx/sbin/nginx -c ${nginx_dir}/conf/nginx.conf
ExecReload=/etc/nginx/sbin/nginx -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    judge "Added Nginx systemd service file"
    systemctl daemon-reload
}

tls_type() {
    if [[ -f "/etc/nginx/sbin/nginx" ]] && [[ -f "$nginx_conf" ]] && [[ "$shell_mode" == "ws" ]]; then
        echo "Choose supported TLS version (default:3):"
        echo "Note: If you use Quantumult X / routers / older Shadowrocket / V2ray core below 4.18.1, choose compatibility mode."
        echo "1: TLS1.1 TLS1.2 and TLS1.3 (Compatibility mode)"
        echo "2: TLS1.2 and TLS1.3 (Compatibility mode)"
        echo "3: TLS1.3 only"
        read -rp "Enter your choice:" tls_version
        [[ -z ${tls_version} ]] && tls_version=3
        if [[ $tls_version == 3 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} Switched to TLS1.3 only ${Font}"
        elif [[ $tls_version == 1 ]]; then
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.1 TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} Switched to TLS1.1 TLS1.2 and TLS1.3 ${Font}"
        else
            sed -i 's/ssl_protocols.*/ssl_protocols         TLSv1.2 TLSv1.3;/' $nginx_conf
            echo -e "${OK} ${GreenBG} Switched to TLS1.2 and TLS1.3 ${Font}"
        fi
        systemctl restart nginx
        judge "Restarted Nginx"
    else
        echo -e "${Error} ${RedBG} Nginx or configuration file does not exist, or the current installation version is h2. Please install the script correctly and try again. ${Font}"
    fi
}

show_access_log() {
    [ -f ${v2ray_access_log} ] && tail -f ${v2ray_access_log} || echo -e "${RedBG}Log file does not exist${Font}"
}

show_error_log() {
    [ -f ${v2ray_error_log} ] && tail -f ${v2ray_error_log} || echo -e "${RedBG}Log file does not exist${Font}"
}

ssl_update_manuel() {
    [ -f ${amce_sh_file} ] && "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" || echo -e "${RedBG}Certificate signing tool does not exist. Please confirm if you are using your own certificate.${Font}"
    domain="$(info_extraction '\"add\"')"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/v2ray.crt --keypath /data/v2ray.key --ecc
}

bbr_boost_sh() {
    [ -f "tcp.sh" ] && rm -rf ./tcp.sh
    wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

mtproxy_sh() {
    echo -e "${Error} ${RedBG} Feature under maintenance, temporarily unavailable ${Font}"
}

uninstall_all() {
    stop_process_systemd
    [[ -f $v2ray_systemd_file ]] && rm -f $v2ray_systemd_file
    [[ -f $v2ray_bin_dir ]] && rm -f $v2ray_bin_dir
    [[ -f $v2ctl_bin_dir ]] && rm -f $v2ctl_bin_dir
    [[ -d $v2ray_bin_dir_old ]] && rm -rf $v2ray_bin_dir_old
    if [[ -d $nginx_dir ]]; then
        echo -e "${OK} ${Green} Uninstall Nginx? [Y/N] ${Font}"
        read -r uninstall_nginx
        case $uninstall_nginx in
        [yY][eE][sS] | [yY])
            rm -rf $nginx_dir
            rm -rf $nginx_systemd_file
            echo -e "${OK} ${Green} Uninstalled Nginx ${Font}"
            ;;
        *) ;;

        esac
    fi
    [[ -d $v2ray_conf_dir ]] && rm -rf $v2ray_conf_dir
    [[ -d $web_dir ]] && rm -rf $web_dir
    echo -e "${OK} ${Green} Uninstall acme.sh and certificates? [Y/N] ${Font}"
    read -r uninstall_acme
    case $uninstall_acme in
    [yY][eE][sS] | [yY])
      /root/.acme.sh/acme.sh --uninstall
      rm -rf /root/.acme.sh
      rm -rf /data/v2ray.crt /data/v2ray.key
      ;;
    *) ;;
    esac
    systemctl daemon-reload
    echo -e "${OK} ${GreenBG} Uninstallation complete ${Font}"
}

delete_tls_key_and_crt() {
    [[ -f $HOME/.acme.sh/acme.sh ]] && /root/.acme.sh/acme.sh uninstall >/dev/null 2>&1
    [[ -d $HOME/.acme.sh ]] && rm -rf "$HOME/.acme.sh"
    echo -e "${OK} ${GreenBG} Cleared certificate residual files ${Font}"
}

judge_mode() {
    if [ -f $v2ray_bin_dir ] || [ -f $v2ray_bin_dir_old/v2ray ]; then
        if grep -q "ws" $v2ray_qr_config_file; then
            shell_mode="ws"
        elif grep -q "h2" $v2ray_qr_config_file; then
            shell_mode="h2"
        fi
    fi
}

install_v2ray_ws_tls() {
    is_root
    check_system
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_alterid_set
    v2ray_install
    port_exist_check 80
    port_exist_check "${port}"
    nginx_exist_check
    v2ray_conf_add_tls
    nginx_conf_add
    web_camouflage
    ssl_judge_and_install
    nginx_systemd
    vmess_qr_config_tls_ws
    basic_information
    vmess_link_image_choice
    tls_type
    show_information
    start_process_systemd
    enable_process_systemd
    acme_cron_update
}

install_v2_h2() {
    is_root
    check_system
    dependency_install
    basic_optimization
    domain_check
    old_config_exist_check
    port_alterid_set
    v2ray_install
    port_exist_check 80
    port_exist_check "${port}"
    v2ray_conf_add_h2
    ssl_judge_and_install
    vmess_qr_config_h2
    basic_information
    vmess_qr_link_image
    show_information
    start_process_systemd
    enable_process_systemd
}

update_sh() {
    ol_version=$(curl -L -s https://raw.githubusercontent.com/johnlu1976/vpnscript/${github_branch}/V2RayWizard.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
    echo "$ol_version" >$version_cmp
    echo "$shell_version" >>$version_cmp
    if [[ "$shell_version" < "$(sort -rV $version_cmp | head -1)" ]]; then
        echo -e "${OK} ${GreenBG} New version available. Update? [Y/N] ${Font}"
        read -r update_confirm
        case $update_confirm in
        [yY][eE][sS] | [yY])
            wget -N --no-check-certificate https://raw.githubusercontent.com/johnlu1976/vpnscript/${github_branch}/V2RayWizard.sh
            echo -e "${OK} ${GreenBG} Update complete ${Font}"
            exit 0
            ;;
        *) ;;

        esac
    else
        echo -e "${OK} ${GreenBG} Current version is up-to-date ${Font}"
    fi
}

maintain() {
    echo -e "${RedBG}This option is temporarily unavailable${Font}"
    echo -e "${RedBG}$1${Font}"
    exit 0
}

list() {
    case $1 in
    tls_modify)
        tls_type
        ;;
    uninstall)
        uninstall_all
        ;;
    crontab_modify)
        acme_cron_update
        ;;
    boost)
        bbr_boost_sh
        ;;
    *)
        menu
        ;;
    esac
}

modify_camouflage_path() {
    [[ -z ${camouflage_path} ]] && camouflage_path=1
    sed -i "/location/c \\\tlocation \/${camouflage_path}\/" ${nginx_conf}          #Modify the camouflage path of the nginx configuration file
    sed -i "/\"path\"/c \\\t  \"path\":\"\/${camouflage_path}\/\"" ${v2ray_conf}    #Modify the camouflage path of the v2ray configuration file
    judge "V2ray camouflage path modified"
}

menu() {
    update_sh
    echo -e "\t V2ray Installation Management Script ${Red}[${shell_version}]${Font}"
    echo -e "\t---authored by wulabing---"
    echo -e "\thttps://github.com/wulabing\n"
    echo -e "Currently installed version:${shell_mode}\n"

    echo -e "—————————————— Installation Guide ——————————————"""
    echo -e "${Green}0.${Font}  Update script"
    echo -e "${Green}1.${Font}  Install V2Ray (Nginx+ws+tls)"
    echo -e "${Green}2.${Font}  Install V2Ray (http/2)"
    echo -e "${Green}3.${Font}  Update V2Ray core"
    echo -e "—————————————— Configuration Changes ——————————————"
    echo -e "${Green}4.${Font}  Change UUID"
    echo -e "${Green}6.${Font}  Change port"
    echo -e "${Green}7.${Font}  Change TLS version (only valid for ws+tls)"
    echo -e "${Green}18.${Font}  Change camouflage path"
    echo -e "—————————————— View Information ——————————————"
    echo -e "${Green}8.${Font}  View real-time access logs"
    echo -e "${Green}9.${Font}  View real-time error logs"
    echo -e "${Green}10.${Font} View V2Ray configuration information"
    echo -e "—————————————— Other Options ——————————————"
    echo -e "${Green}11.${Font} Install 4-in-1 BBR acceleration script"
    echo -e "${Green}12.${Font} Install MTproxy (supports TLS obfuscation)"
    echo -e "${Green}13.${Font} Update certificate validity"
    echo -e "${Green}14.${Font} Uninstall V2Ray"
    echo -e "${Green}15.${Font} Update certificate crontab task"
    echo -e "${Green}16.${Font} Clear certificate residual files"
    echo -e "${Green}17.${Font} Exit \n"

    read -rp "Enter a number:" menu_num
    case $menu_num in
    0)
        update_sh
        ;;
    1)
        shell_mode="ws"
        install_v2ray_ws_tls
        ;;
    2)
        shell_mode="h2"
        install_v2_h2
        ;;
    3)
        bash <(curl -L -s https://raw.githubusercontent.com/johnlu1976/vpnscript/${github_branch}/v2ray.sh)
        ;;
    4)
        read -rp "Enter UUID:" UUID
        modify_UUID
        start_process_systemd
        ;;
    6)
        read -rp "Enter connection port:" port
        if grep -q "ws" $v2ray_qr_config_file; then
            modify_nginx_port
        elif grep -q "h2" $v2ray_qr_config_file; then
            modify_inbound_port
        fi
        start_process_systemd
        ;;
    7)
        tls_type
        ;;
    8)
        show_access_log
        ;;
    9)
        show_error_log
        ;;
    10)
        basic_information
        if [[ $shell_mode == "ws" ]]; then
            vmess_link_image_choice
        else
            vmess_qr_link_image
        fi
        show_information
        ;;
    11)
        bbr_boost_sh
        ;;
    12)
        mtproxy_sh
        ;;
    13)
        stop_process_systemd
        ssl_update_manuel
        start_process_systemd
        ;;
    14)
        source '/etc/os-release'
        uninstall_all
        ;;
    15)
        acme_cron_update
        ;;
    16)
        delete_tls_key_and_crt
        ;;
    17)
        exit 0
        ;;
    18)
        read -rp "Enter camouflage path (Note: Do not add slashes, e.g., ray):" camouflage_path
        modify_camouflage_path
        start_process_systemd
        ;;
    *)
        echo -e "${RedBG}Enter a valid number${Font}"
        ;;
    esac
}

judge_mode
list "$1"
