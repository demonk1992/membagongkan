#!/bin/bash
# go to root
cd
# update upgrade
apt-get update; apt-get -y dist-upgrade;
apt-get install -y screen unzip wget curl git
# use no check certificate
echo "check_certificate = off" >> ~/.wgetrc
# Create and Configure rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
exit 0
END
chmod +x /etc/rc.local
# Create rc.d
cd /etc
mkdir rc.d
chmod +x rc.d
cat > /etc/rc.d/rc.local <<-END
#!/bin/sh -e
exit 0
END
chmod +x /etc/rc.d/rc.local
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
#  set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart
# dsable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
# Upgrade openssl
cd
sudo apt install -y build-essential checkinstall zlib1g-dev 
cd /usr/local/src/
wget https://www.openssl.org/source/openssl-1.1.1i.tar.gz
tar xzf openssl-1.1.1i.tar.gz
cd openssl-1.1.1i
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
make && make test && make install
cd /etc/ld.so.conf.d/
cat > openssl-1.1.1i.conf <<-END
/usr/local/ssl/lib
END
sudo ldconfig -v
sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.backup
sudo mv /usr/bin/openssl /usr/bin/openssl.backup
rm /etc/environment
cat > /etc/environment <<-END
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/ssl/bin"
END
source /etc/environment
echo $PATH
which openssl
openssl version -a
# Install badvpn deb/ubun
apt-get install -y cmake make gcc
cd
wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz && tar xzf 1.999.130.tar.gz
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.d/rc.local
chmod +x /usr/local/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
# Dropbear
apt-get -y install -y dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=3128/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS=""/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart
# Upgrade Dropbear
cd
apt-get install -y zlib1g-dev
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2020.81.tar.bz2
bzip2 -cd dropbear-2020.81.tar.bz2 | tar xvf -
cd dropbear-2020.81
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2020.81 && rm -rf dropbear-2020.81.tar.bz2
service dropbear restart
# login setting
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
# menu
cd /usr/local/bin/
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/menu.zip && unzip menu.zip
chmod +x /usr/local/bin/*
# Stunel
apt-get -y install stunnel4
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 443
connect = 127.0.0.1:3128
END
openssl req -new -newkey rsa:2048 -days 3650 \
  -nodes -x509 -sha256 \
  -subj '/CN=LocalHost' \
  -keyout /root/stunnel.pem \
  -out /root/stunnel.pem
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart
# Install nginx
cd
wget http://nginx.org/download/nginx-1.18.0.tar.gz && tar zxf nginx-1.18.0.tar.gz
cd nginx-1.18.0
wget https://www.openssl.org/source/openssl-1.1.1i.tar.gz && tar xzf openssl-1.1.1i.tar.gz
git clone https://github.com/openresty/headers-more-nginx-module
wget https://ftp.pcre.org/pub/pcre/pcre-8.42.tar.gz && tar xzvf pcre-8.42.tar.gz
wget https://www.zlib.net/zlib-1.2.11.tar.gz && tar xzvf zlib-1.2.11.tar.gz
sudo apt-get -y install libpcre3-dev
sudo apt install -y perl libperl-dev libgd3 libgd-dev libgeoip1 libgeoip-dev geoip-bin libxml2 libxml2-dev libxslt1.1 libxslt1-dev
sudo apt install -y build-essential git tree
tree -L 2 .
apt-get install -y cmake make gcc
./configure \
--conf-path=/etc/nginx/nginx.conf \
--sbin-path=/usr/sbin \
--error-log-path=/var/log/nginx/error.log \
--with-threads \
--with-stream \
--pid-path=/run/nginx.pid \
--with-stream_geoip_module \
--with-stream_ssl_module \
--with-http_image_filter_module \
--with-stream_geoip_module \
--with-pcre \
--with-http_mp4_module \
--with-http_secure_link_module \
--with-http_v2_module \
--with-http_flv_module \
--add-module=headers-more-nginx-module \
--with-http_geoip_module \
--with-http_gzip_static_module \
--with-http_stub_status_module \
--with-http_ssl_module \
--http-proxy-temp-path=/dev/shm/proxy_temp \
--http-client-body-temp-path=/dev/shm/client_body_temp \
--http-fastcgi-temp-path=/dev/shm/fastcgi_temp \
--http-uwsgi-temp-path=/dev/shm/uwsgi_temp \
--http-scgi-temp-path=/dev/shm/scgi_temp \
--build="v1.11.12 with TFO - Demonk" \
--with-openssl=/root/nginx-1.18.0/openssl-1.1.1i \
--with-openssl-opt=no-nextprotoneg \
--with-cc-opt='-O2 -fstack-protector-strong -DTCP_FASTOPEN=23'
make && sudo make install
objs/nginx -t
/etc/init.d/nginx stop && cp objs/nginx /usr/sbin/ && /etc/init.d/nginx start
nginx -V
cd /etc
rm -rf nginx
cd nginx
wget https://github.com/demonk1992/membagongkan/blob/main/nginx-monk.tar.gz && tar zxf nginx-monk.tar.gz
# Speed
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
sysctl -p
sed -i '$ i\fs.file-max = 1024000' /etc/sysctl.conf
sed -i '$ i\fs.inotify.max_user_instances = 8192' /etc/sysctl.conf
sed -i '$ i\net.core.default_qdisc=fq' /etc/sysctl.conf
sed -i '$ i\net.core.netdev_max_backlog = 262144' /etc/sysctl.conf
sed -i '$ i\net.core.rmem_default = 8388608' /etc/sysctl.conf
sed -i '$ i\net.core.rmem_max = 67108864' /etc/sysctl.conf
sed -i '$ i\net.core.somaxconn = 65535' /etc/sysctl.conf
sed -i '$ i\net.core.wmem_default = 8388608' /etc/sysctl.conf
sed -i '$ i\net.core.wmem_max = 67108864' /etc/sysctl.conf
sed -i '$ i\net.ipv4.ip_forward = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.ip_local_port_range = 10240 65000' /etc/sysctl.conf
sed -i '$ i\net.ipv4.route.gc_timeout = 100' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_congestion_control = hybla' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_fastopen = 3' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_fin_timeout = 30' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_keepalive_time = 1200' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_max_orphans = 3276800' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_max_syn_backlog = 65536' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_max_tw_buckets = 60000' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_mem = 94500000 915000000 927000000' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_mtu_probing = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_rmem = 4096 87380 67108864' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_sack = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_syn_retries = 2' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_syncookies = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_timestamps = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_tw_reuse = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_window_scaling = 1' /etc/sysctl.conf
sed -i '$ i\net.ipv4.tcp_wmem = 4096 65536 67108864' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_max = 6553500' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_established = 3600' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120' /etc/sysctl.conf
sed -i '$ i\net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120' /etc/sysctl.conf
sed -i '$ i\net.nf_conntrack_max = 6553500' /etc/sysctl.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
lsmod | grep bbr
echo "session required pam_limits.so" >> /etc/pam.d/common-session
echo "* soft nproc 1000000" >> /etc/security/limits.conf
echo "* hard nproc 1000000" >> /etc/security/limits.conf
echo "* soft nofile 1000000" >> /etc/security/limits.conf
echo "* hard nofile 1000000" >> /etc/security/limits.conf
echo "root soft nproc 1000000" >> /etc/security/limits.conf
echo "root hard nproc 1000000" >> /etc/security/limits.conf
echo "root soft nofile 1000000" >> /etc/security/limits.conf
echo "root hard nofile 1000000" >> /etc/security/limits.conf
# Certificate
MYIP=`curl -s ifconfig.me`;
MYIP2="s/xxxxxxxxx/$MYIP/g";
cd
openssl req -x509 -nodes -sha256 -newkey rsa:2048 \
-keyout demonk.key -out demonk.crt \
-days 3650 \
-subj "/CN=localhost" \
-reqexts SAN -extensions SAN \
-config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=IP:$MYIP,DNS:8.8.8.8"))
# V2ray
curl -O https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh
curl -O https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-dat-release.sh
bash install-release.sh
bash install-dat-release.sh
cat > /usr/local/etc/v2ray/config.json <<-END
{
	"log": {
		"access": "/var/log/v2ray/access.log",
		"error": "/var/log/v2ray/error.log",
		"loglevel": "warning"
	},
	"inbounds": [
		{
			"port": 9000,
			"protocol": "vmess",
			"settings": {
				"clients": [
					{
						"id": "917b319a-5966-4147-b25e-9c82ccc13795",
						"level": 1,
						"alterId": 0
					}
				]
			},
			"streamSettings": {
				"network": "ws"
			},
			"wsSettings": {
                               "path": "/IDGRAFIKA"
			},
			"sniffing": {
				"enabled": true,
				"destOverride": [
					"http",
					"tls"
				]
			}
		}
		//include_ss
		//include_socks
		//include_mtproto
		//include_in_config
		//
	],
	"outbounds": [
		{
			"protocol": "freedom",
			"settings": {
				"domainStrategy": "UseIP"
			},
			"tag": "direct"
		},
		{
			"protocol": "blackhole",
			"settings": {},
			"tag": "blocked"
        },
		{
			"protocol": "mtproto",
			"settings": {},
			"tag": "tg-out"
		}
		//include_out_config
		//
	],
	"dns": {
		"servers": [
			"https+local://cloudflare-dns.com/dns-query",
			"1.1.1.1",
			"1.0.0.1",
			"8.8.8.8",
			"8.8.4.4",
			"localhost"
		]
	},
	"routing": {
		"domainStrategy": "IPOnDemand",
		"rules": [
			{
				"type": "field",
				"ip": [
					"0.0.0.0/8",
					"10.0.0.0/8",
					"100.64.0.0/10",
					"127.0.0.0/8",
					"169.254.0.0/16",
					"172.16.0.0/12",
					"192.0.0.0/24",
					"192.0.2.0/24",
					"192.168.0.0/16",
					"198.18.0.0/15",
					"198.51.100.0/24",
					"203.0.113.0/24",
					"::1/128",
					"fc00::/7",
					"fe80::/10"
				],
				"outboundTag": "blocked"
			},
			{
				"type": "field",
				"inboundTag": ["tg-in"],
				"outboundTag": "tg-out"
			}
			,
			{
				"type": "field",
				"domain": [
					"domain:epochtimes.com",
					"domain:epochtimes.com.tw",
					"domain:epochtimes.fr",
					"domain:epochtimes.de",
					"domain:epochtimes.jp",
					"domain:epochtimes.ru",
					"domain:epochtimes.co.il",
					"domain:epochtimes.co.kr",
					"domain:epochtimes-romania.com",
					"domain:erabaru.net",
					"domain:lagranepoca.com",
					"domain:theepochtimes.com",
					"domain:ntdtv.com",
					"domain:ntd.tv",
					"domain:ntdtv-dc.com",
					"domain:ntdtv.com.tw",
					"domain:minghui.org",
					"domain:renminbao.com",
					"domain:dafahao.com",
					"domain:dongtaiwang.com",
					"domain:falundafa.org",
					"domain:wujieliulan.com",
					"domain:ninecommentaries.com",
					"domain:shenyun.com"
				],
				"outboundTag": "blocked"
			}			,
                {
                    "type": "field",
                    "protocol": [
                        "bittorrent"
                    ],
                    "outboundTag": "blocked"
                }
			//include_ban_ad
			//include_rules
			//
		]
	},
	"transport": {
		"kcpSettings": {
            "uplinkCapacity": 100,
            "downlinkCapacity": 100,
            "congestion": true
        }
	}
}
END
systemctl enable v2ray
sudo systemctl restart v2ray
sudo systemctl status -l v2ray
# info
clear
echo "Demonk punya guys :V " | tee log-install.txt
echo "===============================================" | tee -a log-install.txt
echo "SILAHKAN REBOOT VPS ANDA !"  | tee -a log-install.txt
echo "==============================================="  | tee -a log-install.txt