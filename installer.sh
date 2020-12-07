#!/bin/bash

apt-get update -y && apt-get upgrade -y && apt-get dist-upgrade -y

#use no check certificate
echo "check_certificate = off" >> ~/.wgetrc

#Create and Configure rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
exit 0
END
chmod +x /etc/rc.local

#Upgrade openssl
sudo apt install build-essential checkinstall zlib1g-dev -y
cd /usr/local/src/
wget https://www.openssl.org/source/openssl-1.1.1h.tar.gz
tar xzf openssl-1.1.1h.tar.gz
cd openssl-1.1.1h
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
make && make test && make install
cd /etc/ld.so.conf.d/
cat > openssl-1.1.1c.conf <<-END

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
 
#install badvpn deb/ubun
apt-get install cmake make gcc -y
cd
wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz
tar xzf 1.999.130.tar.gz
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

set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

#  set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# dsable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# dropbear
apt-get -y install dropbear -y
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=3128/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 777"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# configuration stunnel
apt-get install stunnel4 -y
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

# openssl certificate
cd /etc/stunnel/
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/stunnel.pem
cd
service stunnel4 restart

# login setting
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells

# l2tp
https://raw.githubusercontent.com/demonk1992/membagongkan/main/l2tp.sh
bash l2tp.sh

# cron job
apt-get install cron
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/crontab
mv crontab /etc/
chmod 644 /etc/crontab

# limit login
cd
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/userlimit.sh
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/userlimitssh.sh
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/autokill.sh
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/userexpired.sh
echo "@reboot root /root/userlimit.sh" > /etc/cron.d/userlimitreboot
echo "* * * * * root ./userlimit.sh 1" > /etc/cron.d/userlimit1
echo "* * * * * root sleep 10; ./userlimit.sh 1" > /etc/cron.d/userlimit2
echo "* * * * * root sleep 20; ./userlimit.sh 1" > /etc/cron.d/userlimit3
echo "* * * * * root sleep 30; ./userlimit.sh 1" > /etc/cron.d/userlimit4
echo "* * * * * root sleep 40; ./userlimit.sh 1" > /etc/cron.d/userlimit5
echo "* * * * * root sleep 50; ./userlimit.sh 1" > /etc/cron.d/userlimit6
service cron restart
service ssh restart
service dropbear restart

# clear cache
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/clearcache.sh
echo "@reboot root /root/clearcache.sh" > /etc/cron.d/clearcache
chmod 755 /root/clearcache.sh

# limit
sed -i '$ i\echo 1 > *                hard    maxlogins       2' /etc/security/limits.conf

# install nginx
apt-get install nginx -y
cd
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/demonk1992/membagongkan/main/nginx.conf
mkdir -p /home/monk/public_html
echo "<pre>~mscvip~</pre>" > /home/monk/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/demonk1992/membagongkan/main/vps.conf"
service nginx restart

# menu
cd /usr/local/bin/
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/menu.zip
tar zxf menu.zip
chmod +x /usr/local/bin/*

echo "      INSTALL SELESAI RASANYA SANGAT MEMBAGONGKAN !" 
echo "========================================"
cat /dev/null > ~/.bash_history && history -c
