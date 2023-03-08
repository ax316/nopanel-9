#!/bin/bash

#### Implementacion del servicio no panel-9 web ####

CWD=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
fecha=$(date +'La fecha es %A %d de %B del %Y con hora de %r')
port=5243
date=$(date +"%H:%M:%S")
cpu=$(lscpu | grep CPU | head -2 | tail -1 | awk '{print $2}')
email=alexalvarez@powerhost.cl
mypass=$(pwgen -s1 10)
ip=$(ifconfig | grep inet | head -1 | awk '{print $2}')

### Verificacion de usuario root ###

if [ "$(id -u)" != "0" ]; then
   echo "Este no es el usuraio root (or using sudo)."
   exit 1
fi

clear

### Registrar la maquina ###
echo -n "Nombre de la Maquina:"
read host

hostnamectl set-hostname $host

echo "$ip $host" >> /etc/hosts

### Instalacion de repositorios ###
dnf -y install epel-release elrepo-release
sleep 5
dnf -y install https://rpms.remirepo.net/enterprise/remi-release-9.rpm
sleep 5
dnf -y install htop net-tools pwgen vim yum-utils dnf-automatic
sleep 10
dnf -y update


#### desactivando selinux ####

sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/sysconfig/selinux
sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
/usr/sbin/setenforce 0
iptables-save > /root/firewall.rules

### verificacion de instalacion de firewalld ###
if [ -f /usr/sbin/firewalld ]; then 
    echo "El servicio de firewalld, esta instalado"
    sleep 10
    else
    dnf -y install firewalld
    echo "se esta instalado el servicio"
    sleep 60
    fi
	
##### Reescribiendo /etc/resolv.conf ####

echo "nameserver 8.8.8.8" >> /etc/resolv.conf # Google
echo "nameserver 8.8.4.4" >> /etc/resolv.conf # Google
echo "nameserver 1.1.1.1" >> /etc/resolv.conf # cloudflare

##### configuracion de sistemas #####

systemctl start fstrim.timer
systemctl enable fstrim.timer

tuned-adm profile throughput-performance

cat << EOF > /etc/sysctl.conf 
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.sysrq=0
kernel.yama.ptrace_scope=3
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.log_martians=1
net.ipv6.conf.all.accept_redirects=1
net.ipv6.conf.default.accept_redirects=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_synack_retries=5
EOF

# Aumente el rango de puertos IPv4 para aceptar más conexiones
echo  "5000 65535" > /proc/sys/net/ipv4/ip_local_port_range

# Habilitar ExecShield
echo "1" > /proc/sys/kernel/randomize_va_space

# Cuántas veces volver a intentar antes de eliminar una conexión TCP viva
echo "5" > /proc/sys/net/ipv4/tcp_retries2

# establece el búfer de envío de socket máximo para todos los protocolos (en bytes) #
echo "16777216" > /proc/sys/net/core/wmem_max
echo "16777216" > /proc/sys/net/core/wmem_default

# Cambie los siguientes parámetros cuando una alta tasa de solicitudes de conexión entrantes provoque fallas en la conexión #
echo "100000" > /proc/sys/net/core/netdev_max_backlog

# Número máximo de sockets en TIME-WAIT que se mantendrán simultáneamente (predeterminado: 180000) #
echo "600000" > /proc/sys/net/ipv4/tcp_max_tw_buckets

### Parámetros de red para una mejor seguridad ###
# Deshabilitar el reenvío de paquetes (si esta máquina no es un enrutador)
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
echo "0" > /proc/sys/net/ipv4/conf/default/send_redirects

 ### Ajuste del sistema de archivos
# Aumentar el límite del descriptor de archivo del sistema
echo "7930900" > /proc/sys/fs/file-max
# Permitir más PID
echo "65536" > /proc/sys/kernel/pid_max
# Use hasta 95% de RAM (5% gratis)
echo "5" > /proc/sys/vm/swappiness
##
echo "20" > /proc/sys/vm/dirty_background_ratio
##
echo  "25" > /proc/sys/vm/dirty_ratio

### Generando logs adicional####

cp /etc/rsyslog.conf /etc/rsyslog.conf.$date

echo 'auth,user.* /var/log/user' >> /etc/rsyslog.conf
echo 'kern.* /var/log/kern.log' >> /etc/rsyslog.conf
echo 'daemon.* /var/log/daemon.log' >> /etc/rsyslog.conf
echo 'syslog.* /var/log/syslog' >> /etc/rsyslog.conf
echo 'lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log' >> /etc/rsyslog.conf
touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

systemctl restart rsyslog

### Habilitando el servicio auditd ###
systemctl enable auditd

#### configurando ssh ####

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.$date

sed -i "s/^\(#\|\)Port.*/Port $port/" /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin.*/PermitRootLogin without-password/' /etc/ssh/sshd_config
sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/#UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)AllowTcpForwarding yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)ClientAliveCountMax 3/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)Compression delayed/Compression no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)MaxSessions 10/MaxSessions 2/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)TCPKeepAlive yes/TCPKeepAlive no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)AllowAgentForwarding yes/AllowAgentForwarding no/' /etc/ssh/sshd_config
sed -i 's/^\(#\|\)LoginGraceTime 2m/LoginGraceTime 20/' /etc/ssh/sshd_config

mkdir .ssh/authorized_keys

### Reinicio de servicio ###
systemctl restart sshd

firewall-cmd --permanent --add-port=$port/tcp
firewall-cmd --reload

dnf -y install nginx
cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.$date
sed -i "41,9 s/server_name .*/server_name $host;/g" /etc/nginx/nginx.conf
sed -i "s/^\(#\|\)worker_processes.*/worker_processes $cpu;/g" /etc/nginx/nginx.conf
sed -i "40,9 s/listen .*/#listen [::]:80 default_server;/g" /etc/nginx/nginx.conf

#### configurando userdir nginx ####
sed -i '46G' /etc/nginx/nginx.conf
sed -i '47i \location ~ ^/~(.+?)(/.*)?$ { \n' /etc/nginx/nginx.conf
sed -i '48i \alias /home/$1/public_html$2; \n' /etc/nginx/nginx.conf
sed -i '49i \index  index.html index.htm index.php; \n' /etc/nginx/nginx.conf
sed -i '50i \} \n' /etc/nginx/nginx.conf

systemctl enable --now nginx

##### Iplementacion de correo #####

dnf -y install exim mailx

cp /etc/exim/exim.conf /etc/exim/exim.conf.bkp

## Configuracion exim ##

systemctl enable --now exim dovecot spamassassin

### Instalacion del motor de base de datos ###
dnf install MariaDB-server -y
systemctl start mariadb

#### Instalacion de FTP ####

dnf -y install vsftpd

cp /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.$date

sed -i "s/^\(#\|\)ascii_upload_enable=YES/ascii_upload_enable=YES/" /etc/vsftpd/vsftpd.conf
sed -i "s/^\(#\|\)ascii_download_enable=YES/ascii_download_enable=YES/" /etc/vsftpd/vsftpd.conf
sed -i "s/^\(#\|\)chroot_local_user=YES/chroot_local_user=YES/" /etc/vsftpd/vsftpd.conf
sed -i "s/^\(#\|\)chroot_list_enable=YES/chroot_list_enable=YES/" /etc/vsftpd/vsftpd.conf
sed -i "s/^\(#\|\)ls_recurse_enable=YES/ls_recurse_enable=YES/" /etc/vsftpd/vsftpd.conf
sed -i 's/listen=NO/listen=YES/' /etc/vsftpd/vsftpd.conf
sed -i 's/listen_ipv6=YES/listen_ipv6=NO/' /etc/vsftpd/vsftpd.conf
echo "local_root=public_html" >> /etc/vsftpd/vsftpd.conf
echo "use_localtime=YES" >> /etc/vsftpd/vsftpd.conf
echo "seccomp_sandbox=NO" >> /etc/vsftpd/vsftpd.conf
echo "chroot_list_file=/etc/vsftpd/chroot_list" >> /etc/vsftpd/vsftpd.conf


touch /etc/vsftpd/chroot_list

systemctl enable --now vsftpd

#### Instalacion de php ####
dnf module -y reset php
dnf module -y enable php:remi-8.1
dnf module -y install php:remi-8.1/devel
dnf -y install php81-php-snmp php81-unit-php php81-php-pecl-redis5 php81-php-pecl-memcached php81-php-fpm php81-php-pdo php81-php-opcache php81-php-mbstring php81 php81-php-soap php81-php-xml php81-php-mysqlnd php81-php-intl

sleep 5

#### Instalacion de nodejs ####
dnf module -y reset nodejs
dnf module -y enable nodejs:16
dnf module -y install nodejs:16/common

### instalacion del serviico dns ###
dnf -y install bind bind-utils

cp /etc/named.conf /etc/named.conf.bkp

echo 'OPTIONS="-4"' >> /etc/sysconfig/named

systemctl enable --now named
systemctl start named

####### abrir puertos de los servicios ######

firewall-cmd --add-service=http --permanent
firewall-cmd --add-service=https --permanent
firewall-cmd --add-service=ftp --permanent
firewall-cmd --add-service=smtp --permanent
firewall-cmd --add-service=pop3 --permanent
firewall-cmd --add-service=pop3s --permanent
firewall-cmd --add-service=smtps --permanent
firewall-cmd --add-service=imap --permanent
firewall-cmd --add-service=imaps --permanent
firewall-cmd --add-service=mysql --permanent
firewall-cmd --add-service=dns --permanent

firewall-cmd --reload



### Sincronizando fecha ###

if [ -f /usr/share/zoneinfo/America/Santiago ]; then
        echo "Seteando timezone a America/Santiago..."
        mv /etc/localtime /etc/localtime.old
        ln -s /usr/share/zoneinfo/America/Santiago /etc/localtime
fi

systemctl enable --now dnf-automatic.timer

#### Seteando fecha del BIOS ####
hwclock -r

##### Asignacion de contraseña al usuario root #####

pass=$(pwgen -s1 12)

echo $pass | passwd --stdin root

##### Notificacion via mail ####

info=/info.txt

echo "--------------------------------" >> $info
echo "                                " >> $info
echo "   usuario: root                " >> $info
echo "   contraseña: $pass            " >> $info
echo "                                " >> $info
echo "--------------------------------" >> $info

cat $info | mail -s "Credenciales de accesos al servidor $host" alexalvarez@powerhost.cl

rm -rf /info.txt

### verificacion de reinicio del servidor ###

file=/report.txt

needs-restarting -r ; echo $? >> /rbt.txt
num=$(cat /rbt.txt)

if [ $num -eq "1" ]
 then
    echo "Se realiza el reinicio del servidor $host"
          shutdown -r now
else
    echo "No es necesario el reinicio del servidor"
fi

rm -rf /$CWD/nopanel.sh