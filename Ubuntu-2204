
#!/bin/bash
# Filesystem Configuration

# Bootloader Configuration

echo "Bootloader Configuration"

chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

echo "We will now Set a Bootloader Password"

grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
echo " set superusers="root" " >> /etc/grub.d/40_custom
echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
rm grubpassword.tmp
update-grub

# Crontab Configuration

echo "Crontab Configuration"

chown root:root /etc/cron*
chmod og-rwx /etc/cron*

# Network

echo "Network Configuration"

wget -O /etc/sysctl.conf https://raw.githubusercontent.com/HuyThang25/Hardening/refs/heads/main/Ubuntu-22.04/sysctl.conf
sysctl -e -p

# Configure SSH Server

echo "Configure SSH Server"

wget -O /etc/ssh/sshd_config https://raw.githubusercontent.com/HuyThang25/Hardening/refs/heads/main/Ubuntu-22.04/sshd_config

service ssh restart

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# User Accounts

echo "User Accounts Configuration"

wget -O /etc/login.defs https://raw.githubusercontent.com/HuyThang25/Hardening/refs/heads/main/Ubuntu-22.04/login.defs


for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user
  if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
    usermod -s /usr/sbin/nologin $user
  fi
  fi
done

usermod -g 0 root

sed -i s/umask\ 022/umask\ 027/g /etc/init.d/rc

# Logging and Auditing

echo "Logging Configuration"

systemctl enable rsyslog
systemctl start rsyslog
chmod -R g-wx,o-rwx /var/log/*

# System Maintenance

echo "System Maintenance Configuration"

chown root:root /etc/passwd
chmod 644 /etc/passwd

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

chown root:root /etc/group
chmod 644 /etc/group
