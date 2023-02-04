#!/bin/bash
#Precheck-scs

#### it is logging
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3
exec 1>log.out 2>&1
#############

echo -e "\n\nchange # Run Date $(date)"
####### pam remediation
echo -e "\n\n ======Pam Remediation==========================================="   #PAM remediation system-auth-org created

cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth_$(date +%F)
#ls /etc/pam.d/system-auth  || cp -f system-auth-orig /etc/pam.d/system-auth 

yes | cp -f supportFiles/system-auth-orig /etc/pam.d/system-auth

cp -p /etc/pam.d/password-auth /etc/pam.d/password-auth_$(date +%F)
#ls /etc/pam.d/password-auth || cp -f password-auth-orig /etc/pam.d/password-auth

yes | cp -f supportFiles/password-auth-orig /etc/pam.d/password-auth
#unlink /etc/pam.d/system-auth
#unlink /etc/pam.d/password-auth
echo -e "\n\n ======Pam Remediation ends======================================"

######## AUDIT REMEDIATION

echo -e "\n\n auditd Remediation==============================================="   #audit remediation both files created 
echo "AD.70.1.5.23 AD.70.1.5.29 AD.70.1.5.30 AD.70.1.5.31 AD.70.1.5.35"
cp -p /etc/audit/audit.rules /etc/audit/audit.rules_$(date +%F)
cp -f supportFiles/audit.rules-orig /etc/audit/audit.rules

cp -p /etc/audit/rules.d/50-system_local.rules /etc/audit/rules.d/50-system_local.rules_$(date +%F)
cp -f supportFiles/50-system_local.rules-orig /etc/audit/rules.d/50-system_local.rules
service auditd restart
echo -e "\n\n auditd Remediation=Ends==========================================="
########
echo "Permission change *************=====================================******"
echo "Pre permission check"
ls -l  /etc/passwd 
ls -l  /etc/passwd
ls -l  /etc/group
ls -l  /etc/group
ls -l  /etc/shadow 
ls -l  /etc/shadow
ls -l  /etc/gshadow
ls -l  /etc/gshadow

cp -p /etc/passwd /etc/passwd_$(date +%F)
cp -p /etc/passwd- /etc/passwd-_$(date +%F)
cp -p /etc/group /etc/group_$(date +%F)
cp -p /etc/group- /etc/group-_$(date +%F)
cp -p /etc/shadow /etc/shadow_$(date +%F)
cp -p /etc/shadow- /etc/shadow-_$(date +%F)
cp -p /etc/gshadow /etc/gshadow_$(date +%F)
cp -p /etc/gshadow- /etc/gshadow-_$(date +%F)

chmod 644 /etc/passwd 
chmod 644 /etc/passwd-
chmod 644 /etc/group
chmod 644 /etc/group-
chmod 400 /etc/shadow 
chmod 400 /etc/shadow-
chmod 000 /etc/gshadow
chmod 000 /etc/gshadow-
echo "post permission check"
ls -l  /etc/passwd 
ls -l  /etc/passwd-
ls -l  /etc/group
ls -l  /etc/group-
ls -l  /etc/shadow 
ls -l  /etc/shadow-
ls -l  /etc/gshadow
ls -l  /etc/gshadow-
echo "Permission change *************ends==================================******"
######
echo "changes in /etc/sysctl .....==========================================......"
cp -p /etc/sysctl.conf /etc/sysctl.conf_$(date +%F)
sed -i 's/net.ip4.conf.all.log_martians=0/net.ip4.conf.all.log_martians=1/' /etc/sysctl.conf
sed -i 's/net.ip4.conf.default.log._martians=0/net.ip4.conf.default.log._martians=1/' /etc/sysctl.conf
sed -i 's/fs.suid_dumpable=0/fs.suid_dumpable=1/' /etc/sysctl.conf
grep -qxF 'net.ip4.conf.all.log_martians=1' /etc/sysctl.conf || echo 'net.ip4.conf.all.log_martians=1' >> /etc/sysctl.conf
grep -qxF 'net.ip4.conf.default.log._martians=1' /etc/sysctl.conf || echo 'net.ip4.conf.default.log._martians=1' >> /etc/sysctl.conf
grep -qxF 'fs.suid_dumpable=1' /etc/sysctl.conf || echo 'fs.suid_dumpable=1' >> /etc/sysctl.conf
egrep -H 'net.ip4.conf.default.log._martians|net.ip4.conf.all.log_martians|fs.suid_dumpable' /etc/sysctl.conf
echo "changes in /etc/sysctl .....ends========......"
######

echo "check ftp enabled or not  and remove ftp======================================"
rpm -qa | grep -i ftp 
rpm -e ftp

######
echo "Disable TIPS, RDS, SCTP, DCCP==================================================="
cp -p /etc/modprobe.d/CIS.conf  /etc/modprobe.d/CIS.conf_$(date +%F) ; #cp -f CIS.conf /etc/modprobe.d/CIS.conf
grep -qxF 'install tipc /bin/true' /etc/modprobe.d/CIS.conf || echo 'install tipc /bin/true' >> /etc/modprobe.d/CIS.conf
grep -qxF 'install rds /bin/true' /etc/modprobe.d/CIS.conf || echo 'install rds /bin/true' >> /etc/modprobe.d/CIS.conf
grep -qxF 'install sctp /bin/true' /etc/modprobe.d/CIS.conf || echo 'install sctp /bin/true' >> /etc/modprobe.d/CIS.conf
grep -qxF 'install dccp /bin/true' /etc/modprobe.d/CIS.conf || echo 'install dccp /bin/true' >> /etc/modprobe.d/CIS.conf
echo "Disable TIPS, RDS, SCTP, DCCP=====================ends "
######
echo "changes in ryslog===================================" 
#check parameter in rsyslog 
#if not add parameter in rsyslog
echo "AD.70.1.2.4"
#sed -i 's/$FileCreateMode 0640/$FileCreateMode 0640/' /etc/rsyslog.conf
#grep -qxF '$FileCreateMode' /etc/rsyslog.conf &&
cp -p /etc/rsyslog.conf /etc/rsyslog.conf_$(date +%F)  # backup the file 
sed -i 's/$FileCreateMode/#$FileCreateMode/g' /etc/rsyslog.conf
sed -f supportFiles/sedfile /etc/rsyslog.conf > /etc/rsyslog.conf2  #this is also a bakup
cat /etc/rsyslog.conf2 > /etc/rsyslog.conf
# AD.70.1.2.7  change permission of log file to g-wx, o-rwx and but for /var/log/hist diffrent
find /var/log -type f -exec chmod g-wx,o-rwx {} +                  ===> need research more; but it works 
chmod o+x /var/log/hist
#sedfile >> 
sudo "AD.70.1.2.6 //For hosts that are not designated as log hosts"
egrep -H "ModLoad imtcp.so" /etc/rsyslog.conf &&  sed -i 's/\$ModLoad imtcp/#\$ModLoad imtcp/g' /etc/rsyslog.conf
egrep -H "InputTCPServerRun 514" /etc/rsyslog.conf && sed -i 's/\$InputTCPServerRun 514/#\$InputTCPServerRun 514/g' /etc/rsyslog.conf
egrep -H "ModLoad imtcp.so" /etc/rsyslog.conf
egrep -H "InputTCPServerRun 514" /etc/rsyslog.conf
service rsyslogd restart
echo "changes in rsyslog==================================END="
######
echo "change umask to 077 =============================================="
echo "AD.1.9.1.2,AD.1.9.1.3"
cp -p /etc/profile.d/IBMsinit.sh /etc/profile.d/IBMsinit.sh_$(date +%F)
cp -p /etc/profile.d/IBMsinit.csh /etc/profile.d/IBMsinit.csh_$(date +%F)
>/etc/profile.d/IBMsinit.sh
>/etc/profile.d/IBMsinit.csh
echo "if [ $UID -gt 199 ]; then" >>/etc/profile.d/IBMsinit.sh
echo -e "umask 077\nfi" >> /etc/profile.d/IBMsinit.sh
cp /etc/profile.d/IBMinit.sh /etc/profile.d/IBMsinit.csh
egrep -H umask /etc/profile.d/IBMsinit.*sh
echo "change umask to 077 ==================================Ends====="
#######
echo "add line in login.def==============================="
cp -p /etc/login.defs /etc/login.defs_$(date +%F)
sed -i 's/ENCRYPT_METHOD/#ENCRYPT_METHOD/' /etc/login.defs
echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
egrep -H ENCRYPT_METHOD /etc/login.defs | grep -v "#"
########
echo "AD.70.1.4.29 Ensure motd is configured"
chmod 644 /etc/motd
echo "Permission on Motd file = $(stat -c '%a ' /etc/motd)"
##################

echo "AD.2.1.3.2"
cp -p /etc/default/passwd /etc/default/passwd_$(date +%F)
sed -i 's/CRYPT=/#CRYPT=/g' /etc/default/passwd
sed -i 's/CRYPT_FILES=/#CRYPT_FILES=/g' /etc/default/passwd
echo -e "CRYPT=sha-512\nCRYPT_FILES=sha-512" >>/etc/default/passwd
egrep -H  CRYPT=sha-512 /etc/default/passwd
egrep -H CRYPT_FILES= /etc/default/passwd

echo "AD.70.1.2.14	Ensure cron is restricted to authorized users "
cp -p /etc/cron.deny /etc/cron.deny_$(date +%F)
ls /etc/cron.deny && cat /etc/cron.deny
>/etc/cron.deny
mv /etc/cron.deny /etc/cron.allow

echo "AD.70.1.2.33	Ensure all groups in /etc/passwd exist in /etc/group ============================"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group 
  if [ $? -ne 0 ]; then 
    echo -e "\nGroup $i is referenced by /etc/passwd but does not exist in /etc/group"; echo "===============";getent group $i;echo
  fi 
done

echo "AD.70.1.2.36	Ensure shadow group is empty -- checks only "
grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group;awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd

echo "AD.6.0.28	Permissions should be set to 700"
ls -l /home/*/.kshrc > AD.6.0.28_permission
chmod 700 /home/*/.kshrc
ls -l /home/*/.kshrc >> AD.6.0.28_permission

echo "AD.70.1.2.37	Ensure all users' home directories exist "
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
    echo "The home directory ($dir) of user $user does not exist." 
  fi 
done

echo "sticky bit check and fix "
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null >> logs/stickybitnotset
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | chmod a+t

echo "AD.70.1.4.15		Ensure gpgcheck is globally activated "
grep ^gpgcheck /etc/yum.repos.d/*
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.repos.d/*
grep ^gpgcheck /etc/yum.repos.d/*

echo "AD.70.1.4.68		Ensure no ungrouped files or directories exist"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup >> logs/AD.70.1.4.68_UnOwnedFiles
echo "AD.70.1.4.67		Ensure no unowned files or directories exist" 
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser >> logs/AD.70.1.4.67_UnGroupFiles

echo "===== motd check"
cat /etc/motd
egrep '(\\v|\\r|\\m|\\s)' /etc/motd  || echo "This computer including any devices attached to this computer and the information systems accessed from this point contain information that is confidential to National Australia Bank. Your activities and use of these facilities are monitored. Unauthorised or inappropriate use of NAB's Information Technology facilities, including but not  limited to Electronic Mail and Internet services, is against company policy and can lead to disciplinary outcomes including termination and/or legal actions. Your use of (and related activities in connection with) these facilities  is recorded and may be reviewed at any time. Use of these facilities confirm that you accept the conditions detailed  in National Australia Bank's Electronic Communications Policy, Information Security Policy and the National Australia Bank's Code of Conduct" > /etc/motd  

echo "motd end - check above line for anything releated to motd"

echo "AD.70.1.2.29		Ensure users' dot files are not group or world writable"
##below is only checking
for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.[A-Za-z0-9]*; do
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file | cut -f1 -d" "` 
      if [ `echo $fileperm | cut -c6 ` != "-" ]; then
       echo "Group Write permission set on file $file" 
      fi 
      if [ `echo $fileperm | cut -c9 ` != "-" ]; then
       echo "Other Write permission set on file $file" 
      fi 
    fi 
  done 
done
echo "================================================================="
echo "Manual remediation require - AD.1.1.7.2		Login access to account must be restricted to the physical console, or to a method that provides accountability to an individual  --"
grep pts /etc/securetty

echo "AD.70.1.4.25 -- Prelink disable " 
rpm -q prelink 
prelink -ua
yum remove prelink -y

echo " AD.70.1.4.18 Bootloader permission"
ls -l /boot/grub2/grub.cfg
chown root:root /boot/grub2/grub.cfg 
chmod og-rwx /boot/grub2/grub.cfg
