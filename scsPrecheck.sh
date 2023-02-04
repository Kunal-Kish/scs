# Pre Patch Script - Start
#!/bin/bash
# Remove old file
tar czf /var/tmp/scs_check.gz /var/tmp/scs_check
/bin/rm -rf /var/tmp/scs_check
mkdir -p /var/tmp/scs_check
# Data Collection backups
cp -p /etc/default/passwd /var/tmp/scs_check/passwd_bkp_$(date +%F)
cp -p /etc/pam.d/system-auth /var/tmp/scs_check/system-auth_bkp_$(date +%F)
cp -p /etc/pam.d/password-auth /var/tmp/scs_check/password-auth_bkp_$(date +%F)
cp -p /etc/login.defs /var/tmp/scs_check/login.defs_bkp_$(date +%F)
cp -p /etc/profile.d/IBMsinit.sh /var/tmp/scs_check/IBMsinit.sh_bkp_$(date +%F)
cp -p /etc/profile.d/IBMsinit.csh /var/tmp/scs_check/IBMsinit.csh_bkp_$(date +%F)
cp -p /etc/rsyslog.conf /var/tmp/scs_check/rsyslog.conf_bkp_$(date +%F)
cp -p /etc/audit/auditd.conf /var/tmp/scs_check/auditd.conf_bkp_$(date +%F)
cp -p /etc/audit/audit.rules /var/tmp/scs_check/audit.rules_bkp_$(date +%F)
cp -p /etc/audit/rules.d/50-system_local.rules /var/tmp/scs_check/50-system_local.rules_bkp_$(date +%F)
cp -p /etc/sysctl.conf /var/tmp/scs_check/sysctl.conf_bkp_$(date +%F)

#output
ls -l /etc/passwd* >> /var/tmp/scs_check/permissionlog.txt
ls -l /etc/group*  >> /var/tmp/scs_check/permissionlog.txt
ls -l /etc/*shadow* >> /var/tmp/scs_check/permissionlog.txt

# Pre Patch Script - End