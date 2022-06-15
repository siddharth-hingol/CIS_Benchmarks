#!/bin/bash
set +x

###################################
# CIS Benchmark Ubuntu 20.04 v1.1.0
###################################
CIS_LEVEL=2
INCLUDE_UNSCORED=1
WIDTH=170
if [ $CIS_LEVEL -gt 1 ];then
  RESULT_FIELD=10
else
  RESULT_FIELD=6
fi
MSG_FIELD=$(($WIDTH - $RESULT_FIELD))
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
NC=$(tput sgr0)
PASSED_CHECKS=0
FAILED_CHECKS=0

function header() {
    local HEADING=$1
    local TEXT=$((${#HEADING}+2))
    local LBAR=5
    local RBAR=$(($WIDTH - $TEXT - $LBAR))
    echo ""
    for (( x=0; x < $LBAR; x++));do
        printf %s '#'
    done
    echo -n " $HEADING "
    for (( x=0; x < $RBAR; x++));do
        printf %s '#'
    done
    echo ""
}

function msg() {
  printf "%-${MSG_FIELD}s" " - ${1}"
}

function success_result() {
    PASSED_CHECKS=$((PASSED_CHECKS+1))
    local RESULT="$GREEN${1:-PASSED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function failed_result() {
    FAILED_CHECKS=$((FAILED_CHECKS+1))
    local RESULT="$RED${1:-FAILED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function warning_result() {
    local RESULT="$YELLOW${1:-NOT CHECKED}$NC"
    printf "%-${RESULT_FIELD}s\n" $RESULT
}

function check_retval_eq_0() {
  RETVAL=$1
  if [ $RETVAL -eq 0 ]; then
    success_result
  else
    failed_result
  fi
}

function check_retval_ne_0() {
  RETVAL=$1
  if [ $RETVAL -ne 0 ]; then
    success_result
  else
    failed_result
  fi
}

#################
# 1 Initial Setup
#################
  ##############################
  # 1.1 Filesystem Configuration
  ##############################
    ##################################
    # 1.1.1 Disable Unused Filesystems
    ##################################
    let i=0
    for module in cramfs freevxfs jffs2 hfs hfsplus squashfs udf;do
      i=$((i+1))
      header "1.1.1.${i} $module disabled"
      MODPROBE_COMMAND="modprobe -n -v $module"
      LSMOD_COMMAND="lsmod | grep $module"
      
      msg " $MODPROBE_COMMAND"
      if [[ $(eval $MODPROBE_COMMAND 2>&1) =~ install.*/bin/true ]];then
          LEVEL1_PASSED=$(($LEVEL1_PASSED + 1))
          success_result
      else
          LEVEL1_FAILED=$(($LEVEL1_FAILED + 1))
          failed_result
      fi
  
      msg " $LSMOD_COMMAND"
      if [[ $(eval $LSMOD_COMMAND 2>&1) =~ ^$ ]];then
          success_result
      else
          failed_result
      fi
    done

    ##################################
    # 1.1.2 - 1.1.5 /tmp setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        FURTHER_TMP_CHECKS=1
        header "1.1.2 Ensure /tmp is configured"
        msg " findmnt -n /tmp"
        findmnt -n ^/tmp 2>&1 > /dev/null
        check_retval_eq_0 $?
    
        if [ $FURTHER_TMP_CHECKS -gt 0 ];then
            let tmp=2
            for option in nodev nosuid noexec;do
                tmp=$((tmp+1))
                header "1.1.${tmp} Ensure $option option set on /tmp"
                msg " findmnt -n /tmp | grep -v $option"
                findmnt -n ^/tmp | grep -v $option 2>&1 > /dev/null
                check_retval_eq_0 $?
            done
        fi
    fi

    ##################################
    # 1.1.6 - 1.1.9 /dev/shm setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        FURTHER_TMP_CHECKS=1
        header "1.1.6 Ensure /dev/shm is configured"
        msg " findmnt -n /dev/shm"
        findmnt -n ^/dev/shm 2>&1 > /dev/null
        check_retval_eq_0 $?
    
        if [ $FURTHER_TMP_CHECKS -gt 0 ];then
            let tmp=6
            for option in nodev nosuid noexec;do
                tmp=$((tmp+1))
                header "1.1.${tmp} Ensure $option option set on /tmp"
                msg " findmnt -n /dev/shm | grep -v $option"
                findmnt -n ^/dev/shm | grep -v $option 2>&1 > /dev/null
                check_retval_eq_0 $?
            done
        fi
    fi

    ##################################
    # 1.1.10 /var setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
      header "1.1.10 Ensure separate partition exists for /var"
      msg " findmnt /var"
      findmnt ^/var 2>&1 > /dev/null
      check_retval_eq_0 $?
    fi

    ##################################
    # 1.1.11 /var/tmp setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
      FURTHER_VAR_TMP_CHECKS=1
      header "1.1.11 Ensure separate partition exists for /var/tmp"
      msg " findmnt /var/tmp"
      findmnt ^/var/tmp 2>&1 > /dev/null
      if [ $? -eq 0 ];then
          success_result
      else
          FURTHER_VAR_TMP_CHECKS=0
          failed_result
      fi
  
      if [ $FURTHER_VAR_TMP_CHECKS -gt 0 ];then
          let tmp=11
          for option in nodev nosuid noexec;do
              tmp=$((tmp+1))
              header "1.1.${tmp} Ensure /var/tmp partition includes the $option option"
              msg " findmnt -n /var/tmp | grep -v  $option"
              findmnt -n ^/var/tmp | grep -v $option 2>&1 > /dev/null
              check_retval_eq_0 $?
          done
      fi
    fi
    
    ##################################
    # 1.1.15 /var/log setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.1.15 Ensure separate partition exists for /var/log"
        msg " findmnt /var/log"
        findmnt ^/var/log 2>&1 > /dev/null
        check_retval_eq_0 $?
    fi

    ##################################
    # 1.1.16 /var/log/audit setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.1.16 Ensure separate partition exists for /var/log/audit"
        msg " findmnt /var/log/audit"
        findmnt ^/var/log/audit 2>&1 > /dev/null
        check_retval_eq_0 $?
    fi

    ##################################
    # 1.1.17 /home setup
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        FURTHER_HOME_CHECKS=1
        header "1.1.17 Ensure separate partition exists for /home"
        msg " findmnt /home"
        findmnt ^/home 2>&1 > /dev/null
        check_retval_eq_0 $?
    
        if [ $FURTHER_HOME_CHECKS -gt 0 ];then
            let tmp=17
            for option in nodev;do
                tmp=$((tmp+1))
                header "1.1.${tmp} Ensure $option mount option set on /home"
                msg " findmnt -n /home | grep -v $option"
                findmnt -n /home | grep -v $option 2>&1 > /dev/null
                check_retval_eq_0 $?
            done
        fi
    fi

    ##################################
    # 1.1.19 - 1.1.21 removable media
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.1.19 Ensure nodev option set on removable media partitions"
        msg " mount | grep nodev"
        mount | grep nodev 2>&1 > /dev/null
        check_retval_eq_0 $?

        if [ $FURTHER_HOME_CHECKS -gt 0 ];then
            let tmp=19
            for option in nosuid noexec;do
                tmp=$((tmp+1))
                header "1.1.${tmp} Ensure $option option set on removable media partitions"
                msg " mount | grep $option"
                mount | grep $option 2>&1 > /dev/null
                check_retval_eq_0 $?
            done
        fi 
    fi

    ##################################
    # 1.1.22 Sticky Bit Set
    ##################################
    header "1.1.22 Ensure sticky bit is set on all world-writable directories"
    msg
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
    check_retval_eq_0 $?

    ##################################
    # 1.1.23 Disable Automounting
    ##################################
    header "1.1.23 Disable Automounting"
    msg " systemctl is-enabled autofs"
    if ! [[ $(systemctl is-enabled autofs 2>&1) =~ ^enabled$ ]];then
        success_result
    else
        failed_result
    fi

    ##################################
    # 1.1.24 Disable USB Storage
    ##################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.1.24 Disable USB Storage"
        msg " modprobe -n -v usb-storage"
        if ! [[ $(modprobe -n -v usb-storage 2>&1) =~ ^/bin/true$ ]];then
          success_result
        else
          failed_result
        fi
    fi

    if [ $CIS_LEVEL -gt 1 ];then
        #header "1.1.24 Disable USB Storage"
        msg " lsmod | grep usb-storage"
        if ! [[ $(lsmod | grep usb-storage 2>&1) == 0 ]];then
          success_result
        else
          failed_result
        fi
    fi

  ################################
  # 1.2 Configure Software Updates
  ################################
    ##########################################################
    # 1.2.1 Ensure package manager repositories are configured
    ##########################################################
    if [ $INCLUDE_UNSCORED -gt 0 ];then
        header "1.2.1 Ensure package manager repositories are configured"
        msg " apt-cache policy"
        warning_result
    fi

    #######################################
    # 1.2.2 Ensure GPG Keys are configured
    #######################################
    if [ $INCLUDE_UNSCORED -gt 0 ];then
        header "1.2.2 Ensure GPG keys are configured"
        msg " apt-key list"
        warning_result
    fi

  ###################################
  # 1.3 Filesystem Integrity Checking
  ###################################
    #######################################
    # 1.3.1 Ensure AIDE is installed
    #######################################
    header "1.3.1 aide installed"
    msg " dpkg -s aide"
    dpkg -s aide >/dev/null 2>/dev/null
    check_retval_eq_0 $?

    msg " dpkg -s aide-common"
    dpkg -s aide-common >/dev/null 2>/dev/null
    check_retval_eq_0 $?

    ########################################################
    # 1.3.2 Ensure filesystem integrity is regularly checked
    ########################################################
    header "1.3.2 Ensure filesystem integrity is regularly checked"
    msg " Verifying cron job scheduled to run the aide check."
    grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--check|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ 2>&1
    check_retval_eq_0 $?

    msg " systemctl is-enabled aidecheck.service"
    systemctl is-enabled aidecheck.service 2>/dev/null
    check_retval_eq_0 $?

    msg " systemctl is-enabled aidecheck.timer"
    systemctl is-enabled aidecheck.timer 2>/dev/null
    check_retval_eq_0 $?

    msg " systemctl status aidecheck.timer"
    systemctl status aidecheck.timer 2>/dev/null
    check_retval_eq_0 $?

  ################################
  # 1.4 Secure Boot Settings
  ################################
    ##################################################################
    # 1.4.1 Ensure permissions on bootloader config are not overridden
    ##################################################################
    header "1.4.1 Check bootlader filesystem permissions"
    msg " Ensure permissions on /boot/grub/grub.cfg are 0400"
    if [[ $(stat /boot/grub/grub.cfg) =~ Access:.*(0400/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #########################################
    # 1.4.2 Ensure bootloader password is set
    #########################################
    header "1.4.2 Ensure bootloader password is set"
    msg ' grep "^set superusers" /boot/grub/grub.cfg'
    grep "^set superusers" /boot/grub/grub.cfg 2>&1 > /dev/null
    check_retval_eq_0 $?
    
    msg ' grep "^password" /boot/grub/grub.cfg'
    grep "^password" /boot/grub/grub.cfg 2>&1 > /dev/null
    check_retval_eq_0 $?

    ##############################################################
    # 1.4.3 Ensure permissions on bootloader config are configured
    ##############################################################
    header "1.4.3 Ensure permissions on bootloader config are configured"
    msg ' stat /boot/grub/grub.cfg'
    if [[ $(stat /boot/grub/grub.cfg) =~ Access:.*(0400/-rw-------).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    ###########################################################
    # 1.4.4 Ensure authentication required for single user mode
    ###########################################################
    header "1.4.4 Ensure authentication required for single user mode"
    msg ' Verifying if a password is set for the root user'
    grep -Eq '^root:\$[0-9]' /etc/shadow || echo "root is locked" 2>&1 > /dev/null
    check_retval_eq_0 $?

  ##################################
  # 1.5 Additional Process Hardening
  ##################################
    ########################################
    # 1.5.1 Ensure XD/NX support is enabled
    ########################################
    header "1.5.1 Ensure XD/NX support is enabled"
    msg " Verifying the kernel has identified and activated NX/XD protection"
        if ! [[ $(journalctl | grep 'protection: active' 2>&1) == 1 ]];then
          success_result
        else
          failed_result
        fi
    
    ###################################################################
    # 1.5.2 Ensure address space layout randomization (ASLR) is enabled
    ###################################################################
    header "1.5.2 Ensure ASLR is enabled"
    msg 'sysctl kernel.randomize_va_space'
    if [[ "$(sysctl kernel.randomize_va_space)" == "kernel.randomize_va_space = 2" ]];then
        success_result
    else
        failed_result
    fi

    msg 'randomize_va_space in /etc/sysctl.conf, /etc/sysctl.d/*.conf, /usr/lib/sysctl.d/*.conf, /usr/local/lib/sysctl.d/*.conf, /run/sysctl.d/*.conf'
    if [[ `grep -Es "^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /run/sysctl.d/*.conf` == 0 ]];then
        success_result
    else
        failed_result
    fi

    #######################################
    # 1.5.3 Ensure prelink is not Installed
    #######################################
    header "1.5.3 Ensure prelink is not Installed"
    msg 'Verify prelink is not installed'
    if [[ "$(dpkg -s prelink 2>&1)" =~ "dpkg-query: package 'prelink' is not installed and no information is available" ]];then
        success_result
    else
        failed_result
    fi

    ########################################
    # 1.5.4 Ensure core dumps are restricted
    ########################################
    header "1.5.4 Ensure core dumps are restricted"
    msg 'grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*'
    grep -Es '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/* 2>&1 > /dev/null
    check_retval_eq_0 $?

    msg ' sysctl fs.suid_dumpable'
    if [[ "$(sysctl fs.suid_dumpable)" == "fs.suid_dumpable = 0" ]];then
        success_result
    else
        failed_result
    fi

    msg ' sysctl fs.suid_dumpable /etc/sysctl.conf /etc/sysctl.d/*'
    if [[ "$(grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*)" == "fs.suid_dumpable = 0" ]];then
        success_result
    else
        failed_result
    fi

    msg ' check if systemd-coredump is installed'
    if [[ "$(systemctl is-enabled coredump.service 2>&1)" =~ "enabled disabled masked" ]];then
        success_result
    else
        failed_result
    fi

  ##############################
  # 1.6 Mandatory Access Control
  ##############################
    ##########################
    # 1.6.1 Configure AppArmor
    ##########################
      #######################################
      # 1.6.1.1 Ensure AppArmor is installed
      #######################################
      header "1.6.1.1 Ensure AppArmor is installed"
      msg 'Verify that AppArmor is installed'
      if [[ "$(dpkg -s apparmor | grep -E '(Status:|not installed)' 2>&1)" =~ "Status: install ok installed" ]];then
        success_result
      else
        failed_result
      fi

      ####################################################################
      # 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
      ####################################################################
      header "1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration"
      msg 'verify that all linux lines have the apparmor=1 parameter set'
      grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1" 2>&1 > /dev/null
      check_retval_ne_0 $?

      msg 'verify that all linux lines have the security=apparmor parameter set'
      grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor" 2>&1 > /dev/null
      check_retval_ne_0 $?

      ######################################################################
      # 1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
      ######################################################################
      header "1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode"
      msg 'verify that profiles are loaded, and are in either enforce or complain mode'
      if [[ "$(apparmor_status | grep profiles 2>&1)" =~ "profiles are loaded" ]];then
        success_result
      else
        failed_result
      fi
    
      msg 'verify no processes are unconfined'
      if [[ "$(apparmor_status | grep processes 2>&1)" =~ "0 processes are unconfined but have a profile defined" ]];then
        success_result
      else
        failed_result
      fi

      #####################################################
      # 1.6.1.4 Ensure all AppArmor Profiles are enforcing
      #####################################################
      header "1.6.1.4 Ensure all AppArmor Profiles are enforcing"
      msg 'verify that profiles are loaded and are not in complain mode'
      if [[ "$(apparmor_status | grep profiles 2>&1)" =~ "0 profiles are in complain mode" ]];then
        success_result
      else
        failed_result
      fi

      msg 'verify that no processes are unconfined'
      if [[ "$(apparmor_status | grep processes 2>&1)" =~ "0 processes are unconfined" ]];then
        success_result
      else
        failed_result
      fi

  ###################################
  # 1.7 Command Line Warning Banners
  ###################################
    #########################################################
    # 1.7.1 Ensure message of the day is configured properly
    #########################################################
    header "1.7.1 Ensure message of the day is configured properly"
    msg 'Verifying message of the day is configured properly'
    if [[ "$(grep -Eis "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/motd 2>&1)" =~ 0 ]];then
      success_result
    else
      failed_result
    fi

    ##################################################################
    # 1.7.2 Ensure local login warning banner is configured properly
    ##################################################################
    header "1.7.2 Ensure local login warning banner is configured properly"
    msg  " Verifying local login warning banner is configured properly"
    grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue 2>&1 > /dev/null
    check_retval_ne_0 $?

    ###################################################################
    # 1.7.3 Ensure remote login warning banner is configured properly
    ###################################################################
    header "1.7.3 Ensure remote login warning banner is configured properly"
    msg  " Verifying remote login warning banner is configured properly"
    grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/"//g'))" /etc/issue.net 2>&1 > /dev/null
    check_retval_ne_0 $?

    ##########################################################
    # 1.7.4 Ensure permissions on /etc/motd are configured
    ##########################################################
    header "1.7.4 Ensure permissions on /etc/motd"
    msg " Ensure /etc/motd permissions are 0644 root:root"
    if [[ $(stat -L /etc/motd 2>&1) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    ##########################################################
    # 1.7.5 Ensure permissions on /etc/issue are configured
    ##########################################################
    header "1.7.5 Ensure permissions on /etc/issue are configured"
    msg " Ensure /etc/issue permissions are 0644 root:root"
    if [[ $(stat -L /etc/issue 2>&1) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
        success_result
    else
        failed_result
    fi

    #############################################################
    # 1.7.6 Ensure permissions on /etc/issue.net are configured
    #############################################################
    if [ $CIS_LEVEL -gt 1 ];then
        header "1.7.6 Ensure permissions on /etc/issue.net are configured"
        msg " Ensure /etc/issue.net permissions are 0644 root:root"
        if [[ $(stat -L /etc/issue.net 2>&1) =~ Access:.*(0644/-rw-r--r--).*Uid:.*(.*0/.*root).*Gid:.*(.*0/.*root) ]];then
            success_result
        else
            failed_result
        fi
    fi

  #############################################################################
  # 1.8 GNOME Display Manager
  #############################################################################
    ################################################
    # 1.8.1 Ensure GNOME Display Manager is removed
    ################################################
    header "1.8.1 Ensure GNOME Display Manager is removed"
    msg  "verifying gdm3 is not installed"
    if [[ $(dpkg -s gdm3 2>&1) =~ (package \'gdm3\' is not installed) ]];then
        success_result
    else
        failed_result
    fi

    ##############################################
    # 1.8.2 Ensure GDM login banner is configured
    ##############################################
    header "1.8.2 Ensure GDM login banner is configured"
    msg  "Verifying /etc/gdm3/greeter.dconf-defaults file exists"
    if [[ $(cat /etc/gdm3/greeter.dconf-defaults 2>&1) =~ (banner-message-enable=true \n banner-message-text=) ]];then
        success_result
    else
        failed_result
    fi

    ############################################
    # 1.8.3 Ensure disable-user-list is enabled
    ############################################
    header "1.8.3 Ensure disable-user-list is enabled (for Ubuntu Desktop)"
    #msg  "verifying that disable-user-list is enabled"
    #grep -E '^\s*disable-user-list\s*=\s*true\b' 2>&1 > /dev/null
    #check_retval_ne_0 $?

    ####################################
    # 1.8.4 Ensure XDCMP is not enabled
    ####################################
    header "1.8.4 Ensure XDCMP is not enabled"
    msg  "Verifying XDCMP is not enabled"
    grep -Eis '^\s*Enable\s*=\s*true' /etc/gdm3/custom.conf 2>&1 > /dev/null
    check_retval_ne_0 $?

  #############################################################################
  # 1.9 Ensure updates, patches, and additional security software are installed
  #############################################################################
    header "1.9 Ensure updates, patches, and additional security software are installed"
    msg  "Verifying there are no updates or patches to install"
    apt -s upgrade 2>&1 > /dev/null 
    check_retval_eq_0 $?
    
