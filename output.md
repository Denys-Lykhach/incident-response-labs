# **Incident Response Lab Report**

## **1. General Information**

This lab project demonstrates common attacker behaviours (brute-force,
privilege escalation, and persistence) against Windows and Linux
endpoints and shows how to detect and respond to them using native logs
and common forensics/IR tools.

- **Environment:**

  - Windows 11 VM

  - Ubuntu Server VM

  - Kali VM

- **Tools Used:**

  - Sysinternals Suite (Process Explorer, Autoruns, TCPView, Sysmon)

  - Windows Event Viewer

  - Kali tools (Hydra, Nmap, etc.)

## **2. Attack Scenarios**

![](./media/fe78c5a86b3c26cc159b1a6d8049671646b971bd.png){width="6.5in"
height="2.8333333333333335in"}

### **🔹 Windows Attack #1: Brute-force RDP Login**

- **Attack Simulation:**

  - From Kali Linux, perform an RDP brute-force attack using Hydra.

  - Example command:

hydra -l administrator -P rockyou.txt rdp://\<windows_ip\>\
![](./media/0bbbc271f55e9625d78ae3142b9e740bfa4c08c2.png){width="6.5in"
height="2.0in"}

- **Detection:**

  - **Event Viewer:** Security logs → Event ID 4625 (Failed logon
    attempts).

  - **Sysmon:** Repeated suspicious connections from a single IP
    address.

- **Response:**

  - Block the attacker's IP address.

![](./media/ed24c7cb7fe5d25feb12fb6d2d744f81b7b93dd9.png){width="6.5in"
height="3.1770833333333335in"}

- Verify if any successful logins occurred.

PS C:\\WINDOWS\\system32\> Get-WinEvent -FilterHashtable
\@{LogName=\'Security\'; Id=4624} \|

Where-Object { \$*.Message -match \$ip } \| Select-Object TimeCreated,
\@{Name=\'Message\';Expression={\$*.Message}} \| Out-File
C:\\lab_logs\\4624_from_attacker.txt -Force

![](./media/a4a512fcf0e8c4be46ee7080a513cc1711cff34e.png){width="6.5in"
height="1.1354166666666667in"}

- **Mitigation:**

  - Configure account lockout policies.

![](./media/44ca8744bab193a1995ef3506b259ff3fd7606ca.png){width="6.5in"
height="1.6666666666666667in"}

- Restrict RDP access to VPN or specific IPs.

![](./media/2d37e0036311c77505ba49d535bbb16156f60e1d.png){width="6.5in"
height="0.4375in"}

- Disable old general RDP rules.

![](./media/e7cf31e1e922e237afd295586f7a318fb230ad85.png){width="6.5in"
height="0.3229166666666667in"}

### **🔹 Windows Attack #2: Privilege Escalation**

- **Attack Simulation:**

  - Create a local user and add it to the Administrators group

![](./media/0c5b424c6c631b81f6f633e65cfba2e30f3bec42.png){width="6.5in"
height="1.0833333333333333in"}

- **Detection:**

<!-- -->

- **Event ID 4720** --- a user account was created (shows new_user).

- **Event ID 4732** --- a member was added to the Administrators group
  (shows new_user).

- **Event ID 4672** --- special privileges assigned to a logon (evidence
  of admin session).

<!-- -->

- **Response:**

  - Disable the account: net user new_user /active:no

![](./media/19a67eb217d2227121208722c3441899bacf6b24.png){width="6.5in"
height="0.5208333333333334in"}

- Kill suspicious processes / log off sessions: quser then logoff - ID

**Mitigation:**

- Apply security patches regularly.

- Implement least‑privilege (avoid daily admin accounts).

![](./media/c89bf9fa299da67641d386fd6406a3eaa755ee55.png){width="6.5in"
height="0.3125in"}

- Harden account management (MFA for privileged accounts, restrict who
  can add admins).

### **🔹 Windows Attack #3: Malicious Persistence**

- **Attack Simulation:**

  - Add a fake executable to Windows Registry Run key or Task Scheduler
    for persistence.

![](./media/5092d21a59de19b36c26796d4aeaff4ad682c1e5.png){width="5.75in"
height="0.3541666666666667in"}

- **Detection:**

  - **Autoruns:** Displays new suspicious startup item.

- **Response:**

  - Remove malicious registry entry and executable.

![](./media/12846f21b6b1a9089f5330c6a4688ae7a774f1c7.png){width="6.5in"
height="0.4479166666666667in"}

- Perform a full endpoint scan for additional persistence mechanisms.

<!-- -->

- **Mitigation:**

  - Regularly audit startup items with Autoruns.

![](./media/c5693108bd987cfcd6af1a5614ee101ad8aac57f.png){width="6.5in"
height="1.1354166666666667in"}

![](./media/94a21eaf50c010cc8c17e88df14ce191fb968885.png){width="6.5in"
height="1.1354166666666667in"}

![](./media/e48a13bb74c32426e64355dddf8830e1a66a52db.png){width="6.5in"
height="0.5520833333333334in"}

- Use AppLocker or Windows Defender Application Control for
  whitelisting.

![](./media/9e6845badf300f0faa0b43bf7e87ee6b98a7f037.png){width="6.5in"
height="0.3333333333333333in"}

![](./media/929cfb595c43fa7b5656397b788cd79048c556a4.png){width="6.5in"
height="0.3333333333333333in"}

- Deploy EDR rules for persistence detection.

![](./media/12ec7390f9d73aa7b69c30a8f888873991996efa.png){width="6.5in"
height="0.23958333333333334in"}

![](./media/b71fed0f63e4c0dc57c59d74bb5dbaa7c666d0c5.png){width="6.5in"
height="0.2708333333333333in"}

![](./media/cb88d5a89e52c0bdbaaf28e4a74a3648d180a0e2.png){width="6.5in"
height="2.8333333333333335in"}

### **🔹 Linux Attack #1: Brute-force SSH Login**

- **Attack Simulation:**

  - From Kali Linux, brute-force SSH login to a Linux victim machine:

hydra -l root -P rockyou.txt ssh://\<linux_ip\>

![](./media/6306c63a8221c428e5421a047c17101749a6ab3b.png){width="6.5in"
height="1.3645833333333333in"}\
![](./media/c0523d37395353389047845a081887d356823545.png){width="6.5in"
height="3.1770833333333335in"}

- **Detection:**

  - **/var/log/auth.log:** Access from a suspicious IP address.

- **Response:**

  - Block attacker's IP via firewall:

sudo ufw deny from \<attacker_ip\>

![](./media/88e679a222fce0acb4d7d5a1e7f2d933f9928faf.png){width="6.5in"
height="1.3854166666666667in"}\
![](./media/0480bf47607720779ca14b019511f8085367532a.png){width="6.5in"
height="1.5833333333333333in"}

![](./media/2409074a6c986a6d314de458974c12e7ca0dd8f8.png){width="6.5in"
height="0.2708333333333333in"}

- **Mitigation:**

  - Use SSH keys instead of passwords.

  - Restrict SSH access by IP or VPN.

  - Deploy Fail2ban or similar intrusion prevention tools.

![](./media/cb6a424c687acfa023f44a05ec48e046caaec9b5.png){width="5.75in"
height="0.65625in"}

![](./media/5e22aab722694d2b94e122f607d7e268a3df9296.png){width="6.5in"
height="3.6770833333333335in"}

![](./media/2e3eb25ee53932a0268b1048ad19054348d6814f.png){width="6.5in"
height="2.59375in"}

### **🔹 Linux Attack #2: Privilege Escalation**

- **Attack Simulation:**

  - Local Privilege Escalation: a program was compiled, made root-owned
    with the SUID bit, and a NOPASSWD sudo entry was added, allowing a
    root shell to be obtained.

![](./media/880da6dbc4200967ad0bee5a8d41ed037a1cd617.png){width="6.5in"
height="2.9583333333333335in"}

- **Detection:**

  - **Auditd logs:** Commands executed with elevated privileges.

> grep \'COMMAND=\' auth.log
>
> The audit log shows that a file /tmp/suid-shell was created and
> compiled with root privileges, indicating preparation for local
> privilege escalation. The SUID bit was set on this file and a NOPASSWD
> sudoers entry was added for testuser, allowing commands to run as root
> without a password. Finally, auth.log confirms that testuser
> successfully executed a command as root, providing clear evidence of a
> successful local privilege escalation attack.

- **Response:**

  - Review and remediate altered configurations.

  - Remove SUID binaries and roll back sudoers.

![](./media/cfaf50184003a0e52f6dacf275cf6c00f6132aa2.png){width="6.5in"
height="0.6041666666666666in"}

- **Mitigation:**

  - Apply principle of least privilege for sudo.

  - Audit and remove unnecessary SUID binaries.

  - Enforce SELinux/AppArmor profiles.

![](./media/936e6b5cb727550353713fa4b0de0a18bc4e4d1f.png){width="6.5in"
height="1.9375in"}

### **🔹 Linux Attack #3: Malicious Cronjob Persistence**

- **Attack Simulation:**

  - Add a malicious cronjob:

echo \"\* \* \* \* \* /tmp/malware.sh\" \>\> /etc/crontab

![](./media/4f1d4d13ec54ab5ab5a32f96c1e0d5934094807b.png){width="6.5in"
height="2.46875in"}

- **Detection:**

  - **Check crontab:**

crontab -l\
cat /etc/crontab

- **Syslog/journalctl:** Logs showing repetitive process execution.

<!-- -->

- **Response:**

  - Remove malicious cronjob entry and the script.

![](./media/de506686a3a8f0adeed3b00b791cadd6bc34e8a4.png){width="6.5in"
height="3.0625in"}

- **Mitigation:**

  - Regularly audit crontabs and systemd timers.

  - Monitor for changes in /etc.

  - Limit write access to system cron files.

![](./media/57f94960b5d06c022d6e709e135a6f814992ff09.png){width="6.5in"
height="0.625in"}

## **3. Conclusions**

- The simulations demonstrated how common attack vectors (brute-force,
  privilege escalation, persistence) can be executed and detected using
  native system logs and tools like Sysinternals.

- Early detection is possible through proactive log monitoring and
  process analysis.

- Long-term security relies on **patching, access control, and
  continuous monitoring**.

![](./media/82b787b3f005534aadceefe1eeef9c10fc7df9d7.png){width="6.5in"
height="2.1145833333333335in"}

## **4. Appendices**

- Mapping to **MITRE ATT&CK techniques**:

  - **Brute-force:** T1110

  - **Privilege Escalation:** T1068

  - **Persistence via Registry/Startup/Crontab:** T1547 / T1053

- Commands used in the lab:

## **Windows --- Offensive / Attack**

  ----------------------------------------------------------------------------------------
  **Command**                                                   **Purpose**
  ------------------------------------------------------------- --------------------------
  hydra -l administrator -P rockyou.txt rdp://\<windows_ip\>    RDP brute-force attack
                                                                from Kali.

  reg add                                                       Create a Registry Run key
  \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"   to achieve persistent
  /v MaliciousSvc /t REG_SZ /d \"C:\\mal\\mal.exe\" /f          on-boot execution.

  schtasks /create /sc onlogon /tn \"MalSvc\" /tr               Create a scheduled task
  \"C:\\mal\\mal.exe\"                                          that runs at user logon
                                                                (persistence).

  net user new_user P@ssw0rd /add                               Create a local user
                                                                account (example for
                                                                escalation/persistence).

  net localgroup Administrators new_user /add                   Add a local user to the
                                                                Administrators group
                                                                (privilege escalation).
  ----------------------------------------------------------------------------------------

## **Windows --- Detection & Response**

  ---------------------------------------------------------------------------
  **Command / Action**                                 **Purpose**
  ---------------------------------------------------- ----------------------
  Get-WinEvent -FilterHashtable                        Export successful
  \@{LogName=\'Security\'; Id=4624} \| Where-Object {  logon events (ID 4624)
  \$\_.Message -match \$ip } \| Select-Object          filtered by attacker
  TimeCreated,                                         IP to a file for
  \@{Name=\'Message\';Expression={\$\_.Message}} \|    analysis.
  Out-File C:\\lab_logs\\4624_from_attacker.txt -Force 

  net user \<username\> /active:no                     Disable a suspicious
                                                       or compromised local
                                                       account.

  quser                                                List current
                                                       interactive sessions
                                                       on the host.

  logoff \<ID\>                                        Terminate a specific
                                                       interactive session by
                                                       session ID.

  (Autoruns GUI)                                       Enumerate Windows
                                                       startup locations and
                                                       entries to find
                                                       persistence
                                                       mechanisms.

  (Process Explorer GUI)                               Inspect running
                                                       processes and their
                                                       properties for
                                                       suspicious activity.

  (TCPView GUI)                                        View active TCP/UDP
                                                       connections and
                                                       associated processes.

  (Sysmon installation + Event Viewer)                 Enable and review
                                                       detailed
                                                       process/file/network
                                                       telemetry for
                                                       detection and forensic
                                                       analysis.
  ---------------------------------------------------------------------------

## **Linux --- Offensive / Attack**

  -----------------------------------------------------------------------
  **Command**                      **Purpose**
  -------------------------------- --------------------------------------
  hydra -l root -P rockyou.txt     SSH brute-force attack from Kali.
  ssh://\<linux_ip\>               

  echo \"\* \* \* \* \*            Add a malicious system cron entry for
  /tmp/malware.sh\" \>\>           frequent/persistent execution.
  /etc/crontab                     

  gcc /tmp/suid.c -o               Compile an example SUID binary (used
  /tmp/suid-shell                  in privilege escalation
                                   demonstrations).

  chown root:root /tmp/suid-shell  Set owner to root for an SUID binary.

  chmod 4755 /tmp/suid-shell       Set SUID bit to allow binary to run
                                   with owner (root) privileges.

  *(visudo edit)* testuser         Add a NOPASSWD sudoers entry (example
  ALL=(ALL) NOPASSWD:              used to demonstrate sudo abuse).
  /tmp/suid-shell                  
  -----------------------------------------------------------------------

## **Linux --- Detection & Response**

  -----------------------------------------------------------------------
  **Command**                   **Purpose**
  ----------------------------- -----------------------------------------
  sudo tail -n 200              View recent authentication events and SSH
  /var/log/auth.log             attempts.

  journalctl -u ssh             View SSH service logs on systemd systems.

  crontab -l                    List the current user\'s crontab entries.

  cat /etc/crontab              Inspect system crontab for unauthorized
                                entries.

  grep \'COMMAND=\'             Search authentication logs for executed
  /var/log/auth.log             commands (sudo/ssh command logging).

  ausearch -m USER_CMD          Query auditd for recorded user command
                                execution events.

  sudo ufw deny from            Block an attacker IP address using UFW
  \<attacker_ip\>               firewall.

  rm /tmp/suid-shell or chmod   Remove or neutralize unauthorized SUID
  0755 /tmp/suid-shell          binaries as remediation.

  *(visudo edit)*               Remove malicious sudoers entries via safe
                                editor (visudo).
  -----------------------------------------------------------------------
