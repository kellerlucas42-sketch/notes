# 🛡️ CCDC Hardening & Remediation Guide

**Environment:** VyOS gateway (`bedrock`) · Ubuntu 18.04 (`iron`) · Windows Server 2016 (`lapis`) · Rocky 9.6 + Splunk (`redstone`)

> ⚠️ **Golden rule:** Never change scored account credentials without filing a PCR at `scoring.byuccdc.org`, and never alter a service's expected behavior/content just to "beat" the check — that's a disqualifying offense. Harden the *real* service; don't fake it.

---

## 📋 Table of Contents

1. [First 30 Minutes](#-first-30-minutes-on-every-box)
2. [General Linux Hardening](#-general-linux-hardening)
3. [General Windows Hardening](#-general-windows-hardening)
4. [Service-Specific Hardening](#-service-specific-hardening)
5. [Splunk / Logging](#-splunk--logging-redstone)
6. [Windows Event ID Reference](#-windows-event-id-reference-security-log)
7. [VyOS Firewall / Gateway](#-vyos-firewallgateway-bedrock)
8. [Command-Line Cheat Sheet](#-command-line-cheat-sheet)
9. [Operational Reminders](#-operational-reminders)

---

## ⏱ First 30 Minutes on Every Box

Do this **before** touching any configs — you need a baseline to compare against later.

| Step | Linux | Windows |
|---|---|---|
| Inventory listeners | `ss -tulnp` | `netstat -ano` |
| Inventory processes | `ps aux` | Task Manager → Details |
| Check scheduled jobs | `crontab -l -u <user>` (for **every** user) + `/etc/cron.*` | Task Scheduler / `Get-ScheduledTask` |
| Check logged-in users | `last`, `w` | `net user`, `qwinsta` |
| Check privileged accounts | `/etc/passwd` + `/etc/shadow` for unexpected UID 0 | Local Administrators group |

**Then:**

- [ ] Back up every config you're about to touch (`sshd_config`, httpd/nginx configs, `named.conf`, `smb.conf`, DNS zone files, IIS bindings) to a safe local path — you need fast rollback if scoring breaks.
- [ ] Disable/rename any local account **not** on the required list. Do **not** touch credentials of required scored accounts without a PCR.
- [ ] Lock down SSH key access — remove any `authorized_keys` entries you didn't add.
- [ ] Rotate root/Administrator passwords that are **not** part of a scored check.
- [ ] Kill/disable anything listening that you don't recognize (rogue web servers, extra FTP daemons, reverse shells).
- [ ] Confirm Splunk forwarders on `iron`/`lapis` point only where expected — flag any extra destination.

---

## 🐧 General Linux Hardening
*(`iron` – Ubuntu 18.04, `redstone` – Rocky 9.6)*

### SSH — `/etc/ssh/sshd_config`

```
PermitRootLogin no          # unless root login is a scored requirement — verify first
MaxAuthTries 3
Protocol 2
PermitEmptyPasswords no
X11Forwarding no
AllowUsers steve alex <scored-service-accounts>
```
Then: `systemctl restart sshd`

> Leave `PasswordAuthentication` **on** only if a scored check needs password auth for `steve`. Otherwise, key-based only.

### Firewall (host-based, on top of VyOS)

| OS | Tool | Notes |
|---|---|---|
| Ubuntu | `ufw` / `iptables` | Allow only scored ports + SSH from mgmt network; log drops |
| Rocky 9.6 | `firewalld` | `firewall-cmd --list-all` → strip anything not required |

### Other essentials

- **Patch carefully** — a version bump can break an MD5/content-based scoring check. Check the current version before upgrading.
- **Disable unneeded services:** `systemctl list-unit-files --state=enabled` → `systemctl disable --now <svc>` (avahi, cups, rpcbind, etc.)
- **Sudoers audit:** review `/etc/sudoers` and `/etc/sudoers.d/`, strip wildcard `NOPASSWD` entries you didn't add.
- **File integrity:** `auditd` (Rocky) / `auditd` or `aide` (Ubuntu) watching `/etc/passwd`, `/etc/shadow`, `sshd_config`, and the web root.
- **Persistence hunt:** every crontab, `/etc/cron.*`, `systemctl list-timers`.
- **sysctl hardening:**
  ```
  net.ipv4.ip_forward = 0
  net.ipv4.tcp_syncookies = 1
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.all.accept_source_route = 0
  ```

---

## 🪟 General Windows Hardening
*(`lapis` – Windows Server 2016)*

- **Local Administrators:** `net localgroup administrators` → remove anything that isn't `steve`/`alex`/required admins.
- **Windows Firewall:** enable; restrict inbound to scored ports + mgmt-subnet-only RDP/SSH.
- **SMBv1:** `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` — classic pivot vector, rarely scored.
- **Defender / logging:** enable real-time AV if present; bump Security + System log retention; forward to Splunk.
- **Accounts:** disable Guest, remove unneeded local accounts. **Check lockout threshold** — red team can DoS your scored logins by intentionally tripping it.
- **Persistence hunt:** `Get-ScheduledTask`, `Get-Service`.
- **RDP:** restrict via firewall + NLA. If RDP is scored, don't disable it outright — confirm against the rubric first (RDP login is an explicit scored check type).

---

## 🎯 Service-Specific Hardening

### 🌐 HTTP/HTTPS
- Never swap the web server or fake a static responder to match the check — disqualifying.
- Patch to a compatible minor version only if it won't break content/MD5 checks.
- Remove default/sample pages, directory listing (`Options -Indexes` / `autoindex off`), and version banners (`ServerTokens Prod`, `server_tokens off`).
- Lock down upload directories: correct perms, no execution in upload paths.
- If dynamic: parameterize queries (SQLi), trim `disable_functions` in `php.ini`.
- Log everything; watch for sqlmap/nikto signatures, mass 404s, admin-panel probing.

### 🔑 SSH
- Config hardening — see [General Linux](#-general-linux-hardening) above.
- `fail2ban` for brute force — **scope bans away from the scoring engine's IP** or use a generous threshold so you don't lock yourself out of points.
- Monitor `/var/log/auth.log` (Ubuntu) / `/var/log/secure` (Rocky).
- Audit every account's `~/.ssh/authorized_keys`.

### 📁 FTP
- Plaintext by nature — if switching to FTPS/SFTP breaks the scored check, harden the daemon instead:
  ```
  anonymous_enable=NO
  chroot_local_user=YES
  local_umask=022
  ```
- Restrict `write_enable` to only what's required; remove test/demo accounts.
- Watch for **anonymous write access** — one of the most common CCDC FTP footholds.

### 🗂️ AD/DNS
**Active Directory**
- Audit Domain Admins / Enterprise Admins membership — red team loves adding itself here.
- Forward auth events (4624/4625/4720/4728) to Splunk.
- Tighten lockout policy without breaking the scored LDAP login.
- Disable NTLMv1/LM hashes where it won't break required auth.
- Check GPOs for unauthorized changes (a favorite persistence vector).

**DNS**
- Restrict zone transfers (AXFR) to authorized secondaries only — **the** most common CCDC DNS finding.
- Review zone records for injected/unauthorized A/CNAME entries.
- Disable recursion for untrusted clients if the box also does internal resolution.

### 📧 POP3
- Enforce TLS/STARTTLS **only** if it won't break the scored check (often it will — verify first).
- Restrict to required mailboxes; disable open relay/unauthenticated access.
- Rate-limit login attempts.
- Patch the specific daemon (e.g., Dovecot) if version allows without breaking the check.

---

## 📊 Splunk / Logging (`redstone`)

- No scored services here — this box is your detection hub, not something to lock down at the cost of visibility.
- Confirm `iron`/`lapis` forwarders point only to the expected indexer(s); flag anything unexpected.
- Build alerts for:
  - Repeated auth failures
  - New local admin / sudo group membership
  - New listening ports
  - Web server error spikes
  - DNS zone transfer attempts
- Protect the Splunk admin UI itself — restrict to mgmt network, change the admin password beyond the shared default if scoring allows.

---

## 🕵️ Windows Event ID Reference (Security Log)

If you only enable one extra thing on `lapis`, enable **"Include command line in process creation events"** (via `gpedit.msc` → Computer Configuration → Administrative Templates → System → Audit Process Creation, or `secpol.msc`/GPO for Advanced Audit Policy). Native Event ID 4688 doesn't log command-line args by default — turning this on is the single highest-value IR setting on a stock Windows box. Sysmon (Event ID 1) gives you the same thing plus hashes and parent-process chains if you're able to deploy it.

**Logon activity**

| Event ID | Meaning | What to watch for |
|---|---|---|
| **4624** | Successful logon | Check *Logon Type*: Type 3 (network) or Type 10 (RDP) from unexpected hosts/odd hours; Type 9 (NewCredentials, e.g. `runas /netonly`) is a classic pivot indicator |
| **4625** | Failed logon | Burst against one account = brute force. Burst across many accounts from one source = password spraying |
| **4634 / 4647** | Logoff | Useful for session-duration / dwell-time timelines |
| **4648** | Logon with explicit credentials | Legit for some admin tools, but also how lateral movement with stolen creds shows up |
| **4672** | Special privileges assigned (admin-level logon) | Correlate with 4624 to catch privilege escalation |

**Account & group changes**

| Event ID | Meaning | What to watch for |
|---|---|---|
| **4720** | User account created | Any unexpected 4720 is a five-alarm event, especially outside a change window |
| **4732 / 4728** | Member added to local/global security group | Especially additions to Administrators |
| **4738** | User account changed | Password reset, UAC flag changes |
| **4756** | Member added to a universal group | Watch for additions to Domain Admins / Enterprise Admins |

**Process execution** *(needs command-line auditing or Sysmon for full value — see note above)*

| Event ID | Meaning | What to watch for |
|---|---|---|
| **4688** | New process created | Enable command-line logging via GPO — see note above |
| **Sysmon ID 1** | Process creation (full command line, hashes, parent process) | Basis for most real threat hunting, if deployable |

Watch for **LOLBins** (living-off-the-land binaries) invoked oddly:
- `powershell.exe -enc` (base64-encoded commands)
- `certutil.exe -urlcache` (used to download payloads)
- `rundll32.exe` with unusual DLL paths
- `wmic` spawning odd child processes

**Kerberos / Golden Ticket indicators**

| Event ID | Meaning | What to watch for |
|---|---|---|
| **4768 / 4769** | TGT / TGS requests | Unusually long ticket lifetimes; TGS requests for accounts that don't normally authenticate this way |
| **4771** | Kerberos pre-auth failure | Classic Kerberoasting indicator |

A forged **Golden Ticket** often shows up as a TGS-granted session for a user with no matching prior TGT request, or a `krbtgt`-signed ticket with an abnormal lifetime (default policy is ~10 hours — anything far outside that is suspicious).

**Log tampering** *(attackers clean up after themselves)*

| Event ID | Meaning |
|---|---|
| **1102** | Security audit log cleared — if you didn't do it, that's not noise, that's a confession |
| **104** (System log) | Event log service was cleared |

---

## 🔥 VyOS Firewall/Gateway (`bedrock`)

- 1:1 NAT means the firewall should forward **only** the specific ports each host needs — nothing extra.
- Default-deny: explicit deny + log rules for anything not explicitly allowed.
- Management access to `bedrock` itself: internal network only, **never** from WAN.
- Log denied connections — this is your real-time view of red team recon/scanning.
- Save a known-good config (`show configuration commands`) before every change so a bad rule can be rolled back fast.

---

## 💻 Command-Line Cheat Sheet

**Linux — almost entirely CLI:**

| Task | Command |
|---|---|
| SSH config | `/etc/ssh/sshd_config` → `systemctl restart sshd` |
| Firewall | `ufw` (Ubuntu) / `firewall-cmd` (Rocky) |
| Lock an account | `passwd -l <user>` |
| Remove an account | `userdel <user>` |
| List enabled services | `systemctl list-unit-files --state=enabled` |
| Disable a service | `systemctl disable --now <svc>` |
| Persistence check | `crontab -l -u <user>`, `systemctl list-timers` |

**Windows — PowerShell + MMC snap-ins:**

| Task | Tool |
|---|---|
| Local users/groups | `lusrmgr.msc` |
| Password/lockout/audit policy | `secpol.msc` |
| Services | `services.msc` / `Get-Service`, `Set-Service` |
| Scheduled tasks | `taskschd.msc` / `Get-ScheduledTask` |
| Firewall rules | `wf.msc` / `New-NetFirewallRule` |
| Local policy | `gpedit.msc` / `gpupdate` |
| Disable SMBv1 | `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` |
| Event logs | `eventvwr.msc` / `Get-WinEvent` |
| Registry | `regedit` — for one-off checks/fixes; prefer scripted `Set-ItemProperty` for repeatability |
| Windows Update status | `sconfig` or `Get-HotFix` / `wuauclt` — check patch level, but don't blindly auto-update mid-competition if it risks breaking a scored version |
| AD users/groups (if DC) | `dsa.msc` / `Get-ADGroupMember` |
| DNS management (if DC) | `dnsmgmt.msc` / `Set-DnsServerPrimaryZone` |

> Script what you can (especially Linux) into a single per-box hardening script — if red team resets something or you redeploy, you want a one-command re-harden, not a checklist you re-click by hand.

### 🔁 Linux → PowerShell Command Equivalents

**File & directory navigation**

| Linux | PowerShell Alias | Native Cmdlet | Purpose |
|---|---|---|---|
| `pwd` | ✅ | `Get-Location` | Print current directory |
| `ls` | ✅ | `Get-ChildItem` | List files/folders |
| `cd` | ✅ | `Set-Location` | Change directory |
| `mkdir` | ✅ | `New-Item -ItemType Directory` | Create a directory |

**File manipulation**

| Linux | PowerShell Alias | Native Cmdlet | Purpose |
|---|---|---|---|
| `cat` | ✅ | `Get-Content` | Display file contents |
| `cp` | ✅ | `Copy-Item` | Copy files/directories |
| `mv` | ✅ | `Move-Item` | Move or rename |
| `rm` | ✅ | `Remove-Item` | Delete files/directories |
| `touch` | ❌ | `New-Item` (or update `.LastWriteTime`) | Create empty file / update timestamp |

**Text processing & filtering**

| Linux | PowerShell Alias | Native Cmdlet | Purpose |
|---|---|---|---|
| `grep` | ❌ (`sls` shorthand) | `Select-String` | Search for matching text |
| `echo` | ✅ | `Write-Output` | Print text |
| `head` | ❌ | `Get-Content -TotalCount n` | View first *n* lines |
| `tail` | ❌ | `Get-Content -Tail n` (`-Wait` for `tail -f` behavior) | View last *n* lines |

**System & networking**

| Linux | PowerShell Alias | Native Cmdlet | Purpose |
|---|---|---|---|
| `ps` | ✅ | `Get-Process` | List processes |
| `kill` | ✅ | `Stop-Process` | Terminate a process |
| `curl` / `wget` | ✅ | `Invoke-WebRequest` | Download / web request |
| `ifconfig` / `ip` | ❌ | `Get-NetIPAddress` | Show network config |
| `man` / `--help` | ✅ | `Get-Help` | Command documentation |

### 👤 User & Group Management Quick Reference

**Local (Windows)**
```powershell
Add-LocalGroupMember -Group "Administrators" -Member "UserName"
Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "UserName"
Get-LocalGroupMember -Group "Users"

# Legacy net commands still work and are fast under pressure:
net user username password
net localgroup groupname
net localgroup groupname delete
```

**Active Directory (if `lapis` is a DC)**
```powershell
Add-ADGroupMember -Identity "Marketing-Dept" -Members "jdoe"
Remove-ADGroupMember -Identity "Marketing-Dept" -Members "jdoe" -Confirm:$false
New-ADGroup -Name "Finance-Viewers" -GroupScope Global -GroupCategory Security

# net group with /domain targets AD instead of the local machine:
net group /domain
```

### 🔒 File Permissions / ACLs (Windows)

Tightening NTFS permissions on shared folders is a common quick win — check for `Everyone`/`Authenticated Users` with `Modify` or `Full Control` on anything sensitive (web roots, shares, config folders):

```powershell
# 1. Get current permissions
$Acl = Get-Acl "C:\SharedFolder"

# 2. Define the new rule (principal, rights, inheritance, propagation, allow/deny)
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "YOUR_DOMAIN\YourGroup", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)

# 3. Add it to the ACL object
$Acl.SetAccessRule($Ar)

# 4. Apply back to the folder
Set-Acl "C:\SharedFolder" $Acl
```
On Linux, the equivalent audit is `getfacl`/`setfacl` plus a straight `ls -la` pass over web roots, `/etc`, and any shared/upload directories for unexpected world-writable or world-readable files.

### 🧭 Useful Windows Environment Variables

| Variable | Contents |
|---|---|
| `%USERPROFILE%` | Current user's home directory path |
| `%PATH%` | Folders searched for executables — check for suspicious entries a red team may have prepended |
| `%PROGRAMFILES%` | 64-bit install path (32-bit lives in `%PROGRAMFILES(X86)%`), usually `C:\Program Files` |
| `%LOGONSERVER%` | The logon server that authenticated this session — quick way to confirm whether a machine is domain-bound |

---

## ✅ Operational Reminders

- Any credential change to a **required scored account** → PCR on `scoring.byuccdc.org`. Silent changes just break your own scoring.
- Never alter a service's expected behavior/content to game the check — grounds for disqualification.
- **Document every change:** what, when, why, rollback command. This matters for team coordination *and* for injects asking you to report defensive actions.
- **Priority order:**
  1. Don't break scored functionality
  2. Close default-cred / obvious misconfig holes
  3. Deeper hardening (patching, ACLs, logging) as time allows
