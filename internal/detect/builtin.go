package detect

import (
	"database/sql"
	"fmt"
	"time"

	"forensiq/internal/display"
)

type Result struct {
	ID       string
	Name     string
	Hits     int64
	Severity string
}

type detector struct {
	id            string
	name          string
	severity      string
	requireTables []string // all must have rows; if any is empty, detector is skipped
	insertSQL     string
}

// builtins — each detector inserts matching rows into ioc_indicators.
// They use INSERT INTO ... SELECT so empty tables produce 0 rows silently.
var builtins = []detector{
	{
		id:       "defender_detection",
		name:     "Defender threat detection",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', path, 'detect:defender_detection', 'HIGH', 'T1059',
	timestamp, threat_name || ' [' || severity || '] action=' || action
FROM defender_events
WHERE threat_name != '' AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "pif_scr_user",
		name:     "PIF/SCR executable in user directory",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', path, 'detect:pif_scr_user', 'HIGH', 'T1204.002',
	modified, 'PIF/SCR in user dir — classic dropper extension'
FROM mft WHERE NOT is_dir
AND (lower(path) LIKE '%.pif' OR lower(path) LIKE '%.scr')
AND lower(path) LIKE '%/users/%'
AND modified >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "hta_script_user",
		name:     "HTA/VBS/JSE script in user directory",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', path, 'detect:hta_script_user', 'HIGH', 'T1059.005',
	modified, 'Scripting engine file in user dir'
FROM mft WHERE NOT is_dir
AND (lower(path) LIKE '%.hta' OR lower(path) LIKE '%.vbs' OR lower(path) LIKE '%.vbe'
    OR lower(path) LIKE '%.jse' OR lower(path) LIKE '%.wsh' OR lower(path) LIKE '%.wsf')
AND lower(path) LIKE '%/users/%'
AND modified >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "exe_user_docs",
		name:     "EXE/DLL dropped in user Documents/Downloads/Desktop",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', path, 'detect:exe_user_docs', 'HIGH', 'T1204.002',
	modified, 'Executable in user data directory'
FROM mft WHERE NOT is_dir
AND (lower(path) LIKE '%.exe' OR lower(path) LIKE '%.dll' OR lower(path) LIKE '%.com')
AND lower(path) LIKE '%/users/%'
AND (lower(path) LIKE '%/documents/%' OR lower(path) LIKE '%/downloads/%' OR lower(path) LIKE '%/desktop/%')
AND modified >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "log_cleared",
		name:     "Windows event log cleared",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', CAST(event_id AS VARCHAR), 'detect:log_cleared', 'HIGH', 'T1070.001',
	timestamp, 'Log cleared on ' || computer || ' channel=' || channel
FROM evtx_events
WHERE event_id IN (1102, 1100) AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "defender_tamper",
		name:     "Defender real-time protection disabled or tampered",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', CAST(event_id AS VARCHAR), 'detect:defender_tamper', 'HIGH', 'T1562.001',
	timestamp, LEFT(message, 200)
FROM evtx_events
WHERE event_id IN (5001, 5004, 5007, 5010, 5012, 3002)
AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "new_service",
		name:     "New service installed (event 7045)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', CAST(event_id AS VARCHAR), 'detect:new_service', 'HIGH', 'T1543.003',
	timestamp, LEFT(message, 200)
FROM evtx_events
WHERE event_id = 7045 AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "scheduled_task",
		name:     "Scheduled task created or modified",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', CAST(event_id AS VARCHAR), 'detect:scheduled_task', 'MED', 'T1053.005',
	timestamp, LEFT(message, 200)
FROM evtx_events
WHERE event_id IN (4698, 4702) AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "user_created",
		name:     "New local user account created",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', CAST(event_id AS VARCHAR), 'detect:user_created', 'HIGH', 'T1136.001',
	timestamp, LEFT(message, 200)
FROM evtx_events
WHERE event_id = 4720 AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "privilege_group",
		name:     "Account added to privileged group",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'event', CAST(event_id AS VARCHAR), 'detect:privilege_group', 'HIGH', 'T1098',
	timestamp, LEFT(message, 200)
FROM evtx_events
WHERE event_id IN (4732, 4756) AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "explicit_credentials",
		name:     "Explicit credential use (runas / pass-the-hash pattern)",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'auth', "user" || '@' || COALESCE(domain,''), 'detect:explicit_credentials', 'MED', 'T1550.002',
	MIN(timestamp), 'Explicit creds ×' || COUNT(*) || ' from ' || string_agg(DISTINCT COALESCE(src_ip,'-'), ',') || ' workstation=' || string_agg(DISTINCT COALESCE(workstation,'-'), ',')
FROM auth_events
WHERE event_id = 4648 AND timestamp >= TIMESTAMP '2000-01-01'
  AND "user" NOT ILIKE 'UMFD-%' AND "user" NOT ILIKE 'DWM-%'
  AND "user" NOT ILIKE 'LOCAL SERVICE' AND "user" NOT ILIKE 'NETWORK SERVICE'
  AND "user" NOT ILIKE 'ANONYMOUS LOGON' AND COALESCE(domain,'') NOT ILIKE 'Font Driver Host'
  AND COALESCE(domain,'') NOT ILIKE 'Window Manager'
GROUP BY "user", domain
HAVING COUNT(*) >= 2`,
	},
	{
		id:       "brute_force",
		name:     "Brute-force: ≥5 failed logons from same IP",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'ip', src_ip, 'detect:brute_force', 'HIGH', 'T1110.001',
	MIN(timestamp),
	'Brute force: ' || CAST(COUNT(*) AS VARCHAR) || ' failed logons'
FROM auth_events
WHERE event_id = 4625
AND src_ip NOT IN ('', '-', '127.0.0.1') AND src_ip IS NOT NULL
AND timestamp >= TIMESTAMP '2000-01-01'
GROUP BY src_ip
HAVING COUNT(*) >= 5`,
	},
	{
		id:       "encoded_powershell",
		name:     "PowerShell encoded command (base64 -EncodedCommand)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'command', LEFT(cmdline, 300), 'detect:encoded_powershell', 'HIGH', 'T1027.010',
	p.create_time, 'Encoded PS from PID ' || CAST(c.pid AS VARCHAR) || ' parent=' || CAST(p.ppid AS VARCHAR)
FROM mem_cmdline c
JOIN mem_pslist p ON c.pid = p.pid
WHERE (lower(c.cmdline) LIKE '%-encodedcommand%'
	OR lower(c.cmdline) LIKE '%-enc %'
	OR lower(c.cmdline) LIKE '%-e %')
AND lower(c.name) LIKE '%powershell%'`,
	},
	{
		id:       "temp_execution",
		name:     "Process executed from Temp or AppData (living-off-the-land staging)",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'process', p.name || ' (PID ' || CAST(p.pid AS VARCHAR) || ')',
	'detect:temp_execution', 'MED', 'T1036.005',
	p.create_time, 'Cmdline: ' || LEFT(c.cmdline, 200)
FROM mem_pslist p
JOIN mem_cmdline c ON p.pid = c.pid
WHERE (lower(c.cmdline) LIKE '%\temp\%'
    OR lower(c.cmdline) LIKE '%\appdata\local\temp\%'
    OR lower(c.cmdline) LIKE '%\appdata\roaming\%')
AND p.create_time IS NOT NULL`,
	},
	{
		id:       "ram_tools",
		name:     "Memory acquisition or credential dumping tool",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', path, 'detect:ram_tools', 'HIGH', 'T1003',
	modified, 'Memory/credential tool present on disk'
FROM mft WHERE NOT is_dir
AND (lower(path) LIKE '%winpmem%' OR lower(path) LIKE '%dumpit%' OR lower(path) LIKE '%rammap%'
    OR lower(path) LIKE '%ftkimager%' OR lower(path) LIKE '%procdump%'
    OR lower(path) LIKE '%lsass.dmp%' OR lower(path) LIKE '%mimikatz%'
    OR lower(path) LIKE '%wce.exe%' OR lower(path) LIKE '%pwdump%' OR lower(path) LIKE '%gsecdump%')
AND modified >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "sticky_keys",
		name:     "Accessibility tool hijacking (sticky keys / utilman)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', path, 'detect:sticky_keys', 'HIGH', 'T1546.008',
	modified, 'Accessibility binary modified — possible backdoor replacement'
FROM mft WHERE NOT is_dir
AND (lower(path) LIKE '%\sethc.%' OR lower(path) LIKE '%\utilman.%' OR lower(path) LIKE '%\osk.%'
    OR lower(path) LIKE '%\magnify.%' OR lower(path) LIKE '%\narrator.%'
    OR lower(path) LIKE '%\displayswitch.%' OR lower(path) LIKE '%\atbroker.%')
AND (lower(path) LIKE '%.bak' OR lower(path) LIKE '%.old' OR lower(path) LIKE '%.backup' OR lower(path) LIKE '%.exe')
AND modified >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:       "malfind_injection",
		name:     "Memory: malfind process injection hit",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'process', name || ' (PID ' || CAST(pid AS VARCHAR) || ') @ ' || address,
	'detect:malfind_injection',
	CASE
		WHEN lower(name) IN ('svchost.exe','lsass.exe','services.exe','csrss.exe','winlogon.exe','smss.exe','wininit.exe','taskhost.exe','taskhostw.exe','spoolsv.exe') THEN 'HIGH'
		WHEN lower(name) IN ('opera.exe','chrome.exe','msedge.exe','firefox.exe','brave.exe','node.exe','iexplore.exe') THEN 'LOW'
		ELSE 'MEDIUM'
	END,
	'T1055',
	NULL, 'Malfind: ' || reason
FROM mem_malfind`,
	},
	{
		id:            "network_injection",
		name:          "Memory: injected process with active network connections (C2 indicator)",
		severity:      "HIGH",
		requireTables: []string{"mem_malfind", "mem_netscan"},
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT DISTINCT 'process',
    m.name || ' (PID ' || CAST(m.pid AS VARCHAR) || ')',
    'detect:network_injection', 'HIGH', 'T1055',
    NULL,
    'Injected process with network connections — C2 indicator: exec+write VAD @ ' || m.address
FROM mem_malfind m
JOIN mem_netscan n ON CAST(m.pid AS BIGINT) = CAST(n.pid AS BIGINT)
WHERE CAST(m.pid AS BIGINT) > 0
  AND CAST(n.pid AS BIGINT) > 0
  AND lower(m.name) NOT IN ('opera.exe','chrome.exe','msedge.exe','firefox.exe',
                             'brave.exe','node.exe','iexplore.exe','dllhost.exe')`,
	},
	{
		id:            "hidden_process",
		name:          "Memory: hidden process (in pool scan, not in active list)",
		severity:      "HIGH",
		requireTables: []string{"mem_psscan", "mem_pslist"},
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'process', s.name || ' (PID ' || CAST(s.pid AS VARCHAR) || ')',
	'detect:hidden_process', 'HIGH', 'T1055.012',
	NULL, 'DKOM: process in pool scan but not in ActiveProcessLinks — possible rootkit'
FROM mem_psscan s
LEFT JOIN mem_pslist p ON s.pid = p.pid
WHERE p.pid IS NULL
  AND CAST(s.pid AS BIGINT) >= 4
  AND CAST(s.pid AS BIGINT) <= 131072
  AND LENGTH(s.name) >= 3
  AND s.exit_time IS NULL
  AND s.stale_pool IS NOT TRUE`,
	},
	{
		id:            "suspicious_ppid",
		name:          "Memory: suspicious parent-child process relationship",
		severity:      "HIGH",
		requireTables: []string{"mem_pslist"},
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'process', c.name || ' (PID ' || CAST(c.pid AS VARCHAR) || ') parent=' || p.name,
	'detect:suspicious_ppid', 'HIGH', 'T1036.005',
	c.create_time,
	'Unexpected parent-child: ' || c.name || ' spawned by ' || p.name
FROM mem_pslist c
JOIN mem_pslist p ON c.ppid = p.pid
WHERE
	(LOWER(c.name) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','bitsadmin.exe')
	 AND LOWER(p.name) = 'svchost.exe')
	OR
	(LOWER(c.name) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe')
	 AND LOWER(p.name) IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe','onenote.exe','msaccess.exe','mspub.exe'))
	OR
	(LOWER(c.name) = 'svchost.exe'
	 AND LOWER(p.name) NOT IN ('services.exe','svchost.exe','msiexec.exe','wermgr.exe','tiworker.exe','trustedinstaller.exe'))
	OR
	(LOWER(c.name) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe')
	 AND LOWER(p.name) IN ('vmtoolsd.exe','vmwaretray.exe','vmwareuser.exe'))
	OR
	(LOWER(c.name) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe')
	 AND LOWER(p.name) IN ('chrome.exe','firefox.exe','opera.exe','iexplore.exe','msedge.exe','brave.exe'))`,
	},
	{
		id:            "masquerade_path",
		name:          "Memory: system process running from unexpected path (T1036.005)",
		severity:      "HIGH",
		requireTables: []string{"mem_cmdline"},
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'process', c.name || ' (PID ' || CAST(c.pid AS VARCHAR) || ') path=' || c.cmdline,
	'detect:masquerade_path', 'HIGH', 'T1036.005',
	NULL, 'System process not in expected path — possible masquerade/hollowing'
FROM mem_cmdline c
WHERE c.cmdline != ''
  AND c.cmdline LIKE '%\%'
  AND c.cmdline NOT LIKE '%SystemRoot%'
  AND c.cmdline NOT LIKE '%windir%'
  AND (
    (LOWER(c.name) = 'svchost.exe'    AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\svchost.exe%')
    OR (LOWER(c.name) = 'lsass.exe'   AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\lsass.exe%')
    OR (LOWER(c.name) = 'csrss.exe'   AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\csrss.exe%')
    OR (LOWER(c.name) = 'services.exe' AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\services.exe%')
    OR (LOWER(c.name) = 'winlogon.exe' AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\winlogon.exe%')
    OR (LOWER(c.name) = 'smss.exe'    AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\smss.exe%')
    OR (LOWER(c.name) = 'wininit.exe' AND LOWER(c.cmdline) NOT LIKE '%\windows\system32\wininit.exe%')
  )`,
	},
	{
		id:            "cmdline_obfuscation",
		name:          "Memory: command-line obfuscation / LOLBin abuse (T1027/T1059/T1140)",
		severity:      "HIGH",
		requireTables: []string{"mem_cmdline"},
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT DISTINCT 'process',
	c.name || ' (PID ' || CAST(c.pid AS VARCHAR) || '): ' || SUBSTR(c.cmdline,1,200),
	'detect:cmdline_obfuscation', 'HIGH', 'T1027',
	NULL,
	'Obfuscated or LOLBin command line detected'
FROM mem_cmdline c
WHERE c.cmdline != ''
  AND (
    LOWER(c.cmdline) LIKE '% -enc %'
    OR LOWER(c.cmdline) LIKE '% -e %'
    OR LOWER(c.cmdline) LIKE '% -encodedcommand %'
    OR LOWER(c.cmdline) LIKE '% -ec %'
    OR LOWER(c.cmdline) LIKE '% -w hidden%'
    OR LOWER(c.cmdline) LIKE '% -windowstyle hidden%'
    OR LOWER(c.cmdline) LIKE '%-executionpolicy bypass%'
    OR LOWER(c.cmdline) LIKE '%-ep bypass%'
    OR (LOWER(c.name) = 'certutil.exe' AND (
        LOWER(c.cmdline) LIKE '%-urlcache%'
        OR LOWER(c.cmdline) LIKE '%-decode%'
        OR LOWER(c.cmdline) LIKE '%-decodehex%'
    ))
    OR (LOWER(c.name) = 'wmic.exe' AND LOWER(c.cmdline) LIKE '%process call create%')
    OR (LOWER(c.name) = 'mshta.exe' AND (
        LOWER(c.cmdline) LIKE '%http%'
        OR LOWER(c.cmdline) LIKE '%vbscript%'
        OR LOWER(c.cmdline) LIKE '%javascript%'
    ))
    OR (LOWER(c.name) = 'bitsadmin.exe' AND LOWER(c.cmdline) LIKE '%/transfer%')
  )`,
	},
	{
		id:            "amcache_ghost",
		name:          "Amcache entry with no MFT match (possible file deletion)",
		severity:      "MED",
		requireTables: []string{"amcache", "mft"},
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'file', a.path, 'detect:amcache_ghost', 'MED', 'T1070.004',
	a.first_seen, 'Executed file no longer on disk (amcache without MFT entry)'
FROM amcache a
LEFT JOIN mft m ON lower(replace(a.path, '\', '/')) = lower(m.path)
WHERE m.path IS NULL
AND a.first_seen IS NOT NULL
AND a.first_seen >= TIMESTAMP '2000-01-01'
LIMIT 500`,
	},
	{
		id:       "wmi_subscription",
		name:     "WMI event subscription (persistence)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators (type, value, source, confidence, related_campaign, first_seen, notes)
SELECT 'wmi', consumer_name || ' → ' || filter_name,
	'detect:wmi_subscription', 'HIGH', 'T1546.003',
	created, 'WMI subscription: ' || consumer_type || ' query=' || LEFT(filter_query, 100)
FROM wmi_subs`,
	},
	{
		id:       "certutil_download",
		name:     "LOLBin: certutil used to download files",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','certutil download: '||c.cmdline,'detect:certutil_download','HIGH',
  'certutil used to download files — common malware dropper technique',NULL
FROM mem_cmdline c
WHERE lower(c.cmdline) LIKE '%certutil%'
  AND (lower(c.cmdline) LIKE '%-urlcache%' OR lower(c.cmdline) LIKE '%-decode%' OR lower(c.cmdline) LIKE '%http%')
GROUP BY c.cmdline`,
	},
	{
		id:       "mshta_http",
		name:     "LOLBin: mshta loading remote HTA",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','mshta remote: '||c.cmdline,'detect:mshta_http','HIGH',
  'mshta loading remote script — common phishing/execution technique',NULL
FROM mem_cmdline c
WHERE lower(c.cmdline) LIKE '%mshta%'
  AND (lower(c.cmdline) LIKE '%http%' OR lower(c.cmdline) LIKE '%\\\\%')
GROUP BY c.cmdline`,
	},
	{
		id:       "regsvr32_scrobj",
		name:     "LOLBin: regsvr32 Squiblydoo",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','regsvr32 scrobj: '||c.cmdline,'detect:regsvr32_scrobj','HIGH',
  'regsvr32 loading scrobj.dll or remote COM script (Squiblydoo)',NULL
FROM mem_cmdline c
WHERE lower(c.cmdline) LIKE '%regsvr32%'
  AND (lower(c.cmdline) LIKE '%scrobj%' OR lower(c.cmdline) LIKE '%http%' OR lower(c.cmdline) LIKE '%/s /u /i%')
GROUP BY c.cmdline`,
	},
	{
		id:       "shadow_copy_deletion",
		name:     "Ransomware precursor: shadow copy deletion",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','shadow delete: '||c.cmdline,'detect:shadow_copy_deletion','HIGH',
  'Volume shadow copy deletion — ransomware precursor or anti-forensics',NULL
FROM mem_cmdline c
WHERE (lower(c.cmdline) LIKE '%vssadmin%delete shadows%'
    OR lower(c.cmdline) LIKE '%wmic%shadowcopy%delete%'
    OR lower(c.cmdline) LIKE '%wbadmin%delete%catalog%'
    OR lower(c.cmdline) LIKE '%bcdedit%recoveryenabled%no%')
GROUP BY c.cmdline`,
	},
	{
		id:       "bits_job_download",
		name:     "BITS abuse for persistence/download",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','bitsadmin: '||c.cmdline,'detect:bits_job_download','MED',
  'BITS job used to transfer files — can be abused for persistence and C2',NULL
FROM mem_cmdline c
WHERE lower(c.cmdline) LIKE '%bitsadmin%'
  AND (lower(c.cmdline) LIKE '%/transfer%' OR lower(c.cmdline) LIKE '%/create%' OR lower(c.cmdline) LIKE '%http%')
GROUP BY c.cmdline`,
	},
	{
		id:       "run_key_persistence",
		name:     "Registry Run key modification (persistence)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'registry','run key: '||LEFT(e.message,200),'detect:run_key_persistence','HIGH',
  'Registry Run key modified — common persistence mechanism',MIN(e.timestamp)
FROM evtx_events e
WHERE e.event_id = 13
  AND (lower(e.message) LIKE '%\currentversion\run%'
    OR lower(e.message) LIKE '%\currentversion\runonce%')
GROUP BY LEFT(e.message,200)`,
	},
	{
		id:       "lolbin_wscript",
		name:     "LOLBin: wscript/cscript from suspicious path",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','wscript: '||c.cmdline,'detect:lolbin_wscript','MED',
  'wscript/cscript executing scripts from user-writable location',NULL
FROM mem_cmdline c
WHERE (lower(c.cmdline) LIKE '%wscript%' OR lower(c.cmdline) LIKE '%cscript%')
  AND (lower(c.cmdline) LIKE '%\temp\%' OR lower(c.cmdline) LIKE '%\appdata\%'
    OR lower(c.cmdline) LIKE '%\downloads\%' OR lower(c.cmdline) LIKE '%\desktop\%')
GROUP BY c.cmdline`,
	},
	{
		id:       "defender_tamper_ps",
		name:     "Defender real-time protection disabled via PowerShell",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process','defender tamper: '||c.cmdline,'detect:defender_tamper_ps','HIGH',
  'Defender real-time protection disabled via PowerShell',NULL
FROM mem_cmdline c
WHERE lower(c.cmdline) LIKE '%set-mppreference%'
  AND (lower(c.cmdline) LIKE '%disablerealtimemonitoring%$true%'
    OR lower(c.cmdline) LIKE '%-disablerealtimemonitoring 1%')
GROUP BY c.cmdline`,
	},
	{
		id:       "ssh_bruteforce",
		name:     "SSH brute force: ≥20 failed logins from same IP",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT 'ip', src_ip, 'detect:ssh_bruteforce', 'HIGH',
  'SSH brute force: '||COUNT(*)||' failed attempts', MIN(timestamp)
FROM linux_auth
WHERE event_type IN ('ssh_login_failed','ssh_invalid_user') AND src_ip != ''
GROUP BY src_ip HAVING COUNT(*) >= 20`,
	},
	{
		id:       "new_authorized_key",
		name:     "Authorized SSH key in persistence artifacts",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', path||' ['||"user"||']', 'detect:new_authorized_key', 'MED',
  'SSH authorized_key entry: '||details, NULL
FROM linux_persistence WHERE type = 'authorized_key'`,
	},
	{
		id:       "root_crontab",
		name:     "Root crontab persistence entry",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', command, 'detect:root_crontab', 'HIGH',
  'root crontab: '||details||' @ '||path, NULL
FROM linux_persistence
WHERE type = 'crontab' AND ("user" = 'root' OR "user" = '')`,
	},
	{
		id:       "usnjrnl_mass_delete",
		name:     "Mass file deletion via $UsnJrnl (ransomware/wiper indicator)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT 'host','mass_file_deletion','detect:usnjrnl_mass_delete','HIGH',
  COUNT(*)||' FILE_DELETE events in $UsnJrnl', MIN(timestamp)
FROM usnjrnl WHERE reason LIKE '%FILE_DELETE%'
HAVING COUNT(*) >= 100`,
	},
	{
		id:       "usnjrnl_ransomware_ext",
		name:     "$UsnJrnl: suspicious encrypted file extensions created",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', path, 'detect:usnjrnl_ransomware_ext', 'HIGH',
  'Suspicious extension created: '||path, MIN(timestamp)
FROM usnjrnl
WHERE reason LIKE '%FILE_CREATE%'
  AND (lower(path) LIKE '%.locked' OR lower(path) LIKE '%.encrypted' OR lower(path) LIKE '%.enc'
    OR lower(path) LIKE '%.crypt' OR lower(path) LIKE '%.crypted' OR lower(path) LIKE '%.ransom'
    OR lower(path) LIKE '%.pays' OR lower(path) LIKE '%.wncry' OR lower(path) LIKE '%.wcry'
    OR lower(path) LIKE '%.zepto' OR lower(path) LIKE '%.locky' OR lower(path) LIKE '%.cerber')
GROUP BY path`,
	},
	{
		id:       "new_interactive_user",
		name:     "Interactive user account in /etc/passwd",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'account', "user", 'detect:new_interactive_user', 'MED',
  details, NULL
FROM linux_persistence
WHERE type = 'passwd_entry' AND enabled = true
  AND command NOT IN ('/bin/false','/usr/sbin/nologin','/sbin/nologin')`,
	},
	{
		id:       "shell_download_exec",
		name:     "Shell history: download-and-execute pattern",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', LEFT(command,200), 'detect:shell_download_exec', 'HIGH',
  'download+execute in shell history', timestamp
FROM shell_history
WHERE (lower(command) LIKE '%wget%' OR lower(command) LIKE '%curl%')
  AND (lower(command) LIKE '%|%bash%' OR lower(command) LIKE '%|%sh%'
    OR lower(command) LIKE '%chmod%x%' OR lower(command) LIKE '%./%')`,
	},
	{
		id:       "shell_reverse_shell",
		name:     "Shell history: reverse shell command",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', LEFT(command,200), 'detect:shell_reverse_shell', 'HIGH',
  'reverse shell in shell history', timestamp
FROM shell_history
WHERE lower(command) LIKE '%nc % -e%'
   OR lower(command) LIKE '%ncat % -e%'
   OR lower(command) LIKE '%bash -i >%/dev/tcp/%'
   OR lower(command) LIKE '%python%pty%spawn%'
   OR lower(command) LIKE '%socat%exec%'`,
	},
	{
		id:       "amcache_suspicious_path",
		name:     "Amcache: executable from user-writable location",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', path, 'detect:amcache_suspicious_path', 'HIGH',
  'Executed from suspicious path (amcache)', first_seen
FROM amcache
WHERE (lower(path) LIKE '%\temp\%' OR lower(path) LIKE '%\tmp\%' OR lower(path) LIKE '%\downloads\%'
    OR lower(path) LIKE '%\desktop\%' OR lower(path) LIKE '%\appdata\local\temp\%'
    OR lower(path) LIKE '%\appdata\roaming\%')
  AND lower(path) LIKE '%.exe'`,
	},
	{
		id:       "shimcache_suspicious_path",
		name:     "Shimcache: executable from user-writable location",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', path, 'detect:shimcache_suspicious_path', 'HIGH',
  'Shimcache entry from suspicious path', last_modified
FROM shimcache
WHERE (lower(path) LIKE '%\temp\%' OR lower(path) LIKE '%\tmp\%' OR lower(path) LIKE '%\downloads\%'
    OR lower(path) LIKE '%\desktop\%' OR lower(path) LIKE '%\appdata\local\temp\%')
  AND lower(path) LIKE '%.exe'`,
	},
	{
		id:       "wmi_persistence",
		name:     "WMI event subscription persistence",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', consumer_name, 'detect:wmi_persistence', 'HIGH',
  'WMI subscription: '||consumer_type||' filter='||filter_name, created
FROM wmi_subs`,
	},
	{
		id:       "ps_scriptblock_download_cradle",
		name:     "PowerShell scriptblock: download cradle / obfuscation",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', LEFT(script_text, 200), 'detect:ps_scriptblock_download_cradle', 'HIGH',
  'PS download cradle or obfuscation detected', timestamp
FROM ps_scriptblock
WHERE (lower(script_text) LIKE '%downloadstring%'
   OR lower(script_text) LIKE '%invoke-expression%'
   OR lower(script_text) LIKE '%iex(%'
   OR lower(script_text) LIKE '%frombase64string%'
   OR lower(script_text) LIKE '%-enc %'
   OR lower(script_text) LIKE '%-encodedcommand%')
AND lower(script_text) NOT LIKE '%chocolatey%'
AND lower(script_text) NOT LIKE '%copyright%'
AND lower(script_text) NOT LIKE '%microsoft.com%'
AND lower(script_text) NOT LIKE '%#requires%'`,
	},
	{
		id:       "shell_antiforensics",
		name:     "Shell history: anti-forensics commands",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', LEFT(command,200), 'detect:shell_antiforensics', 'HIGH',
  'anti-forensics in shell history', timestamp
FROM shell_history
WHERE lower(command) LIKE '%history -c%'
   OR lower(command) LIKE '%shred %'
   OR lower(command) LIKE '%wipe %'
   OR lower(command) LIKE '%unset histfile%'
   OR lower(command) LIKE '%export histsize=0%'
   OR (lower(command) LIKE '%rm %' AND lower(command) LIKE '%.bash_history%')`,
	},
	{
		id:       "recycle_bin_exe",
		name:     "Recycle Bin: executable or script deleted",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', original_path, 'detect:recycle_bin_exe', 'MED',
  'Executable/script deleted via Recycle Bin (' || i_file || ')', deleted_at
FROM recycle_bin
WHERE lower(original_path) LIKE '%.exe'
   OR lower(original_path) LIKE '%.dll'
   OR lower(original_path) LIKE '%.bat'
   OR lower(original_path) LIKE '%.ps1'
   OR lower(original_path) LIKE '%.vbs'
   OR lower(original_path) LIKE '%.hta'
   OR lower(original_path) LIKE '%.js'`,
	},
	{
		id:       "userassist_suspicious_path",
		name:     "UserAssist: program executed from suspicious location",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', path, 'detect:userassist_suspicious_path', 'HIGH',
  'UserAssist execution from suspicious path, runs=' || run_count, last_run
FROM userassist
WHERE lower(path) LIKE '%\\temp\\%'
   OR lower(path) LIKE '%\\tmp\\%'
   OR lower(path) LIKE '%\\appdata\\local\\temp\\%'
   OR lower(path) LIKE '%\\downloads\\%'
   OR lower(path) LIKE '%\\public\\%'
   OR lower(path) LIKE '%\\recycle%'`,
	},
	{
		id:       "bam_suspicious_path",
		name:     "BAM/DAM: executable run from suspicious location",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'process', path, 'detect:bam_suspicious_path', 'HIGH',
  'BAM/DAM execution from suspicious path', last_run
FROM bam_dam
WHERE lower(path) LIKE '%\\temp\\%'
   OR lower(path) LIKE '%\\tmp\\%'
   OR lower(path) LIKE '%\\appdata\\local\\temp\\%'
   OR lower(path) LIKE '%\\downloads\\%'
   OR lower(path) LIKE '%\\public\\%'`,
	},
	{
		id:       "jumplists_suspicious_target",
		name:     "JumpList: recently accessed file from suspicious path",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', target_path, 'detect:jumplists_suspicious_target', 'HIGH',
  'JumpList entry from suspicious path (app=' || COALESCE(NULLIF(app_name,''), app_id) || ')', accessed
FROM jumplists
WHERE lower(target_path) LIKE '%\\temp\\%'
   OR lower(target_path) LIKE '%\\appdata\\local\\temp\\%'
   OR lower(target_path) LIKE '%\\downloads\\%'
   OR lower(target_path) LIKE '%\\public\\%'
   OR lower(target_path) LIKE '%\\recycle%'`,
	},
	{
		id:       "jumplists_high_access",
		name:     "JumpList: file opened >20 times",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', target_path, 'detect:jumplists_high_access', 'MED',
  'Frequently opened via JumpList: ' || access_count || ' times (app=' || COALESCE(NULLIF(app_name,''), app_id) || ')', accessed
FROM jumplists
WHERE access_count > 20 AND target_path != ''`,
	},
	{
		id:       "shellbags_network_share",
		name:     "Shellbags: network share or UNC path browsed",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'network', path, 'detect:shellbags_network_share', 'HIGH',
  'User browsed network location (shellbags): user=' || COALESCE("user", '-'), last_modified
FROM shellbags
WHERE (lower(path) LIKE '\\\\%' OR lower(path) LIKE '//%'
    OR lower(path) LIKE '%network%' OR lower(path) LIKE '%\\\\server%')
  AND item_type = 'network'`,
	},
	{
		id:       "shellbags_suspicious_path",
		name:     "Shellbags: folder browsed from suspicious location",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","notes","first_seen")
SELECT DISTINCT 'file', path, 'detect:shellbags_suspicious_path', 'HIGH',
  'Shellbag entry from suspicious path — folder may have been deleted: user=' || COALESCE("user", '-'), last_modified
FROM shellbags
WHERE lower(path) LIKE '%\\temp\\%'
   OR lower(path) LIKE '%\\tmp\\%'
   OR lower(path) LIKE '%\\appdata\\local\\temp%'
   OR lower(path) LIKE '%\\downloads\\%'
   OR lower(path) LIKE '%\\recycle%'
   OR lower(path) LIKE '%\\public\\%'`,
	},
	// ── New detectors: targeted at TEST_IMAGE_2 attack chain patterns ───────────
	{
		id:       "pass_the_hash",
		name:     "Pass-the-Hash: high-volume explicit credential use (≥10 events)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT 'auth', "user" || '@' || COALESCE(domain,''), 'detect:pass_the_hash', 'HIGH', 'T1550.002',
  'Pass-the-Hash: ' || COUNT(*) || ' explicit credential events, src=' || string_agg(DISTINCT COALESCE(src_ip,'-'), ', '),
  MIN(timestamp)
FROM auth_events
WHERE event_id = 4648
  AND "user" IS NOT NULL AND "user" != '' AND NOT "user" LIKE '%$'
  AND "user" NOT ILIKE 'UMFD-%' AND "user" NOT ILIKE 'DWM-%'
  AND "user" NOT ILIKE 'LOCAL SERVICE' AND "user" NOT ILIKE 'NETWORK SERVICE'
  AND "user" NOT ILIKE 'ANONYMOUS LOGON' AND "user" NOT ILIKE 'Window Manager'
  AND COALESCE(domain,'') NOT ILIKE 'Font Driver Host'
  AND COALESCE(domain,'') NOT ILIKE 'Window Manager'
  AND timestamp >= TIMESTAMP '2000-01-01'
GROUP BY "user", domain
HAVING COUNT(*) >= 10`,
	},
	{
		id:            "hollow_process",
		name:          "Memory: process with no disk evidence (possible hollow/ghost process)",
		severity:      "HIGH",
		requireTables: []string{"mem_pslist", "prefetch"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT 'process', p.name || ' (PID ' || CAST(p.pid AS VARCHAR) || ')',
  'detect:hollow_process', 'HIGH', 'T1055.012',
  'Process in memory has no prefetch and no amcache match — possible process hollowing',
  p.create_time
FROM mem_pslist p
WHERE p.name IS NOT NULL
  AND p.name NOT LIKE 'System%' AND p.name != 'Idle'
  AND p.pid > 4
  AND NOT EXISTS (
    SELECT 1 FROM prefetch pf WHERE lower(pf.filename) = lower(p.name)
  )
  AND NOT EXISTS (
    SELECT 1 FROM amcache a WHERE lower(split_part(a.path,'\\',-1)) = lower(p.name)
  )
  AND p.create_time IS NOT NULL`,
	},
	{
		id:       "kerberoasting",
		name:     "Kerberoasting: Kerberos service ticket with RC4 encryption",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT 'auth', CAST(event_id AS VARCHAR), 'detect:kerberoasting', 'HIGH', 'T1558.003',
  'Kerberos 4769 with RC4 (etype 0x17) — possible Kerberoasting', MIN(timestamp)
FROM evtx_events
WHERE event_id = 4769
  AND (message LIKE '%0x17%' OR message LIKE '%23%')
  AND timestamp >= TIMESTAMP '2000-01-01'
GROUP BY event_id
HAVING COUNT(*) >= 1`,
	},
	{
		id:       "dcsync_attack",
		name:     "DCSync: directory replication rights used by non-DC account",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT 'auth', CAST(event_id AS VARCHAR), 'detect:dcsync_attack', 'HIGH', 'T1003.006',
  'DCSync: event 4662 with DS-Replication-Get-Changes — may indicate credential dump', MIN(timestamp)
FROM evtx_events
WHERE event_id = 4662
  AND (message LIKE '%Replication-Get-Changes%' OR message LIKE '%1131f6a%' OR message LIKE '%1131f6aa%')
  AND timestamp >= TIMESTAMP '2000-01-01'
GROUP BY event_id
HAVING COUNT(*) >= 1`,
	},
	{
		id:       "ntds_exfil",
		name:     "Credential Access: NTDS.dit extraction (ntdsutil IFM / VSS copy)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(c.cmdline,300), 'detect:ntds_exfil', 'HIGH', 'T1003.003',
  'NTDS.dit extraction — domain credential dump technique', p.create_time
FROM mem_cmdline c
JOIN mem_pslist p ON c.pid = p.pid
WHERE (lower(c.cmdline) LIKE '%ntdsutil%' AND (lower(c.cmdline) LIKE '%ifm%' OR lower(c.cmdline) LIKE '%ntds%'))
   OR lower(c.cmdline) LIKE '%ntds.dit%'
   OR (lower(c.cmdline) LIKE '%vssadmin%create shadow%' AND lower(c.cmdline) LIKE '%c:%')`,
	},
	{
		id:       "uac_bypass_registry",
		name:     "Privilege Escalation: UAC bypass via registry hijack (fodhelper/eventvwr)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'registry', key_path || ' = ' || LEFT(value_data,200),
  'detect:uac_bypass_registry', 'HIGH', 'T1548.002',
  'UAC bypass: HKCU registry shell command hijack for auto-elevated binary', modified
FROM registry_raw
WHERE value_data IS NOT NULL AND value_data != ''
  AND value_name IN ('', '(Default)')
  AND (lower(key_path) LIKE '%ms-settings%shell%open%command%'
    OR lower(key_path) LIKE '%mscfile%shell%open%command%'
    OR lower(key_path) LIKE '%software\classes\exefile%shell%open%command%'
    OR lower(key_path) LIKE '%software\classes\ms-settings%')`,
	},
	{
		id:       "lsass_targeted_access",
		name:     "Credential Access: process targeting LSASS for credential dump",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(c.cmdline,300), 'detect:lsass_targeted_access', 'HIGH', 'T1003.001',
  'Cmdline targeting lsass.exe — credential dumping indicator', p.create_time
FROM mem_cmdline c
JOIN mem_pslist p ON c.pid = p.pid
WHERE lower(c.cmdline) LIKE '%lsass%'
  AND (lower(c.cmdline) LIKE '%procdump%'
    OR lower(c.cmdline) LIKE '%rundll32%comsvcs%'
    OR lower(c.cmdline) LIKE '%tasklist%'
    OR lower(c.cmdline) LIKE '%processhacker%'
    OR lower(c.cmdline) LIKE '%-ma %'
    OR lower(c.cmdline) LIKE '%sqldumper%')`,
	},
	{
		id:       "rdp_brute_force",
		name:     "Brute-Force: RDP-specific failures (logon_type=10) from external IP",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT 'ip', src_ip, 'detect:rdp_brute_force', 'HIGH', 'T1110.001',
  'RDP brute force: ' || COUNT(*) || ' failures (logon_type=10)', MIN(timestamp)
FROM auth_events
WHERE event_id = 4625 AND logon_type = 10
  AND src_ip NOT IN ('', '-', '127.0.0.1', '::1') AND src_ip IS NOT NULL
  AND timestamp >= TIMESTAMP '2000-01-01'
GROUP BY src_ip
HAVING COUNT(*) >= 5`,
	},
	{
		id:       "suspicious_parent_child",
		name:     "Phishing: Office/browser spawning cmd/PowerShell (T1566.001)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(child_c.cmdline, 300),
  'detect:suspicious_parent_child', 'HIGH', 'T1566.001',
  'Suspicious parent→child: ' || parent.name || ' spawned ' || child.name || ' — phishing indicator',
  child.create_time
FROM mem_pslist child
JOIN mem_pslist parent ON child.ppid = parent.pid
JOIN mem_cmdline child_c ON child.pid = child_c.pid
WHERE lower(parent.name) IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe','msaccess.exe',
    'chrome.exe','firefox.exe','msedge.exe','iexplore.exe','acrord32.exe')
  AND lower(child.name) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe',
    'mshta.exe','rundll32.exe','regsvr32.exe')`,
	},
	{
		id:       "process_masquerade",
		name:     "Defense Evasion: system process name running from non-standard path (T1036.005)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'file', path, 'detect:process_masquerade', 'HIGH', 'T1036.005',
  'System process name outside System32/SysWOW64 — possible masquerade/LOLBin abuse', first_seen
FROM amcache
WHERE (lower(path) LIKE '%\svchost.exe' OR lower(path) LIKE '%\lsass.exe'
    OR lower(path) LIKE '%\csrss.exe' OR lower(path) LIKE '%\smss.exe'
    OR lower(path) LIKE '%\winlogon.exe' OR lower(path) LIKE '%\services.exe'
    OR lower(path) LIKE '%\spoolsv.exe' OR lower(path) LIKE '%\wininit.exe'
    OR lower(path) LIKE '%\lsm.exe' OR lower(path) LIKE '%\taskhost.exe'
    OR lower(path) LIKE '%\taskhostw.exe' OR lower(path) LIKE '%\dllhost.exe'
    OR lower(path) LIKE '%\conhost.exe' OR lower(path) LIKE '%\explorer.exe')
  AND NOT (lower(path) LIKE '%\system32\%' OR lower(path) LIKE '%\syswow64\%'
    OR lower(path) LIKE '%\winsxs\%' OR lower(path) LIKE '%\windows\explorer%')
  AND path IS NOT NULL AND path != ''`,
	},
	{
		id:       "discovery_recon",
		name:     "Discovery: recon commands in memory (whoami/net/nltest/systeminfo) T1082/T1069",
		severity: "MED",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(c.cmdline, 200), 'detect:discovery_recon', 'MED', 'T1082',
  'Post-exploitation recon command in live process cmdline', p.create_time
FROM mem_cmdline c
JOIN mem_pslist p ON c.pid = p.pid
WHERE lower(c.cmdline) LIKE '%whoami%/all%'
   OR lower(c.cmdline) LIKE '%whoami%/priv%'
   OR lower(c.cmdline) LIKE '%net localgroup%'
   OR lower(c.cmdline) LIKE '%net user%/domain%'
   OR lower(c.cmdline) LIKE '%nltest%/domain_trusts%'
   OR lower(c.cmdline) LIKE '%nltest%/dclist%'
   OR lower(c.cmdline) LIKE '%ipconfig%/all%'
   OR lower(c.cmdline) LIKE '%arp %-a%'`,
	},
	{
		id:       "asrep_roasting",
		name:     "Credential Access: AS-REP Roasting — 4768 without pre-auth (T1558.004)",
		severity: "HIGH",
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT 'auth', CAST(event_id AS VARCHAR), 'detect:asrep_roasting', 'HIGH', 'T1558.004',
  'AS-REP Roasting: event 4768 with no Kerberos pre-authentication required — ' || COUNT(*) || ' events', MIN(timestamp)
FROM evtx_events
WHERE event_id = 4768
  AND message LIKE '%0x0%'
  AND timestamp >= TIMESTAMP '2000-01-01'
GROUP BY event_id
HAVING COUNT(*) >= 1`,
	},
	// ── Sysmon event detectors (events 1/3/22) ───────────────────────────────
	{
		id:            "sysmon_office_spawn",
		name:          "Sysmon: Office/browser spawning shell (T1566.001 — parent cmdline enriched)",
		severity:      "HIGH",
		requireTables: []string{"sysmon_process"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(image,300), 'detect:sysmon_office_spawn', 'HIGH', 'T1566.001',
  'Sysmon1: shell spawned by ' || split_part(parent_image,'\',-1) || ' parent_cmd=' || LEFT(COALESCE(parent_cmdline,''),150),
  timestamp
FROM sysmon_process
WHERE lower(split_part(image,'\',-1)) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe')
  AND lower(split_part(COALESCE(parent_image,''),'\',-1)) IN (
      'winword.exe','excel.exe','powerpnt.exe','outlook.exe','msaccess.exe',
      'chrome.exe','firefox.exe','msedge.exe','iexplore.exe','opera.exe','acrord32.exe')
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_encoded_ps",
		name:          "Sysmon: PowerShell encoded command (T1027.010)",
		severity:      "HIGH",
		requireTables: []string{"sysmon_process"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(cmdline,300), 'detect:sysmon_encoded_ps', 'HIGH', 'T1027.010',
  'Sysmon1: encoded PS sha256=' || COALESCE(sha256,''), timestamp
FROM sysmon_process
WHERE lower(split_part(image,'\',-1)) IN ('powershell.exe','pwsh.exe')
  AND (lower(cmdline) LIKE '%-encodedcommand%' OR lower(cmdline) LIKE '%-enc %'
    OR lower(cmdline) LIKE '%frombase64string%' OR lower(cmdline) LIKE '%-e %')
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_lolbin",
		name:          "Sysmon: LOLBin execution with hash (T1218)",
		severity:      "HIGH",
		requireTables: []string{"sysmon_process"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(cmdline,300), 'detect:sysmon_lolbin', 'HIGH', 'T1218',
  'Sysmon1: LOLBin sha256=' || COALESCE(sha256,'') || ' user=' || COALESCE(user_name,''), timestamp
FROM sysmon_process
WHERE lower(split_part(image,'\',-1)) IN (
    'certutil.exe','mshta.exe','regsvr32.exe','wscript.exe','cscript.exe',
    'msiexec.exe','installutil.exe','regasm.exe','regsvcs.exe',
    'odbcconf.exe','msbuild.exe','cmstp.exe','forfiles.exe','bitsadmin.exe')
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_susp_path",
		name:          "Sysmon: process launched from suspicious write path (T1036)",
		severity:      "MED",
		requireTables: []string{"sysmon_process"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(image,300), 'detect:sysmon_susp_path', 'MED', 'T1036',
  'Sysmon1: exec from writable path sha256=' || COALESCE(sha256,''), timestamp
FROM sysmon_process
WHERE (lower(image) LIKE '%\temp\%' OR lower(image) LIKE '%\appdata\local\temp\%'
    OR lower(image) LIKE '%\appdata\roaming\%' OR lower(image) LIKE '%\downloads\%'
    OR lower(image) LIKE '%\public\%' OR lower(image) LIKE '%\programdata\%')
  AND lower(split_part(image,'\',-1)) LIKE '%.exe'
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_network_external",
		name:          "Sysmon: outbound connection by suspicious process (T1071)",
		severity:      "HIGH",
		requireTables: []string{"sysmon_network"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'ip', dst_ip, 'detect:sysmon_network_external', 'HIGH', 'T1071',
  'Sysmon3: outbound by ' || split_part(image,'\',-1) || ':' || CAST(dst_port AS VARCHAR) || ' user=' || COALESCE(user_name,''), timestamp
FROM sysmon_network
WHERE initiated = true
  AND dst_ip NOT IN ('0.0.0.0','-','') AND dst_ip IS NOT NULL
  AND NOT (dst_ip LIKE '10.%' OR dst_ip LIKE '192.168.%' OR dst_ip LIKE '172.1%'
    OR dst_ip LIKE '172.2%' OR dst_ip LIKE '172.3%' OR dst_ip = '127.0.0.1' OR dst_ip = '::1')
  AND lower(split_part(image,'\',-1)) IN (
      'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe',
      'regsvr32.exe','rundll32.exe','certutil.exe','msiexec.exe','wmic.exe',
      'bitsadmin.exe','curl.exe','wget.exe','explorer.exe')
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_dns_suspicious",
		name:          "Sysmon: DNS query to suspicious domain (T1071.004)",
		severity:      "MED",
		requireTables: []string{"sysmon_dns"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'domain', query_name, 'detect:sysmon_dns_suspicious', 'MED', 'T1071.004',
  'Sysmon22: DNS by ' || split_part(image,'\',-1) || ' results=' || LEFT(COALESCE(query_results,''),80), timestamp
FROM sysmon_dns
WHERE query_name IS NOT NULL AND query_name != '' AND query_name != '-'
  AND (lower(split_part(image,'\',-1)) IN (
      'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe',
      'mshta.exe','regsvr32.exe','rundll32.exe','certutil.exe')
    OR lower(query_name) LIKE '%.tk' OR lower(query_name) LIKE '%.top'
    OR lower(query_name) LIKE '%.pw' OR lower(query_name) LIKE '%.click'
    OR lower(query_name) LIKE '%.gq' OR lower(query_name) LIKE '%.ml'
    OR len(split_part(query_name,'.',1)) >= 20)
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_unsigned_dll",
		name:          "Sysmon: unsigned DLL loaded by trusted process (T1574.002)",
		severity:      "HIGH",
		requireTables: []string{"sysmon_imageload"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'file', image_loaded, 'detect:sysmon_unsigned_dll', 'HIGH', 'T1574.002',
  'Sysmon7: unsigned DLL in ' || split_part(image,'\',-1) || ' sha256=' || COALESCE(sha256,''), timestamp
FROM sysmon_imageload
WHERE signed = false
  AND lower(split_part(image_loaded,'\',-1)) LIKE '%.dll'
  AND (lower(image_loaded) LIKE '%\temp\%' OR lower(image_loaded) LIKE '%\appdata\%'
    OR lower(image_loaded) LIKE '%\downloads\%' OR lower(image_loaded) LIKE '%\public\%'
    OR lower(image_loaded) LIKE '%\programdata\%')
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "sysmon_masquerade_sysname",
		name:          "Sysmon: system process name running from non-standard path (T1036.005)",
		severity:      "HIGH",
		requireTables: []string{"sysmon_process"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', LEFT(image,300), 'detect:sysmon_masquerade_sysname', 'HIGH', 'T1036.005',
  'Sysmon1: system name outside System32 sha256=' || COALESCE(sha256,''), timestamp
FROM sysmon_process
WHERE lower(split_part(image,'\',-1)) IN (
    'svchost.exe','lsass.exe','csrss.exe','smss.exe','winlogon.exe',
    'services.exe','spoolsv.exe','wininit.exe','lsm.exe','taskhost.exe',
    'taskhostw.exe','dllhost.exe','conhost.exe','explorer.exe')
  AND NOT (lower(image) LIKE '%\system32\%' OR lower(image) LIKE '%\syswow64\%'
    OR lower(image) LIKE '%\winsxs\%' OR lower(image) LIKE '%\windows\explorer%')
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	// ── Event 4688 process-creation detectors ────────────────────────────────
	{
		id:            "proc_create_lolbin",
		name:          "LOLBin process creation (Event 4688)",
		severity:      "HIGH",
		requireTables: []string{"proc_creation"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', image, 'detect:proc_create_lolbin', 'HIGH', 'T1218',
  'LOLBin via event 4688: ' || COALESCE(NULLIF(cmdline,''), image), timestamp
FROM proc_creation
WHERE lower(split_part(image, '\\', -1)) IN (
    'certutil.exe','mshta.exe','regsvr32.exe','wscript.exe','cscript.exe',
    'msiexec.exe','installutil.exe','regasm.exe','regsvcs.exe',
    'odbcconf.exe','ieexec.exe','xwizard.exe','expand.exe','extrac32.exe',
    'pcwrun.exe','appsyncpublishingserver.exe'
)
AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "proc_create_susp_parent",
		name:          "Office/browser spawning shell (Event 4688 parent-child)",
		severity:      "HIGH",
		requireTables: []string{"proc_creation"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', image, 'detect:proc_create_susp_parent', 'HIGH', 'T1566.001',
  'Shell spawned by Office/browser via 4688 — parent=' || COALESCE(parent_image,'?') || ' cmd=' || COALESCE(NULLIF(cmdline,''), image), timestamp
FROM proc_creation
WHERE lower(split_part(image, '\\', -1)) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe')
  AND lower(split_part(COALESCE(parent_image,''), '\\', -1)) IN (
      'winword.exe','excel.exe','powerpnt.exe','outlook.exe','msaccess.exe',
      'chrome.exe','firefox.exe','msedge.exe','iexplore.exe','opera.exe','acrord32.exe'
  )
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
	{
		id:            "proc_create_susp_path",
		name:          "Process created from suspicious path (Event 4688)",
		severity:      "MED",
		requireTables: []string{"proc_creation"},
		insertSQL: `INSERT INTO ioc_indicators("type","value","source","confidence","related_campaign","notes","first_seen")
SELECT DISTINCT 'process', image, 'detect:proc_create_susp_path', 'MED', 'T1036',
  'Executable from suspicious write location: ' || COALESCE(NULLIF(cmdline,''), image), timestamp
FROM proc_creation
WHERE (lower(image) LIKE '%\\temp\\%'
    OR lower(image) LIKE '%\\appdata\\local\\temp\\%'
    OR lower(image) LIKE '%\\appdata\\roaming\\%'
    OR lower(image) LIKE '%\\downloads\\%'
    OR lower(image) LIKE '%\\public\\%'
    OR lower(image) LIKE '%\\users\\public\\%')
  AND lower(split_part(image, '\\', -1)) LIKE '%.exe'
  AND timestamp >= TIMESTAMP '2000-01-01'`,
	},
}

// tableHasData returns true when the named table has at least one row.
func tableHasData(db *sql.DB, table string) bool {
	var n int64
	_ = db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n)
	return n > 0
}

// DataCoverage describes which artifact sources are populated in a case.
type DataCoverage struct {
	Sources map[string]bool
}

// CheckCoverage probes the key artifact tables and returns a coverage snapshot.
func CheckCoverage(db *sql.DB) DataCoverage {
	sources := []string{
		"mft", "evtx_events", "auth_events", "prefetch", "amcache", "shimcache",
		"usnjrnl", "mem_pslist", "mem_psscan", "mem_cmdline", "mem_malfind", "mem_netscan",
		"linux_auth", "shell_history", "proc_creation",
		"sysmon_process", "sysmon_network", "sysmon_dns", "sysmon_imageload",
	}
	cov := DataCoverage{Sources: make(map[string]bool, len(sources))}
	for _, s := range sources {
		cov.Sources[s] = tableHasData(db, s)
	}
	return cov
}

// RunAll clears previous detect results and runs all built-in detectors.
// Detectors whose requireTables are not all populated are skipped.
// Returns per-detector hit counts.
func RunAll(db *sql.DB) ([]Result, error) {
	start := time.Now()

	cov := CheckCoverage(db)

	// Print data coverage summary.
	fmt.Printf("  Data sources: ")
	order := []string{"mft", "evtx_events", "auth_events", "prefetch", "amcache", "shimcache", "mem_pslist", "usnjrnl"}
	for _, s := range order {
		mark := "✗"
		if cov.Sources[s] {
			mark = "✓"
		}
		fmt.Printf("%s%s ", mark, s)
	}
	fmt.Println()

	if _, err := db.Exec(`DELETE FROM ioc_indicators WHERE source LIKE 'detect:%'`); err != nil {
		return nil, fmt.Errorf("detect: clear previous results: %w", err)
	}

	var results []Result
	skipped := 0
	for _, d := range builtins {
		// Skip detectors whose required tables are empty.
		missing := false
		for _, t := range d.requireTables {
			if !cov.Sources[t] {
				missing = true
				break
			}
		}
		if missing {
			skipped++
			continue
		}

		res, err := db.Exec(d.insertSQL)
		if err != nil {
			display.ParserErr("detect:"+d.id, err)
			continue
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			results = append(results, Result{ID: d.id, Name: d.name, Hits: n, Severity: d.severity})
		}
	}

	total := int64(0)
	for _, r := range results {
		total += r.Hits
	}
	skipNote := ""
	if skipped > 0 {
		skipNote = fmt.Sprintf("  skipped %d (missing data)", skipped)
	}
	fmt.Printf("\n  Detectors run: %d%s  |  Total hits: %d  |  %.1fs\n\n",
		len(builtins)-skipped, skipNote, total, time.Since(start).Seconds())

	return results, nil
}
