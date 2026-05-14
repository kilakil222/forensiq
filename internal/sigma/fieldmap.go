package sigma

import "strings"

type logsourceDef struct {
	from    string            // SQL FROM clause (may include JOINs)
	valExpr string            // expression for the ioc_indicators.value column
	tsExpr  string            // expression for the first_seen timestamp
	fields  map[string]string // SIGMA field name → SQL column expression
}

// logsourceMap maps (category, product, service) → logsourceDef.
// Keys are "category", "product:category", or "service" — looked up in priority order.
var logsourceMap = map[string]logsourceDef{
	// process_creation unions live RAM processes with 4688 disk events so rules
	// fire on both memory captures and disk-only cases.
	"process_creation": {
		from: `(
			SELECT p.name AS _img, COALESCE(c.cmdline,'') AS _cmd,
			       '' AS _parent_img, '' AS _parent_cmd, '' AS _user, '' AS _integrity,
			       p.create_time AS _ts,
			       COALESCE(p.name,'?')||' (PID '||CAST(p.pid AS VARCHAR)||')' AS _val
			FROM mem_pslist p LEFT JOIN mem_cmdline c ON p.pid = c.pid
			UNION ALL
			SELECT COALESCE(image,'') AS _img, COALESCE(cmdline,'') AS _cmd,
			       COALESCE(parent_image,'') AS _parent_img,
			       COALESCE(parent_cmdline,'') AS _parent_cmd,
			       COALESCE(user_name,'') AS _user,
			       COALESCE(integrity_level,'') AS _integrity,
			       timestamp AS _ts,
			       COALESCE(image,'?')||' [4688]' AS _val
			FROM proc_creation
		) _pc`,
		valExpr: `_val`,
		tsExpr:  `_ts`,
		fields: map[string]string{
			"Image":             "_img",
			"OriginalFileName":  "_img",
			"ProcessName":       "_img",
			"CommandLine":       "_cmd",
			"ParentImage":       "_parent_img",
			"ParentProcessName": "_parent_img",
			"ParentCommandLine": "_parent_cmd",
			"User":              "_user",
			"IntegrityLevel":    "_integrity",
			"ProcessId":         "''",
			"ParentProcessId":   "''",
			"Hashes":            "''",
		},
	},
	"network_connection": {
		from:    `mem_netscan`,
		valExpr: `COALESCE(name,'?') || ' → ' || COALESCE(remote_addr,'?') || ':' || CAST(COALESCE(remote_port,0) AS VARCHAR)`,
		tsExpr:  `created`,
		fields: map[string]string{
			"DestinationIp":       "remote_addr",
			"DestinationPort":     "CAST(remote_port AS VARCHAR)",
			"DestinationHostname": "remote_addr",
			"SourceIp":            "local_addr",
			"SourcePort":          "CAST(local_port AS VARCHAR)",
			"Image":               "name",
			"ProcessId":           "CAST(pid AS VARCHAR)",
			"Protocol":            "proto",
			"Initiated":           "''",
		},
	},
	"file_event": {
		from:    `mft`,
		valExpr: `path`,
		tsExpr:  `modified`,
		fields: map[string]string{
			"TargetFilename": "path",
			"FileName":       "path",
			"FilePath":       "path",
			"CreationUtcTime": "created",
		},
	},
	"file_change": {
		from:    `mft`,
		valExpr: `path`,
		tsExpr:  `modified`,
		fields: map[string]string{
			"TargetFilename": "path",
			"FileName":       "path",
		},
	},
	"file_delete": {
		from:    `mft`,
		valExpr: `path`,
		tsExpr:  `modified`,
		fields: map[string]string{
			"TargetFilename": "path",
			"FileName":       "path",
			"IsExecutable":   "''",
		},
	},
	// EVTX-based logsources — all map to evtx_events
	"security": {
		from:    `evtx_events`,
		valExpr: `CAST(event_id AS VARCHAR) || ': ' || COALESCE(message,'')`,
		tsExpr:  `timestamp`,
		fields:  evtxFields,
	},
	"system": {
		from:    `evtx_events`,
		valExpr: `CAST(event_id AS VARCHAR) || ': ' || COALESCE(message,'')`,
		tsExpr:  `timestamp`,
		fields:  evtxFields,
	},
	"application": {
		from:    `evtx_events`,
		valExpr: `CAST(event_id AS VARCHAR) || ': ' || COALESCE(message,'')`,
		tsExpr:  `timestamp`,
		fields:  evtxFields,
	},
	"powershell-classic": {
		from:    `ps_scriptblock`,
		valExpr: `COALESCE(script_text,'')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"ScriptBlockText": "script_text",
			"Path":            "path",
			"Level":           "level",
		},
	},
	"ps_script": {
		from:    `ps_scriptblock`,
		valExpr: `COALESCE(script_text,'')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"ScriptBlockText": "script_text",
			"Path":            "path",
		},
	},
	"defender": {
		from:    `defender_events`,
		valExpr: `COALESCE(threat_name,'?') || ' | ' || COALESCE(path,'?')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"ThreatName": "threat_name",
			"Path":       "path",
			"Action":     "action",
			"Severity":   "severity",
		},
	},
	// Catch-all for any EVTX by service name
	"sysmon": {
		from:    `evtx_events`,
		valExpr: `CAST(event_id AS VARCHAR) || ': ' || COALESCE(message,'')`,
		tsExpr:  `timestamp`,
		fields:  evtxFields,
	},
	// Structured auth table — enables precise user/IP/logon_type matching vs message text search
	"auth": {
		from:    `auth_events`,
		valExpr: `COALESCE("user",'?') || ' [' || CAST(event_id AS VARCHAR) || '] from ' || COALESCE(src_ip,'-')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"EventID":          "event_id",
			"User":             `"user"`,
			"TargetUserName":   `"user"`,
			"SubjectUserName":  `"user"`,
			"Domain":           "domain",
			"IpAddress":        "src_ip",
			"WorkstationName":  "workstation",
			"LogonType":        "CAST(logon_type AS VARCHAR)",
			"ProcessName":      "process_name",
		},
	},
	// Sysmon-specific structured tables (parsed from EVTX Event IDs)
	"sysmon_imageload": {
		from:    `sysmon_imageload`,
		valExpr: `COALESCE(image,'?') || ' → ' || COALESCE(image_loaded,'?')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"Image":       "image",
			"ImageLoaded": "image_loaded",
			"Signed":      "signed",
			"Signature":   "signature",
			"User":        "user_name",
			"SHA256":      "sha256",
		},
	},
	"sysmon_dns": {
		from:    `sysmon_dns`,
		valExpr: `COALESCE(query_name,'?')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"Image":        "image",
			"QueryName":    "query_name",
			"QueryStatus":  "query_status",
			"QueryResults": "query_results",
			"User":         "user_name",
		},
	},
	// Structured sysmon network table (faster and more precise than evtx message search)
	"sysmon:network_connection": {
		from:    `sysmon_network`,
		valExpr: `COALESCE(image,'?') || ' → ' || COALESCE(dst_ip,'?') || ':' || CAST(COALESCE(dst_port,0) AS VARCHAR)`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"DestinationIp":       "dst_ip",
			"DestinationPort":     "CAST(dst_port AS VARCHAR)",
			"DestinationHostname": "dst_host",
			"SourceIp":            "src_ip",
			"SourcePort":          "CAST(src_port AS VARCHAR)",
			"Image":               "image",
			"ProcessId":           "CAST(pid AS VARCHAR)",
			"Protocol":            "proto",
			"Initiated":           "CAST(initiated AS VARCHAR)",
			"User":                "user_name",
			"Computer":            "computer",
		},
	},
	// Registry events — mapped to our structured registry_raw table
	"registry_event": {
		from:    `registry_raw`,
		valExpr: `COALESCE(hive,'') || chr(92) || COALESCE(key_path,'') || chr(92) || COALESCE(value_name,'')`,
		tsExpr:  `modified`,
		fields: map[string]string{
			"TargetObject": `hive || chr(92) || key_path || chr(92) || value_name`,
			"Details":      "value_data",
			"EventType":    "''",
			"Image":        "''",
			"ProcessId":    "''",
			"User":         "''",
		},
	},
	"registry_add": {
		from:    `registry_raw`,
		valExpr: `COALESCE(hive,'') || chr(92) || COALESCE(key_path,'') || chr(92) || COALESCE(value_name,'')`,
		tsExpr:  `modified`,
		fields: map[string]string{
			"TargetObject": `hive || chr(92) || key_path || chr(92) || value_name`,
			"Details":      "value_data",
			"EventType":    "''",
		},
	},
	"registry_set": {
		from:    `registry_raw`,
		valExpr: `COALESCE(hive,'') || chr(92) || COALESCE(key_path,'') || chr(92) || COALESCE(value_name,'')`,
		tsExpr:  `modified`,
		fields: map[string]string{
			"TargetObject": `hive || chr(92) || key_path || chr(92) || value_name`,
			"Details":      "value_data",
			"EventType":    "''",
		},
	},
	// DNS query events — structured sysmon_dns table
	"sysmon:dns_query": {
		from:    `sysmon_dns`,
		valExpr: `COALESCE(image,'?') || ' queried ' || COALESCE(query_name,'?')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"QueryName":    "query_name",
			"QueryStatus":  "query_status",
			"QueryResults": "query_results",
			"Image":        "image",
			"ProcessId":    "CAST(pid AS VARCHAR)",
			"User":         "user_name",
		},
	},
	// Driver/image load events
	"driver_load": {
		from:    `sysmon_imageload`,
		valExpr: `COALESCE(image_loaded,'?')`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"ImageLoaded": "image_loaded",
			"Signed":      "CAST(signed AS VARCHAR)",
			"Signature":   "signature",
			"SHA256":      "sha256",
			"Image":       "image",
		},
	},
	// Pipe creation (from EVTX event 17/18 or proc_creation)
	"pipe_created": {
		from:    `evtx_events`,
		valExpr: `COALESCE(message,'')`,
		tsExpr:  `timestamp`,
		fields:  evtxFields,
	},
	// Process tampering (Sysmon event 25)
	"process_tampering": {
		from:    `sysmon_process`,
		valExpr: `COALESCE(image,'?') || ' [' || CAST(COALESCE(pid,0) AS VARCHAR) || ']'`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"Image":  "image",
			"User":   "user_name",
			"Hashes": "sha256",
		},
	},
	// Shell history (Linux/macOS coverage)
	"shell_history": {
		from:    `shell_history`,
		valExpr: `COALESCE("user",'?') || ': ' || LEFT(COALESCE(command,''),200)`,
		tsExpr:  `timestamp`,
		fields: map[string]string{
			"CommandLine": "command",
			"User":        `"user"`,
			"Shell":       "shell",
		},
	},
	// WMI events
	"wmi_event": {
		from:    `wmi_subs`,
		valExpr: `COALESCE(consumer_name,'?') || ' | ' || COALESCE(filter_query,'?')`,
		tsExpr:  `created`,
		fields: map[string]string{
			"Name":         "consumer_name",
			"ConsumerType": "consumer_type",
			"Filter":       "filter_query",
			"Query":        "filter_query",
		},
	},
	// Scheduled tasks
	"task_scheduler": {
		from:    `scheduled_tasks`,
		valExpr: `COALESCE(name,'?') || ': ' || COALESCE(command,'?')`,
		tsExpr:  `last_run`,
		fields: map[string]string{
			"TaskName":    "name",
			"TaskPath":    "path",
			"CommandLine": "command || COALESCE(' ' || args, '')",
			"Author":      "author",
		},
	},
	// Sysmon process creation (structured table, more precise than proc_creation union)
	"sysmon:process_creation": {
		from: `(
        SELECT image AS _img, COALESCE(cmdline,'') AS _cmd,
               COALESCE(parent_image,'') AS _parent_img,
               COALESCE(parent_cmdline,'') AS _parent_cmd,
               COALESCE(user_name,'') AS _user,
               COALESCE(integrity_level,'') AS _integrity,
               timestamp AS _ts,
               COALESCE(sha256,'') AS _sha256,
               COALESCE(image,'?')||' [sysmon]' AS _val
        FROM sysmon_process
    ) _sp`,
		valExpr: `_val`,
		tsExpr:  `_ts`,
		fields: map[string]string{
			"Image":             "_img",
			"OriginalFileName":  "_img",
			"CommandLine":       "_cmd",
			"ParentImage":       "_parent_img",
			"ParentCommandLine": "_parent_cmd",
			"User":              "_user",
			"IntegrityLevel":    "_integrity",
			"Hashes":            "_sha256",
			"SHA256":            "_sha256",
		},
	},
}

// evtxFields is shared across EVTX-based logsources.
var evtxFields = map[string]string{
	"EventID":            "event_id",
	"Channel":            "channel",
	"Computer":           "computer",
	"Message":            "message",
	"Provider_Name":      "provider",
	"SubjectUserName":    "message",
	"TargetUserName":     "message",
	"WorkstationName":    "message",
	"IpAddress":          "message",
	"CommandLine":        "message",
	"ImagePath":          "message",
	"ServiceName":        "message",
	"TaskName":           "message",
	"ScriptBlockText":    "message",
}

// resolveLogsource finds the best matching logsourceDef for a rule.
func resolveLogsource(rule *Rule) (logsourceDef, bool) {
	ls := rule.Logsource
	candidates := []string{
		strings.ToLower(ls.Category),
		strings.ToLower(ls.Service),
		strings.ToLower(ls.Product + ":" + ls.Category),
	}
	// Try "product:category" combination with sysmon prefix
	if strings.ToLower(ls.Product) == "windows" && ls.Category != "" {
		candidates = append(candidates, "sysmon:"+strings.ToLower(ls.Category))
	}
	for _, key := range candidates {
		if key == "" || key == ":" {
			continue
		}
		if def, ok := logsourceMap[key]; ok {
			return def, true
		}
	}
	return logsourceDef{}, false
}
