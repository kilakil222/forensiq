package schema

import (
	"fmt"

	"forensiq/internal/fcase"
)

func Apply(c *fcase.Case) error {
	for i, ddl := range tables {
		if err := c.Exec(ddl); err != nil {
			return fmt.Errorf("schema: table[%d]: %w", i, err)
		}
	}
	for i, ddl := range views {
		if err := c.Exec(ddl); err != nil {
			return fmt.Errorf("schema: view[%d]: %w", i, err)
		}
	}
	return nil
}

var tables = []string{
	// --- Source tracking ---
	`CREATE TABLE IF NOT EXISTS source_files (
		id         INTEGER PRIMARY KEY,
		path       TEXT NOT NULL,
		type       TEXT,
		sha256     TEXT,
		size       BIGINT,
		parsed_at  TIMESTAMP,
		error      TEXT
	)`,

	// --- Execution ---
	`CREATE TABLE IF NOT EXISTS prefetch (
		filename      TEXT, path TEXT, run_count BIGINT,
		last_run      TIMESTAMP, first_seen TIMESTAMP,
		volume_paths TEXT, sha256 TEXT,
		file_refs     TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS amcache (
		path TEXT, sha256 TEXT, compile_time TIMESTAMP,
		first_seen TIMESTAMP, publisher TEXT, version TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS shimcache (
		path TEXT, last_modified TIMESTAMP, executed BOOLEAN, order_idx INTEGER
	)`,
	`CREATE TABLE IF NOT EXISTS userassist (
		path TEXT, run_count INTEGER, last_run TIMESTAMP,
		focus_count INTEGER, focus_duration INTEGER
	)`,
	`CREATE TABLE IF NOT EXISTS bam_dam (
		path TEXT, last_run TIMESTAMP, sid TEXT, source TEXT
	)`,

	// --- Filesystem ---
	`CREATE TABLE IF NOT EXISTS mft (
		inode BIGINT, path TEXT, size BIGINT,
		created TIMESTAMP, modified TIMESTAMP, accessed TIMESTAMP,
		mft_modified TIMESTAMP, is_dir BOOLEAN, is_deleted BOOLEAN,
		ads_name TEXT, flags INTEGER
	)`,
	`CREATE TABLE IF NOT EXISTS usnjrnl (
		usn BIGINT, path TEXT, reason TEXT, timestamp TIMESTAMP,
		file_attributes INTEGER, source_info TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS lnk_files (
		path TEXT, target_path TEXT, created TIMESTAMP, modified TIMESTAMP,
		accessed TIMESTAMP, machine_id TEXT, drive_serial TEXT,
		volume_label TEXT, args TEXT, working_dir TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS jumplists (
		app_id      TEXT,
		app_name    TEXT,
		entry_type  TEXT,
		target_path TEXT,
		created     TIMESTAMP,
		modified    TIMESTAMP,
		accessed    TIMESTAMP,
		access_count INTEGER,
		pin_status  TEXT,
		entry_id    TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS recycle_bin (
		original_path TEXT, deleted_at TIMESTAMP, size BIGINT,
		sid TEXT, i_file TEXT, r_file TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS shellbags (
		path          TEXT,
		last_modified TIMESTAMP,
		"user"        TEXT,
		source        TEXT,
		item_type     TEXT
	)`,

	// --- Registry / Persistence ---
	`CREATE TABLE IF NOT EXISTS persistence (
		type TEXT, name TEXT, command TEXT, path TEXT,
		key_path TEXT, enabled BOOLEAN, sid TEXT, modified TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS services (
		name TEXT, display_name TEXT, start_type TEXT,
		binary_path TEXT, object_name TEXT, modified TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS scheduled_tasks (
		name TEXT, path TEXT, command TEXT, args TEXT,
		trigger TEXT, author TEXT, last_run TIMESTAMP, enabled BOOLEAN
	)`,
	`CREATE TABLE IF NOT EXISTS wmi_subs (
		consumer_name TEXT, consumer_type TEXT,
		filter_name TEXT, filter_query TEXT, created TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS registry_raw (
		hive TEXT, key_path TEXT, value_name TEXT,
		value_type TEXT, value_data TEXT, modified TIMESTAMP
	)`,

	// --- Event Logs ---
	`CREATE TABLE IF NOT EXISTS evtx_events (
		event_id INTEGER, channel TEXT, timestamp TIMESTAMP,
		computer TEXT, user_sid TEXT, provider TEXT,
		message TEXT, xml_raw TEXT, record_id BIGINT
	)`,
	`CREATE TABLE IF NOT EXISTS auth_events (
		event_id INTEGER, timestamp TIMESTAMP, "user" TEXT, domain TEXT,
		logon_type INTEGER, src_ip TEXT, workstation TEXT,
		logon_id TEXT, process_name TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS kerberos_events (
		event_id INTEGER, timestamp TIMESTAMP, "user" TEXT, domain TEXT,
		service_name TEXT, ticket_options TEXT,
		encryption_type TEXT, src_ip TEXT, failure_code TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS ps_scriptblock (
		timestamp TIMESTAMP, script_id TEXT, script_text TEXT,
		path TEXT, level TEXT, computer TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS ps_history (
		command TEXT, timestamp TIMESTAMP,
		source TEXT, "user" TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS defender_events (
		event_id INTEGER, timestamp TIMESTAMP, threat_name TEXT,
		severity TEXT, path TEXT, action TEXT,
		detection_user TEXT, process_name TEXT, sha256 TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS proc_creation (
		event_id        INTEGER,
		timestamp       TIMESTAMP,
		pid             INTEGER,
		ppid            INTEGER,
		image           TEXT,
		cmdline         TEXT,
		parent_image    TEXT,
		user_name       TEXT,
		integrity_level TEXT,
		token_elevation TEXT,
		logon_id        TEXT,
		computer        TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS sysmon_process (
		timestamp       TIMESTAMP,
		pid             INTEGER,
		ppid            INTEGER,
		image           TEXT,
		cmdline         TEXT,
		parent_image    TEXT,
		parent_cmdline  TEXT,
		sha256          TEXT,
		integrity_level TEXT,
		user_name       TEXT,
		logon_id        TEXT,
		computer        TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS sysmon_network (
		timestamp  TIMESTAMP,
		pid        INTEGER,
		image      TEXT,
		proto      TEXT,
		src_ip     TEXT,
		src_port   INTEGER,
		src_host   TEXT,
		dst_ip     TEXT,
		dst_port   INTEGER,
		dst_host   TEXT,
		initiated  BOOLEAN,
		user_name  TEXT,
		computer   TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS sysmon_dns (
		timestamp     TIMESTAMP,
		pid           INTEGER,
		image         TEXT,
		query_name    TEXT,
		query_status  TEXT,
		query_results TEXT,
		user_name     TEXT,
		computer      TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS sysmon_file (
		timestamp       TIMESTAMP,
		pid             INTEGER,
		image           TEXT,
		target_filename TEXT,
		user_name       TEXT,
		computer        TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS sysmon_imageload (
		timestamp    TIMESTAMP,
		pid          INTEGER,
		image        TEXT,
		image_loaded TEXT,
		sha256       TEXT,
		signed       BOOLEAN,
		signature    TEXT,
		user_name    TEXT,
		computer     TEXT
	)`,

	// --- Lateral Movement ---
	`CREATE TABLE IF NOT EXISTS lateral_movement (
		type TEXT, timestamp TIMESTAMP, src_host TEXT, dst_host TEXT,
		"user" TEXT, method TEXT, tool TEXT, details TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS ual_access (
		client_name TEXT, client_ip TEXT, user_sid TEXT,
		access_time TIMESTAMP, role_guid TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS smb_events (
		timestamp TIMESTAMP, "user" TEXT, share TEXT, src_ip TEXT,
		operation TEXT, path TEXT, event_id INTEGER
	)`,
	`CREATE TABLE IF NOT EXISTS rdp_events (
		event_id INTEGER, timestamp TIMESTAMP, "user" TEXT,
		src_ip TEXT, session_id TEXT, duration INTEGER
	)`,

	// --- Browser ---
	`CREATE TABLE IF NOT EXISTS browser_history (
		browser TEXT, url TEXT, title TEXT,
		visit_time TIMESTAMP, visit_count INTEGER, profile TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS browser_downloads (
		browser TEXT, url TEXT, local_path TEXT,
		start_time TIMESTAMP, end_time TIMESTAMP,
		bytes BIGINT, "state" TEXT
	)`,

	// --- Memory (Volatility3) ---
	`CREATE TABLE IF NOT EXISTS mem_pslist (
		pid INTEGER, ppid INTEGER, name TEXT, mem_offset TEXT,
		threads INTEGER, handles INTEGER, wow64 BOOLEAN,
		create_time TIMESTAMP, exit_time TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS mem_psscan (
		pid INTEGER, ppid INTEGER, name TEXT, mem_offset TEXT, create_time TIMESTAMP, exit_time TIMESTAMP, stale_pool BOOLEAN
	)`,
	`CREATE TABLE IF NOT EXISTS mem_cmdline (
		pid INTEGER, name TEXT, cmdline TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_netscan (
		mem_offset TEXT, proto TEXT, local_addr TEXT, local_port INTEGER,
		remote_addr TEXT, remote_port INTEGER, "state" TEXT,
		pid INTEGER, name TEXT, created TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS mem_filescan (
		mem_offset TEXT, name TEXT, path TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_handles (
		pid INTEGER, name TEXT, handle_type TEXT,
		handle_value TEXT, object_name TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_modules (
		pid INTEGER, name TEXT, base TEXT, size BIGINT, path TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_driverscan (
		mem_offset TEXT, name TEXT, size BIGINT, path TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_malfind (
		pid INTEGER, name TEXT, address TEXT, size BIGINT,
		reason TEXT, vad_tag TEXT, hexdump TEXT, disasm TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_sysinfo (
		key TEXT, value TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS mem_hivelist (
		mem_offset TEXT, hive_name TEXT, path TEXT, mapped BOOLEAN
	)`,

	// --- Linux/macOS ---
	`CREATE TABLE IF NOT EXISTS linux_auth (
		timestamp TIMESTAMP, event_type TEXT, "user" TEXT,
		src_ip TEXT, method TEXT, pid INTEGER, message TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS linux_sessions (
		"user" TEXT, terminal TEXT, login_time TIMESTAMP,
		logout_time TIMESTAMP, src_ip TEXT, source TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS shell_history (
		command TEXT, timestamp TIMESTAMP,
		source TEXT, "user" TEXT, shell TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS linux_persistence (
		type TEXT, path TEXT, command TEXT,
		"user" TEXT, enabled BOOLEAN, details TEXT
	)`,

	// --- Email ---
	`CREATE TABLE IF NOT EXISTS emails (
		id           BIGINT,
		source_file  TEXT,
		folder       TEXT,
		message_id   TEXT,
		from_addr    TEXT,
		from_name    TEXT,
		to_addrs     TEXT,
		cc_addrs     TEXT,
		bcc_addrs    TEXT,
		subject      TEXT,
		sent_at      TIMESTAMP,
		received_at  TIMESTAMP,
		body_text    TEXT,
		body_html    TEXT,
		has_attachments BOOLEAN DEFAULT FALSE,
		x_mailer     TEXT,
		x_originating_ip TEXT,
		reply_to     TEXT,
		in_reply_to  TEXT,
		headers_raw  TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS email_attachments (
		email_id     BIGINT,
		filename     TEXT,
		content_type TEXT,
		size_bytes   BIGINT,
		sha256       TEXT,
		is_executable BOOLEAN DEFAULT FALSE
	)`,
	`CREATE TABLE IF NOT EXISTS email_urls (
		email_id  BIGINT,
		url       TEXT,
		domain    TEXT
	)`,

	// --- Windows Error Reporting ---
	`CREATE TABLE IF NOT EXISTS wer_crashes (
		app_name             TEXT,
		app_path             TEXT,
		app_version          TEXT,
		app_timestamp        TEXT,
		crash_time           TIMESTAMP,
		fault_module         TEXT,
		fault_module_version TEXT,
		exception_code       TEXT,
		exception_offset     TEXT,
		bucket_id            TEXT,
		source_file          TEXT
	)`,

	// --- AnyDesk remote-access artifacts ---
	`CREATE TABLE IF NOT EXISTS anydesk_sessions (
		direction    TEXT,
		timestamp    TIMESTAMP,
		auth_method  TEXT,
		client_alias TEXT,
		anydesk_id   TEXT,
		source_file  TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS anydesk_events (
		timestamp   TIMESTAMP,
		pid         INTEGER,
		level       TEXT,
		component   TEXT,
		message     TEXT,
		source_file TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS anydesk_config (
		key         TEXT,
		value       TEXT,
		source_file TEXT
	)`,

	// --- Network configuration (from DHCP/system events) ---
	`CREATE TABLE IF NOT EXISTS network_config (
		timestamp      TIMESTAMP,
		event_id       INTEGER,
		adapter        TEXT,
		ip_addr        TEXT,
		gateway        TEXT,
		dns_servers    TEXT,
		subnet         TEXT,
		dhcp_server    TEXT,
		source         TEXT
	)`,

	// --- BITS (Background Intelligent Transfer Service) ---
	`CREATE TABLE IF NOT EXISTS bits_jobs (
		job_guid    TEXT,
		job_name    TEXT,
		job_type    INTEGER,
		state       INTEGER,
		state_name  TEXT,
		priority    INTEGER,
		owner       TEXT,
		created_at  TIMESTAMP,
		modified_at TIMESTAMP,
		completed_at TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS bits_files (
		job_guid     TEXT,
		file_guid    TEXT,
		remote_url   TEXT,
		local_path   TEXT,
		bytes_total  BIGINT,
		bytes_xferred BIGINT,
		pct_complete REAL
	)`,

	// --- SRUM (System Resource Usage Monitor) ---
	`CREATE TABLE IF NOT EXISTS srum_network_usage (
		timestamp     TIMESTAMP,
		app_id        INTEGER,
		user_id       INTEGER,
		app_name      TEXT,
		user_name     TEXT,
		bytes_sent    BIGINT,
		bytes_recvd   BIGINT,
		iface_luid    BIGINT,
		l2_profile_id INTEGER
	)`,
	`CREATE TABLE IF NOT EXISTS srum_app_usage (
		timestamp     TIMESTAMP,
		app_id        INTEGER,
		user_id       INTEGER,
		app_name      TEXT,
		user_name     TEXT,
		fg_cycles     BIGINT,
		bg_cycles     BIGINT,
		fg_context_switches INTEGER,
		bg_context_switches INTEGER,
		fg_bytes_read BIGINT,
		fg_bytes_written BIGINT
	)`,

	// --- Registry MRU ---
	`CREATE TABLE IF NOT EXISTS typed_urls (
    url         TEXT,
    visit_order INTEGER,
    "user"      TEXT,
    source      TEXT
)`,
	`CREATE TABLE IF NOT EXISTS run_mru (
    command   TEXT,
    mru_order TEXT,
    "user"    TEXT,
    modified  TIMESTAMP
)`,
	`CREATE TABLE IF NOT EXISTS rdp_client_history (
    server    TEXT,
    username  TEXT,
    "user"    TEXT,
    modified  TIMESTAMP
)`,
	`CREATE TABLE IF NOT EXISTS muicache (
    exe_path    TEXT,
    description TEXT,
    "user"      TEXT,
    modified    TIMESTAMP
)`,
	`CREATE TABLE IF NOT EXISTS opensave_mru (
    path      TEXT,
    extension TEXT,
    mru_order TEXT,
    "user"    TEXT,
    modified  TIMESTAMP
)`,

	// --- NTFS $LogFile ---
	`CREATE TABLE IF NOT EXISTS logfile_events (
		lsn            BIGINT,
		operation      TEXT,
		op_code        INTEGER,
		transaction_id BIGINT,
		target_attr    INTEGER,
		filename       TEXT,
		timestamp      TIMESTAMP
	)`,

	// --- Active Directory (NTDS.dit) ---
	`CREATE TABLE IF NOT EXISTS ntds_accounts (
		sam_account_name  TEXT,
		display_name      TEXT,
		description       TEXT,
		object_sid        TEXT,
		last_logon        TIMESTAMP,
		pwd_last_set      TIMESTAMP,
		bad_pwd_count     INTEGER,
		account_flags     INTEGER,
		is_disabled       BOOLEAN,
		is_deleted        BOOLEAN,
		pwd_never_expires BOOLEAN,
		no_pwd_required   BOOLEAN
	)`,

	// --- USB History ---
	`CREATE TABLE IF NOT EXISTS usb_history (
		first_install   TIMESTAMP,
		last_arrival    TIMESTAMP,
		device_id       TEXT,
		friendly_name   TEXT,
		serial_number   TEXT,
		drive_letter    TEXT,
		volume_name     TEXT,
		manufacturer    TEXT,
		"user"          TEXT,
		source          TEXT
	)`,

	// --- Network Adapters ---
	`CREATE TABLE IF NOT EXISTS network_adapters (
		adapter_name    TEXT,
		description     TEXT,
		ip_address      TEXT,
		subnet_mask     TEXT,
		default_gateway TEXT,
		dns_servers     TEXT,
		dhcp_enabled    TEXT,
		mac_address     TEXT,
		source          TEXT
	)`,

	// --- Installed Software ---
	`CREATE TABLE IF NOT EXISTS installed_software (
		display_name    TEXT,
		display_version TEXT,
		publisher       TEXT,
		install_date    TEXT,
		install_location TEXT,
		uninstall_string TEXT,
		"user"          TEXT,
		source          TEXT
	)`,

	// --- Intelligence ---
	`CREATE TABLE IF NOT EXISTS ioc_indicators (
		type TEXT, value TEXT, source TEXT, confidence TEXT,
		related_campaign TEXT, first_seen TIMESTAMP, notes TEXT
	)`,
	`CREATE TABLE IF NOT EXISTS ioc_extracted (
		type       TEXT,
		value      TEXT,
		source     TEXT,
		context    TEXT,
		count      INTEGER DEFAULT 1,
		first_seen TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS attack_techniques (
		technique_id TEXT, name TEXT, tactic TEXT,
		evidence TEXT, artifacts TEXT, confidence TEXT
	)`,
}

var views = []string{
	`CREATE OR REPLACE VIEW v_process_activity AS
		SELECT p.pid, p.ppid, p.name, p.create_time, p.exit_time,
		       c.cmdline, pf.run_count, pf.last_run AS prefetch_last_run,
		       a.sha256 AS amcache_sha256, a.compile_time
		FROM mem_pslist p
		LEFT JOIN mem_cmdline c ON p.pid = c.pid
		LEFT JOIN prefetch pf ON lower(p.name) = lower(pf.filename)
		LEFT JOIN amcache a ON lower(p.name) = lower(split_part(a.path, '\', -1))`,

	`CREATE OR REPLACE VIEW v_network_activity AS
		SELECT n.pid, n.name, n.proto, n.local_addr, n.local_port,
		       n.remote_addr, n.remote_port, n."state", n.created,
		       i.type AS ioc_type, i.related_campaign, i.confidence AS ioc_confidence
		FROM mem_netscan n
		LEFT JOIN ioc_indicators i ON n.remote_addr = i.value`,

	`CREATE OR REPLACE VIEW v_lateral_movement AS
		SELECT 'auth' AS source, timestamp, "user", src_ip AS src,
		       workstation AS dst, CAST(logon_type AS TEXT) AS method
		FROM auth_events WHERE logon_type IN (3, 10)
		UNION ALL
		SELECT 'rdp', timestamp, "user", src_ip, NULL, 'RDP'
		FROM rdp_events
		UNION ALL
		SELECT 'smb', timestamp, "user", src_ip, share, operation
		FROM smb_events`,

	`CREATE OR REPLACE VIEW v_persistence AS
		SELECT 'registry' AS source, type, name, command, modified FROM persistence
		UNION ALL
		SELECT 'service', start_type, name, binary_path, modified FROM services
		UNION ALL
		SELECT 'task', 'scheduled', name, command, last_run FROM scheduled_tasks
		UNION ALL
		SELECT 'wmi', consumer_type, consumer_name, filter_query, created FROM wmi_subs`,

	`CREATE OR REPLACE VIEW v_file_activity AS
		SELECT 'mft' AS source, path, created AS timestamp, 'CREATED' AS event,
		       size, is_deleted
		FROM mft
		UNION ALL
		SELECT 'usnjrnl', path, timestamp, reason, NULL, FALSE
		FROM usnjrnl`,

	`CREATE OR REPLACE VIEW v_user_activity AS
		SELECT 'auth' AS source, timestamp, "user", src_ip AS detail FROM auth_events
		UNION ALL
		SELECT 'shell', timestamp, "user", command FROM shell_history
		UNION ALL
		SELECT 'browser', visit_time, NULL, url FROM browser_history`,

	`CREATE OR REPLACE VIEW v_alerts AS
		SELECT 'defender' AS source, timestamp, threat_name AS name,
		       severity, path, sha256
		FROM defender_events
		UNION ALL
		SELECT 'malfind', NULL, name, 'HIGH', address, NULL
		FROM mem_malfind`,
}
