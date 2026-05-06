package evtx

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	vevtx "www.velocidex.com/golang/evtx"

	"forensiq/internal/parsers"
)

// Progress is an alias so callers don't need to import parsers directly.
type Progress = parsers.Progress

// Parser implements parsers.Parser for Windows Event Log (.evtx) files.
type Parser struct {
	channel string
}

// New returns a new EVTX parser for the given channel name (e.g. "Security").
func New(channel string) *Parser {
	return &Parser{channel: channel}
}

// Name returns a human-readable label such as "EVTX/Security".
func (p *Parser) Name() string {
	return "EVTX/" + p.channel
}

// Parse reads an EVTX file from r, inserts all events into evtx_events, and
// routes specialised events to the typed tables.
func (p *Parser) Parse(r io.Reader, db *sql.DB, ch chan<- Progress) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("evtx: read: %w", err)
	}

	rs := newReadSeeker(data)

	chunks, err := vevtx.GetChunks(rs)
	if err != nil {
		return fmt.Errorf("evtx: get chunks: %w", err)
	}

	// Wrap all inserts in a single transaction for 10-50x speedup on bulk inserts.
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("evtx: begin transaction: %w", err)
	}
	// Rollback is a no-op after a successful Commit.
	defer func() { _ = tx.Rollback() }()

	// Prepare statements on the transaction.
	stmtEvtx, err := tx.Prepare(`INSERT INTO evtx_events
		(event_id, channel, timestamp, computer, user_sid, provider, message, record_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare evtx_events: %w", err)
	}
	defer stmtEvtx.Close()

	stmtAuth, err := tx.Prepare(`INSERT INTO auth_events
		(event_id, timestamp, "user", domain, logon_type, src_ip, workstation, logon_id, process_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare auth_events: %w", err)
	}
	defer stmtAuth.Close()

	stmtKerb, err := tx.Prepare(`INSERT INTO kerberos_events
		(event_id, timestamp, "user", domain, service_name, ticket_options, encryption_type, src_ip, failure_code)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare kerberos_events: %w", err)
	}
	defer stmtKerb.Close()

	stmtPS, err := tx.Prepare(`INSERT INTO ps_scriptblock
		(timestamp, script_id, script_text, path, level, computer)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare ps_scriptblock: %w", err)
	}
	defer stmtPS.Close()

	stmtDef, err := tx.Prepare(`INSERT INTO defender_events
		(event_id, timestamp, threat_name, severity, path, action, detection_user, process_name, sha256)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare defender_events: %w", err)
	}
	defer stmtDef.Close()

	stmtProc, err := tx.Prepare(`INSERT INTO proc_creation
		(event_id, timestamp, pid, ppid, image, cmdline, parent_image, user_name, integrity_level, token_elevation, logon_id, computer)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare proc_creation: %w", err)
	}
	defer stmtProc.Close()

	stmtSysProc, err := tx.Prepare(`INSERT INTO sysmon_process
		(timestamp, pid, ppid, image, cmdline, parent_image, parent_cmdline, sha256, integrity_level, user_name, logon_id, computer)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare sysmon_process: %w", err)
	}
	defer stmtSysProc.Close()

	stmtSysNet, err := tx.Prepare(`INSERT INTO sysmon_network
		(timestamp, pid, image, proto, src_ip, src_port, src_host, dst_ip, dst_port, dst_host, initiated, user_name, computer)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare sysmon_network: %w", err)
	}
	defer stmtSysNet.Close()

	stmtSysDNS, err := tx.Prepare(`INSERT INTO sysmon_dns
		(timestamp, pid, image, query_name, query_status, query_results, user_name, computer)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare sysmon_dns: %w", err)
	}
	defer stmtSysDNS.Close()

	stmtSysFile, err := tx.Prepare(`INSERT INTO sysmon_file
		(timestamp, pid, image, target_filename, user_name, computer)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare sysmon_file: %w", err)
	}
	defer stmtSysFile.Close()

	stmtSysImg, err := tx.Prepare(`INSERT INTO sysmon_imageload
		(timestamp, pid, image, image_loaded, sha256, signed, signature, user_name, computer)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("evtx: prepare sysmon_imageload: %w", err)
	}
	defer stmtSysImg.Close()

	start := time.Now()
	var count int64

	for _, chunk := range chunks {
		records, err := parseChunkSafe(chunk)
		if err != nil {
			continue
		}

		for _, rec := range records {
			eventMap, ok := rec.Event.(*ordereddict.Dict)
			if !ok {
				continue
			}
			event, ok := ordereddict.GetMap(eventMap, "Event")
			if !ok {
				continue
			}

			// --- Extract System fields ---
			eventID, _ := ordereddict.GetInt(event, "System.EventID.Value")
			ts := getFloat(event, "System.TimeCreated.SystemTime")
			computer := getString(event, "System.Computer")
			userSID := getString(event, "System.Security.UserID")
			provider := getString(event, "System.Provider.Name")
			recordID, _ := ordereddict.GetInt(event, "System.EventRecordID")

			// Serialize EventData as JSON for the message field
			var message string
			if ed, pres := event.Get("EventData"); pres {
				if b, err2 := json.Marshal(ed); err2 == nil {
					message = string(b)
				}
			}

			timestamp := unixFloatToTime(ts)

			// Insert into evtx_events; skip count++ and routing on failure.
			_, err = stmtEvtx.Exec(
				eventID,
				p.channel,
				timestamp,
				computer,
				userSID,
				provider,
				message,
				recordID,
			)
			if err != nil {
				log.Printf("evtx: insert evtx_events record_id=%d: %v", recordID, err)
				continue
			}
			count++

			// --- Route to specialised tables ---
			switch eventID {
			case 4624, 4625, 4648:
				p.insertAuth(stmtAuth, event, eventID, timestamp)
			case 4768, 4769:
				p.insertKerberos(stmtKerb, event, eventID, timestamp)
			case 4104:
				// Many providers reuse event_id 4104 (e.g. MSDTC). Only treat as PS
				// script-block if the EVTX channel is the PowerShell operational log.
				if strings.Contains(p.channel, "PowerShell") {
					p.insertScriptblock(stmtPS, event, timestamp, computer)
				}
			case 1116, 1117:
				p.insertDefender(stmtDef, event, eventID, timestamp)
			case 4688:
				p.insertProcCreate(stmtProc, event, timestamp, computer)
			case 1, 3, 7, 11, 22:
				if strings.Contains(p.channel, "Sysmon") {
					switch eventID {
					case 1:
						p.insertSysmonProcess(stmtSysProc, event, timestamp, computer)
					case 3:
						p.insertSysmonNetwork(stmtSysNet, event, timestamp, computer)
					case 7:
						p.insertSysmonImageLoad(stmtSysImg, event, timestamp, computer)
					case 11:
						p.insertSysmonFile(stmtSysFile, event, timestamp, computer)
					case 22:
						p.insertSysmonDNS(stmtSysDNS, event, timestamp, computer)
					}
				}
			}

			if count%10000 == 0 {
				// Non-blocking send: drop progress update if consumer is not keeping up.
				select {
				case ch <- parsers.Progress{
					Parser:  p.Name(),
					Count:   count,
					Elapsed: time.Since(start),
				}:
				default:
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("evtx: commit transaction: %w", err)
	}

	// Final Done send is blocking — the caller must drain the channel.
	ch <- parsers.Progress{
		Parser:  p.Name(),
		Count:   count,
		Done:    true,
		Elapsed: time.Since(start),
	}
	return nil
}

func (p *Parser) insertAuth(stmt *sql.Stmt, event *ordereddict.Dict, eventID int, ts time.Time) {
	ed := getEventData(event)
	user := edString(ed, "TargetUserName")
	domain := edString(ed, "TargetDomainName")
	logonType, _ := edInt(ed, "LogonType")
	srcIP := edString(ed, "IpAddress")
	workstation := edString(ed, "WorkstationName")
	logonID := edString(ed, "TargetLogonId")
	processName := edString(ed, "ProcessName")

	if _, err := stmt.Exec(eventID, ts, user, domain, logonType, srcIP, workstation, logonID, processName); err != nil {
		log.Printf("evtx: insert auth_events event_id=%d: %v", eventID, err)
	}
}

func (p *Parser) insertKerberos(stmt *sql.Stmt, event *ordereddict.Dict, eventID int, ts time.Time) {
	ed := getEventData(event)
	user := edString(ed, "TargetUserName")
	domain := edString(ed, "TargetDomainName")
	serviceName := edString(ed, "ServiceName")
	ticketOptions := edString(ed, "TicketOptions")
	encType := edString(ed, "TicketEncryptionType")
	srcIP := edString(ed, "IpAddress")
	failureCode := edString(ed, "Status")

	if _, err := stmt.Exec(eventID, ts, user, domain, serviceName, ticketOptions, encType, srcIP, failureCode); err != nil {
		log.Printf("evtx: insert kerberos_events event_id=%d: %v", eventID, err)
	}
}

func (p *Parser) insertScriptblock(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	scriptID := edString(ed, "ScriptBlockId")
	scriptText := edString(ed, "ScriptBlockText")
	path := edString(ed, "Path")
	level := getString(event, "System.Level")

	if _, err := stmt.Exec(ts, scriptID, scriptText, path, level, computer); err != nil {
		log.Printf("evtx: insert ps_scriptblock: %v", err)
	}
}

func (p *Parser) insertDefender(stmt *sql.Stmt, event *ordereddict.Dict, eventID int, ts time.Time) {
	ed := getEventData(event)
	threatName := edString(ed, "Threat Name")
	severity := edString(ed, "Severity Name")
	path := edString(ed, "Path")
	action := edString(ed, "Action Name")
	detectionUser := edString(ed, "Detection User")
	processName := edString(ed, "Process Name")
	sha256 := edString(ed, "SHA-256")

	if _, err := stmt.Exec(eventID, ts, threatName, severity, path, action, detectionUser, processName, sha256); err != nil {
		log.Printf("evtx: insert defender_events event_id=%d: %v", eventID, err)
	}
}

func (p *Parser) insertProcCreate(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	image := edString(ed, "NewProcessName")
	cmdline := edString(ed, "CommandLine")
	parentImage := edString(ed, "ParentProcessName")
	userName := edString(ed, "SubjectUserName")
	integLabel := edString(ed, "MandatoryLabel")
	tokenElev := edString(ed, "TokenElevationType")
	logonID := edString(ed, "SubjectLogonId")
	pid := hexToInt64(edString(ed, "NewProcessId"))
	ppid := hexToInt64(edString(ed, "ProcessId"))
	integrity := labelToIntegrity(integLabel)
	if _, err := stmt.Exec(4688, ts, pid, ppid, image, cmdline, parentImage, userName, integrity, tokenElev, logonID, computer); err != nil {
		log.Printf("evtx: insert proc_creation: %v", err)
	}
}

func (p *Parser) insertSysmonProcess(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	pid := edDecimalInt(ed, "ProcessId")
	ppid := edDecimalInt(ed, "ParentProcessId")
	image := edString(ed, "Image")
	cmdline := edString(ed, "CommandLine")
	parentImage := edString(ed, "ParentImage")
	parentCmdline := edString(ed, "ParentCommandLine")
	sha256 := parseSysmonSHA256(edString(ed, "Hashes"))
	integrity := edString(ed, "IntegrityLevel")
	user := edString(ed, "User")
	logonID := edString(ed, "LogonId")
	if _, err := stmt.Exec(ts, pid, ppid, image, cmdline, parentImage, parentCmdline, sha256, integrity, user, logonID, computer); err != nil {
		log.Printf("evtx: insert sysmon_process: %v", err)
	}
}

func (p *Parser) insertSysmonNetwork(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	pid := edDecimalInt(ed, "ProcessId")
	image := edString(ed, "Image")
	user := edString(ed, "User")
	proto := edString(ed, "Protocol")
	initiated := strings.EqualFold(edString(ed, "Initiated"), "true")
	srcIP := edString(ed, "SourceIp")
	srcPort := edDecimalInt(ed, "SourcePort")
	srcHost := edString(ed, "SourceHostname")
	dstIP := edString(ed, "DestinationIp")
	dstPort := edDecimalInt(ed, "DestinationPort")
	dstHost := edString(ed, "DestinationHostname")
	if _, err := stmt.Exec(ts, pid, image, proto, srcIP, srcPort, srcHost, dstIP, dstPort, dstHost, initiated, user, computer); err != nil {
		log.Printf("evtx: insert sysmon_network: %v", err)
	}
}

func (p *Parser) insertSysmonDNS(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	pid := edDecimalInt(ed, "ProcessId")
	image := edString(ed, "Image")
	user := edString(ed, "User")
	queryName := edString(ed, "QueryName")
	queryStatus := edString(ed, "QueryStatus")
	queryResults := edString(ed, "QueryResults")
	if _, err := stmt.Exec(ts, pid, image, queryName, queryStatus, queryResults, user, computer); err != nil {
		log.Printf("evtx: insert sysmon_dns: %v", err)
	}
}

func (p *Parser) insertSysmonFile(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	pid := edDecimalInt(ed, "ProcessId")
	image := edString(ed, "Image")
	target := edString(ed, "TargetFilename")
	user := edString(ed, "User")
	if _, err := stmt.Exec(ts, pid, image, target, user, computer); err != nil {
		log.Printf("evtx: insert sysmon_file: %v", err)
	}
}

func (p *Parser) insertSysmonImageLoad(stmt *sql.Stmt, event *ordereddict.Dict, ts time.Time, computer string) {
	ed := getEventData(event)
	pid := edDecimalInt(ed, "ProcessId")
	image := edString(ed, "Image")
	imageLoaded := edString(ed, "ImageLoaded")
	sha256 := parseSysmonSHA256(edString(ed, "Hashes"))
	signed := strings.EqualFold(edString(ed, "Signed"), "true")
	signature := edString(ed, "Signature")
	user := edString(ed, "User")
	if _, err := stmt.Exec(ts, pid, image, imageLoaded, sha256, signed, signature, user, computer); err != nil {
		log.Printf("evtx: insert sysmon_imageload: %v", err)
	}
}

func edDecimalInt(d *ordereddict.Dict, key string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(edString(d, key)), 10, 64)
	return n
}

func parseSysmonSHA256(hashes string) string {
	for _, part := range strings.Split(hashes, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "SHA256=") {
			return part[7:]
		}
	}
	return ""
}

func hexToInt64(s string) int64 {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	n, _ := strconv.ParseInt(s, 16, 64)
	return n
}

func labelToIntegrity(sid string) string {
	switch sid {
	case "S-1-16-16384":
		return "System"
	case "S-1-16-12288":
		return "High"
	case "S-1-16-8192":
		return "Medium"
	case "S-1-16-4096":
		return "Low"
	case "S-1-16-0":
		return "Untrusted"
	default:
		return sid
	}
}

// --- helpers ---

func getEventData(event *ordereddict.Dict) *ordereddict.Dict {
	v, pres := event.Get("EventData")
	if !pres {
		return ordereddict.NewDict()
	}
	d, ok := v.(*ordereddict.Dict)
	if !ok {
		return ordereddict.NewDict()
	}
	return d
}

func edString(d *ordereddict.Dict, key string) string {
	v, pres := d.Get(key)
	if !pres {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		return fmt.Sprintf("%v", v)
	}
}

func edInt(d *ordereddict.Dict, key string) (int, bool) {
	v, pres := d.Get(key)
	if !pres {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	}
	return 0, false
}

func getString(d *ordereddict.Dict, path string) string {
	v, pres := ordereddict.GetString(d, path)
	if !pres {
		return ""
	}
	return v
}

func getFloat(d *ordereddict.Dict, path string) float64 {
	v, pres := ordereddict.GetAny(d, path)
	if !pres {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case uint64:
		return float64(n)
	}
	return 0
}

func unixFloatToTime(f float64) time.Time {
	if f == 0 {
		return time.Time{}
	}
	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

func parseChunkSafe(chunk *vevtx.Chunk) (records []*vevtx.EventRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("evtx: chunk parse panic: %v", r)
		}
	}()
	return chunk.Parse(0)
}

// readSeeker wraps a byte slice to implement io.ReadSeeker.
type readSeeker struct {
	data   []byte
	offset int64
}

func newReadSeeker(data []byte) *readSeeker {
	return &readSeeker{data: data}
}

func (rs *readSeeker) Read(p []byte) (int, error) {
	if rs.offset >= int64(len(rs.data)) {
		return 0, io.EOF
	}
	n := copy(p, rs.data[rs.offset:])
	rs.offset += int64(n)
	return n, nil
}

func (rs *readSeeker) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = rs.offset + offset
	case io.SeekEnd:
		abs = int64(len(rs.data)) + offset
	default:
		return 0, fmt.Errorf("readSeeker: invalid whence %d", whence)
	}
	if abs < 0 {
		return 0, fmt.Errorf("readSeeker: negative position")
	}
	rs.offset = abs
	return abs, nil
}
