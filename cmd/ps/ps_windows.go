//go:build windows

package ps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// collectProcesses on Windows uses PowerShell CIM (Win32_Process) to retrieve
// rich per-process information in one pass. It avoids fragile remote PEB
// parsing and works on stock Windows.
func collectProcesses() ([]*Process, error) {
	script := psScript()
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	if err != nil {
		// Surface a friendlier error when PowerShell is unavailable or blocked
		return nil, errors.New("failed to query processes via PowerShell CIM; ensure PowerShell is available and ExecutionPolicy allows running inline commands")
	}

	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()

	// The output can be either an array or a single object depending on system state.
	var raw any
	if err := dec.Decode(&raw); err != nil {
		// If the buffer contains BOM or warnings, try to sanitize line-by-line and re-decode
		sanitized := sanitizeJSON(out)
		dec2 := json.NewDecoder(bytes.NewReader(sanitized))
		dec2.UseNumber()
		if err2 := dec2.Decode(&raw); err2 != nil {
			return nil, err
		}
	}

	rows := toSliceOfMaps(raw)
	now := time.Now()
	procs := make([]*Process, 0, len(rows))

	for _, m := range rows {
		pid := int(getInt64(m, "ProcessId"))
		if pid <= 0 {
			continue
		}

		ppid := int(getInt64(m, "ParentProcessId"))
		name := getString(m, "Name")
		cmd := getString(m, "CommandLine")
		exe := getString(m, "ExecutablePath")

		// Times
		ut100 := getUint64(m, "UserModeTime")   // in 100ns
		kt100 := getUint64(m, "KernelModeTime") // in 100ns
		cpuUser := float64(ut100) / 1e7
		cpuSys := float64(kt100) / 1e7

		// Memory
		rss := int64(getInt64(m, "WorkingSetSize"))
		vms := int64(getInt64(m, "VirtualSize"))

		// Threads / priority
		th := int(getInt64(m, "ThreadCount"))
		prio := int(getInt64(m, "Priority"))

		// Start/elapsed
		var start time.Time
		if cd := getString(m, "CreationDate"); cd != "" {
			if t, ok := parseCIMDateTime(cd); ok {
				start = t
			}
		}
		elapsedI64 := int64(0)
		if !start.IsZero() {
			elapsedI64 = int64(now.Sub(start).Seconds())
		}

		// Owner (Domain\User) if available
		owner := getString(m, "User")

		// I/O transfer counts (bytes)
		readBytes := getUint64(m, "ReadTransferCount")
		writeBytes := getUint64(m, "WriteTransferCount")
		var io *ProcIO
		if readBytes != 0 || writeBytes != 0 {
			io = &ProcIO{ReadBytes: readBytes, WriteBytes: writeBytes}
		}

		// On Windows, UID/GID semantics don't apply; we fill names when available.
		p := &Process{
			PID:   pid,
			PPID:  ppid,
			UID:   0,
			GID:   0,
			User:  owner,
			Group: "",

			State:   "", // Windows doesn't map cleanly to R/S/D/T/Z/I
			TTY:     "", // No TTY concept per process like Unix; leave empty
			Comm:    name,
			Command: cmd,

			Exe: exe,
			Cwd: "", // expensive to query on Windows; omit

			CPUUserSeconds:   cpuUser,
			CPUSystemSeconds: cpuSys,
			MemRSSBytes:      rss,
			MemVMSBytes:      vms,

			Threads:  intPtr(th),
			Priority: intPtr(prio),
			// Nice is not a Windows concept; leave nil

			StartTime:       utcRFC3339(start),
			StartTimeUnixNs: start.UnixNano(),
			ElapsedSeconds:  int64Ptr(elapsedI64),

			// Windows has no cgroups/namespaces/SELinux
			IO: io,
		}

		procs = append(procs, p)
	}

	return procs, nil
}

func psScript() string {
	// Build a PowerShell script that returns a JSON array of processes with selected fields.
	// We also compute a friendly User string via GetOwner, but ignore errors for protected/system processes.
	return `
$ErrorActionPreference = 'SilentlyContinue'
$procs = Get-CimInstance Win32_Process
$rows = foreach ($p in $procs) {
    $owner = $null
    try { $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner } catch {}
    [pscustomobject]@{
        ProcessId         = $p.ProcessId
        ParentProcessId   = $p.ParentProcessId
        Name              = $p.Name
        CommandLine       = $p.CommandLine
        ExecutablePath    = $p.ExecutablePath
        CreationDate      = $p.CreationDate
        WorkingSetSize    = $p.WorkingSetSize
        VirtualSize       = $p.VirtualSize
        ThreadCount       = $p.ThreadCount
        Priority          = $p.Priority
        KernelModeTime    = $p.KernelModeTime
        UserModeTime      = $p.UserModeTime
        ReadTransferCount = $p.ReadTransferCount
        WriteTransferCount= $p.WriteTransferCount
        User              = if ($owner) { if ($owner.Domain) { ($owner.Domain + '\' + $owner.User) } else { $owner.User } } else { $null }
    }
}
$rows | ConvertTo-Json -Depth 3
`
}

// --- helpers ---

func sanitizeJSON(b []byte) []byte {
	// Drop leading BOM or lines that are not starting with '{'/'['
	s := string(b)
	var useful []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "{") || strings.HasPrefix(line, "[") {
			useful = append(useful, line)
		}
	}
	return []byte(strings.Join(useful, "\n"))
}

func toSliceOfMaps(v any) []map[string]any {
	switch t := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{t}
	default:
		return nil
	}
}

func getString(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		switch t := v.(type) {
		case string:
			return t
		case json.Number:
			return t.String()
		case float64:
			return strconv.FormatInt(int64(t), 10)
		}
	}
	return ""
}

func getInt64(m map[string]any, k string) int64 {
	if v, ok := m[k]; ok && v != nil {
		switch t := v.(type) {
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return i
			}
		case float64:
			return int64(t)
		case string:
			if i, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
				return i
			}
		}
	}
	return 0
}

func getUint64(m map[string]any, k string) uint64 {
	if v := getInt64(m, k); v > 0 {
		return uint64(v)
	}
	return 0
}

func intPtr(v int) *int       { return &v }
func int64Ptr(v int64) *int64 { return &v }

func utcRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// parseCIMDateTime parses DMTF CIM datetime, e.g. "20250101T120000.123456+060" or "20250101120000.123456+060"
func parseCIMDateTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// Accept both with or without 'T'. Strip non-digits except sign.
	s = strings.ReplaceAll(s, "T", "")
	// Expected: yyyymmddHHMMSS.mmmmmm±UUU
	if len(s) < 14 {
		return time.Time{}, false
	}
	y, _ := strconv.Atoi(s[0:4])
	mo, _ := strconv.Atoi(s[4:6])
	d, _ := strconv.Atoi(s[6:8])
	h, _ := strconv.Atoi(s[8:10])
	mi, _ := strconv.Atoi(s[10:12])
	se, _ := strconv.Atoi(s[12:14])
	rem := s[14:]
	usec := 0
	offsetMin := 0
	if strings.HasPrefix(rem, ".") {
		rem = rem[1:]
		// microseconds (up to 6)
		for i := 0; i < len(rem) && i < 6 && rem[i] >= '0' && rem[i] <= '9'; i++ {
			usec = usec*10 + int(rem[i]-'0')
		}
		// pad if fewer than 6 digits
		for l := len(strconv.Itoa(usec)); l < 6; l++ {
			usec *= 10
		}
		// trim consumed digits
		i := 0
		for i < len(rem) && rem[i] >= '0' && rem[i] <= '9' {
			i++
		}
		rem = rem[i:]
	}
	if len(rem) >= 4 && (rem[0] == '+' || rem[0] == '-') {
		sign := 1
		if rem[0] == '-' {
			sign = -1
		}
		if v, err := strconv.Atoi(rem[1:4]); err == nil {
			offsetMin = sign * v
		}
	}
	loc := time.FixedZone("", -offsetMin*60) // DMTF stores minutes offset from UTC; negate to get seconds east of UTC
	t := time.Date(y, time.Month(mo), d, h, mi, se, usec*1000, loc)
	return t.UTC(), true
}
