//go:build darwin

package ps

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func collectProcesses() ([]*Process, error) {
	columns := []string{
		"pid=", "ppid=", "uid=", "rgid=", "user=", "rgroup=",
		"state=", "tt=", "comm=", "time=",
		"rss=", "vsz=", "nice=", "pri=", "etime=", "command=",
	}
	spec := strings.Join(columns, ",")
	out, err := exec.Command("ps", "axo", spec).Output()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var procs []*Process

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		// We require at least the first 15 fixed columns (up to etime)
		if len(fields) < 15 {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		uid64, _ := strconv.ParseUint(fields[2], 10, 32)
		rgid64, _ := strconv.ParseUint(fields[3], 10, 32)
		user := fields[4]
		group := fields[5]
		state := fields[6]
		tty := fields[7]
		if tty == "??" || tty == "-" {
			tty = ""
		}
		comm := fields[8]

		cputimeSec := parseElapsedToSeconds(fields[9])

		rssKB, _ := strconv.ParseInt(fields[10], 10, 64)
		vszKB, _ := strconv.ParseInt(fields[11], 10, 64)

		nice, _ := strconv.Atoi(fields[12])
		priority, _ := strconv.Atoi(fields[13])

		elapsed := parseElapsedToSeconds(fields[14])
		start := now.Add(-time.Duration(elapsed) * time.Second)

		command := strings.Join(fields[15:], " ")

		p := &Process{
			PID:   pid,
			PPID:  ppid,
			UID:   uint32(uid64),
			GID:   uint32(rgid64),
			User:  user,
			Group: group,

			State:   firstStateRune(state),
			TTY:     tty,
			Comm:    comm,
			Command: command,

			CPUUserSeconds:   float64(cputimeSec), // Darwin ps exposes total CPU in `time`; we record it here
			CPUSystemSeconds: 0,
			MemRSSBytes:      rssKB * 1024,
			MemVMSBytes:      vszKB * 1024,

			Nice:     &nice,
			Priority: &priority,

			StartTime:       start.UTC().Format(time.RFC3339),
			StartTimeUnixNs: start.UnixNano(),
			ElapsedSeconds:  &elapsed,
		}

		procs = append(procs, p)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return procs, nil
}

// naiveShellSplit splits on spaces while keeping simple quoted segments together.
// It supports single and double quotes without escape sequences.
func naiveShellSplit(s string) []string {
	var (
		res   []string
		buf   strings.Builder
		quote rune
	)
	flush := func() {
		if buf.Len() > 0 {
			res = append(res, buf.String())
			buf.Reset()
		}
	}
	for _, r := range s {
		switch {
		case quote == 0 && (r == '\t' || r == ' '):
			flush()
		case quote == 0 && (r == '\'' || r == '"'):
			quote = r
		case quote != 0 && r == quote:
			quote = 0
		default:
			buf.WriteRune(r)
		}
	}
	flush()
	return res
}

// firstStateRune normalizes the Darwin state/STAT string to a single-letter code
// we use in our JSON (R|S|D|T|Z|I). Unknowns fall back to the first rune.
func firstStateRune(state string) string {
	state = strings.TrimSpace(state)
	if state == "" {
		return ""
	}
	s := state[:1]
	switch s {
	case "R", "S", "D", "T", "Z", "I":
		return s
	default:
		return s
	}
}

// parseElapsedToSeconds parses ps(1) etime/utime/stime formats on macOS:
//
//	MM:SS
//	HH:MM:SS
//	DD-HH:MM:SS
func parseElapsedToSeconds(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var days int64
	if i := strings.IndexByte(s, '-'); i >= 0 {
		d, err := strconv.ParseInt(s[:i], 10, 64)
		if err == nil {
			days = d
		}
		s = s[i+1:]
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0
	}
	var h, m, sec int64
	var err error
	if len(parts) == 3 {
		h, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			h = 0
		}
		m, _ = strconv.ParseInt(parts[1], 10, 64)
		sec, _ = strconv.ParseInt(parts[2], 10, 64)
	} else { // MM:SS
		m, _ = strconv.ParseInt(parts[0], 10, 64)
		sec, _ = strconv.ParseInt(parts[1], 10, 64)
	}
	return days*86400 + h*3600 + m*60 + sec
}
