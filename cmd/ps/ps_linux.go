//go:build linux

package ps

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// collectProcesses gathers processes using the Linux /proc filesystem.
func collectProcesses() ([]*Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	hz := clockTicks()
	btime, _ := bootTime()
	now := time.Now()

	procs := make([]*Process, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}

		p, err := readOneProcess(pid, hz, btime, now)
		if err != nil {
			// Permissions or short-lived processes—skip quietly
			continue
		}
		procs = append(procs, p)
	}
	return procs, nil
}

func readOneProcess(pid int, hz int64, btime int64, now time.Time) (*Process, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))

	st, err := readProcStat(base)
	if err != nil {
		return nil, err
	}

	status, _ := readStatusMap(filepath.Join(base, "status"))

	ppid := st.ppid
	uid := parseFirstUint(status["Uid"]) // real uid
	gid := parseFirstUint(status["Gid"]) // real gid

	uname := lookupUserName(uid)
	gname := lookupGroupName(gid)

	// Command & comm
	cmd := readCmdline(filepath.Join(base, "cmdline"))
	if cmd == "" {
		// Restricted or zombie; fall back to comm only
		cmd = ""
	}
	comm := st.comm

	// Paths
	exe := readLink(filepath.Join(base, "exe"))
	cwd := readLink(filepath.Join(base, "cwd"))

	// CPU
	cpuUser := float64(st.utime) / float64(hz)
	cpuSys := float64(st.stime) / float64(hz)

	// Memory
	memRSS := parseKB(status["VmRSS"]) * 1024
	memVMS := parseKB(status["VmSize"]) * 1024
	memSwap := parseKB(status["VmSwap"]) * 1024

	// Nice / priority / threads
	priority := int(st.priority)
	nice := int(st.nice)
	threads := int(st.numThreads)

	// Start time / elapsed
	var start time.Time
	if btime > 0 && hz > 0 {
		startSec := btime + int64(st.starttime)/hz
		start = time.Unix(startSec, 0)
	} else {
		start = now // best effort
	}
	elapsed := now.Sub(start).Seconds()
	elapsedI64 := int64(elapsed)

	// TTY
	tty := deriveTTY(base, st.ttyNr)
	if tty == "" {
		// keep as empty => serialized as empty string; caller may treat as null
	}

	// cgroups & container id
	cgPrimary, cgAll, containerID := readCgroups(filepath.Join(base, "cgroup"))

	// namespaces
	ns := readNamespaces(filepath.Join(base, "ns"))

	// IO stats
	ioStats := readIO(filepath.Join(base, "io"))

	// SELinux
	seLinux := readSELinuxLabel(filepath.Join(base, "attr", "current"))

	p := &Process{
		PID:   pid,
		PPID:  ppid,
		UID:   uint32(uid),
		GID:   uint32(gid),
		User:  uname,
		Group: gname,

		State:   normalizeState(st.state),
		TTY:     tty,
		Comm:    comm,
		Command: cmd,

		Exe: exe,
		Cwd: cwd,

		CPUUserSeconds:   cpuUser,
		CPUSystemSeconds: cpuSys,
		MemRSSBytes:      memRSS,
		MemVMSBytes:      memVMS,
		MemSwapBytes:     memSwap,

		Threads:  &threads,
		Nice:     &nice,
		Priority: &priority,

		StartTime:       start.UTC().Format(time.RFC3339),
		StartTimeUnixNs: start.UnixNano(),
		ElapsedSeconds:  &elapsedI64,

		Cgroup:       cgPrimary,
		Cgroups:      cgAll,
		NS:           ns,
		ContainerID:  containerID,
		IO:           ioStats,
		SELinuxLabel: seLinux,
	}

	return p, nil
}

// --- Helpers ---

type procStat struct {
	ppid       int
	state      string
	comm       string
	utime      uint64
	stime      uint64
	starttime  uint64
	priority   int64
	nice       int64
	numThreads int64
	ttyNr      int64
}

func readProcStat(base string) (*procStat, error) {
	b, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return nil, err
	}
	s := string(b)
	// comm is in parentheses and may contain spaces; find the last ')'
	l := strings.IndexByte(s, '(')
	r := strings.LastIndexByte(s, ')')
	if l < 0 || r < 0 || r <= l {
		return nil, errors.New("malformed /proc/[pid]/stat")
	}
	comm := s[l+1 : r]
	rest := strings.TrimSpace(s[r+1:])
	fields := strings.Fields(rest)
	if len(fields) < 20 { // we need at least up to nice/threads/starttime
		return nil, errors.New("short /proc/[pid]/stat")
	}
	// Field indexes relative to after ')':
	// 1 state, 2 ppid, 6 tty_nr, 13 utime, 14 stime, 17 priority, 18 nice, 19 num_threads, 21 starttime
	state := fields[0]
	ppid, _ := strconv.Atoi(fields[1])
	// tty_nr is field 6
	ttyNr, _ := strconv.ParseInt(fields[5], 10, 64)
	utime, _ := strconv.ParseUint(fields[13-1], 10, 64)
	stime, _ := strconv.ParseUint(fields[14-1], 10, 64)
	priority, _ := strconv.ParseInt(fields[17-1], 10, 64)
	nice, _ := strconv.ParseInt(fields[18-1], 10, 64)
	numThreads, _ := strconv.ParseInt(fields[19-1], 10, 64)
	starttime, _ := strconv.ParseUint(fields[21-1], 10, 64)

	return &procStat{
		ppid:       ppid,
		state:      state,
		comm:       comm,
		utime:      utime,
		stime:      stime,
		starttime:  starttime,
		priority:   priority,
		nice:       nice,
		numThreads: numThreads,
		ttyNr:      ttyNr,
	}, nil
}

func readStatusMap(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ':'); i >= 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			m[k] = v
		}
	}
	return m, sc.Err()
}

func parseFirstUint(v string) uint32 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	// e.g. "1000\t1000\t1000\t1000"
	if i := strings.IndexAny(v, "\t "); i >= 0 {
		v = v[:i]
	}
	u64, _ := strconv.ParseUint(v, 10, 32)
	return uint32(u64)
}

func parseKB(v string) int64 {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	// format: "   12345 kB"
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

func lookupUserName(uid uint32) string {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err == nil && u != nil {
		return u.Username
	}
	return strconv.Itoa(int(uid))
}

func lookupGroupName(gid uint32) string {
	g, err := user.LookupGroupId(strconv.Itoa(int(gid)))
	if err == nil {
		return g.Name
	}
	return strconv.Itoa(int(gid))
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	return strings.Join(parts, " ")
}

func readLink(path string) string {
	p, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return p
}

func normalizeState(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = s[:1]
	switch s {
	case "R", "S", "D", "T", "Z", "I":
		return s
	default:
		return s
	}
}

func deriveTTY(base string, ttyNr int64) string {
	// Best-effort: follow fd/0. If it's a terminal, it usually points to /dev/pts/N or /dev/ttyN
	if link := readLink(filepath.Join(base, "fd", "0")); link != "" {
		if strings.HasPrefix(link, "/dev/") {
			// Normalize like Darwin examples: "pts/0" or "tty1"
			return strings.TrimPrefix(link, "/dev/")
		}
	}
	_ = ttyNr // Not mapping major/minor to device names to avoid heavy /dev scan
	return ""
}

func readIO(path string) *ProcIO {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var r, w uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "read_bytes:") {
			fmt.Sscanf(line, "read_bytes: %d", &r)
		} else if strings.HasPrefix(line, "write_bytes:") {
			fmt.Sscanf(line, "write_bytes: %d", &w)
		}
	}
	return &ProcIO{ReadBytes: r, WriteBytes: w}
}

func readNamespaces(nsDir string) *ProcNamespaces {
	read := func(name string) string {
		if p := readLink(filepath.Join(nsDir, name)); p != "" {
			return p
		}
		return ""
	}
	mnt := read("mnt")
	pid := read("pid")
	net := read("net")
	uts := read("uts")
	ipc := read("ipc")
	usr := read("user")
	cg := read("cgroup")
	if mnt == "" && pid == "" && net == "" && uts == "" && ipc == "" && usr == "" && cg == "" {
		return nil
	}
	return &ProcNamespaces{Mnt: mnt, PID: pid, Net: net, UTS: uts, IPC: ipc, User: usr, Cgroup: cg}
}

var containerIDRe = regexp.MustCompile(`(?i)[a-f0-9]{12,64}`)

func readCgroups(path string) (*string, *[]string, *string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil
	}
	defer f.Close()

	var all []string
	var primary *string
	var cid *string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// formats:
		// v1: 5:cpuacct,cpu:/kubepods.slice/.../docker/abcdef...
		// v2: 0::/user.slice/..../<scope>
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 {
			path := parts[2]
			all = append(all, path)
			if primary == nil && path != "" {
				p := path
				primary = &p
			}
			if cid == nil {
				if id := extractContainerID(path); id != "" {
					cid = &id
				}
			}
		}
	}
	if len(all) == 0 {
		return nil, nil, cid
	}
	return primary, &all, cid
}

func extractContainerID(path string) string {
	// Look for longest hex-like token (common for docker/cri/containerd)
	best := ""
	for _, seg := range strings.Split(path, "/") {
		m := containerIDRe.FindString(seg)
		if m != "" {
			if len(m) > len(best) {
				best = m
			}
		}
	}
	return best
}

func readSELinuxLabel(path string) *string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v := strings.TrimSpace(string(b))
	if v == "" || v == "kernel" {
		return nil
	}
	return &v
}

func bootTime() (int64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				v, _ := strconv.ParseInt(parts[1], 10, 64)
				return v, nil
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, io.EOF
}

func clockTicks() int64 {
	v, err := unix.Sysconf(unix._SC_CLK_TCK)
	if err == nil && v > 0 {
		return v
	}
	// Fallback—common on Linux
	return 100
}
