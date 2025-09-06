package ps

import (
	"flag"
	"os"

	"github.com/antonmedv/jout/internal/out"
)

type Process struct {
	// Identity
	PID   int    `json:"pid"`
	PPID  int    `json:"ppid"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	User  string `json:"user"`
	Group string `json:"group"`

	// State / terminal
	State   string `json:"state"`   // R|S|D|T|Z|I (running,sleeping,io wait,stopped,zombie,idle)
	TTY     string `json:"tty"`     // "pts/0", "tty1"; null if none (kept without omitempty to emit null)
	Comm    string `json:"comm"`    // short name, e.g. "sshd"
	Command string `json:"command"` // argv vector; may be empty if restricted

	// Paths
	Exe string `json:"exe,omitempty"` // resolved binary path
	Cwd string `json:"cwd,omitempty"` // working directory

	// CPU & memory (cumulative since start)
	CPUUserSeconds   float64 `json:"cpu_user_seconds"`
	CPUSystemSeconds float64 `json:"cpu_system_seconds"`
	MemRSSBytes      int64   `json:"mem_rss_bytes"`
	MemVMSBytes      int64   `json:"mem_vms_bytes"`
	MemSwapBytes     int64   `json:"mem_swap_bytes,omitempty"` // if available

	Threads  *int `json:"threads,omitempty"`
	Nice     *int `json:"nice,omitempty"`
	Priority *int `json:"priority,omitempty"`

	// Start/elapsed
	StartTime       string `json:"start_time"`         // RFC3339 UTC
	StartTimeUnixNs int64  `json:"start_time_unix_ns"` // monotonic-friendly
	ElapsedSeconds  *int64 `json:"elapsed_seconds,omitempty"`

	// Containers / cgroups / namespaces (Linux)
	Cgroup      *string         `json:"cgroup,omitempty"`  // primary/legacy cgroup path
	Cgroups     *[]string       `json:"cgroups,omitempty"` // all cgroup paths (v1/v2)
	NS          *ProcNamespaces `json:"namespaces,omitempty"`
	ContainerID *string         `json:"container_id,omitempty"` // docker/cri

	// I/O stats (Linux)
	IO *ProcIO `json:"io,omitempty"`

	// Security labels (Linux, optional)
	SELinuxLabel *string `json:"selinux_label,omitempty"`
}

type ProcIO struct {
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
}

type ProcNamespaces struct {
	Mnt    string `json:"mnt,omitempty"`
	PID    string `json:"pid,omitempty"`
	Net    string `json:"net,omitempty"`
	UTS    string `json:"uts,omitempty"`
	IPC    string `json:"ipc,omitempty"`
	User   string `json:"user,omitempty"`
	Cgroup string `json:"cgroup,omitempty"`
}

func Run(args []string) (int, error) {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var userFilter string
	fs.StringVar(&userFilter, "user", "", "Filter processes by user name")

	if err := fs.Parse(args); err != nil {
		return 2, nil
	}

	procs, err := collectProcesses()
	if err != nil {
		return 1, err
	}

	if userFilter != "" {
		filtered := make([]*Process, 0, len(procs))
		for _, p := range procs {
			if p != nil && p.User == userFilter {
				filtered = append(filtered, p)
			}
		}
		procs = filtered
	}

	out.JSON(procs)
	return 0, nil
}
