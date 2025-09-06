package ls

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/antonmedv/jout/internal/out"
)

type Entry struct {
	// Identity
	Name  string `json:"name"`
	Path  string `json:"path"`
	Type  string `json:"type"`
	IsDir bool   `json:"is_dir"`

	// Symlink info
	LinkTarget string `json:"link_target,omitempty"`

	// Size and permissions
	Size      int64  `json:"size_bytes"`
	ModeStr   string `json:"mode_str"`
	ModeOctal string `json:"mode_octal_octal"`

	// Ownership and links
	Inode uint64 `json:"inode,omitempty"`
	Nlink uint64 `json:"nlink,omitempty"`
	Uid   uint32 `json:"uid,omitempty"`
	Gid   uint32 `json:"gid,omitempty"`
	Owner string `json:"owner,omitempty"`
	Group string `json:"group,omitempty"`

	// Timestamps
	Mtime string `json:"mtime"`
	Atime string `json:"atime,omitempty"`
	Ctime string `json:"ctime,omitempty"`
}

func makeEntry(name, fullPath string, info os.FileInfo) Entry {
	// Determine type
	t := "file"
	if info.Mode()&os.ModeSymlink != 0 {
		t = "symlink"
	} else if info.IsDir() {
		t = "dir"
	}

	var linkTarget string
	if t == "symlink" {
		if lt, err := os.Readlink(fullPath); err == nil {
			linkTarget = lt
		}
	}

	m := info.Mode()
	x := getExtra(info)
	var atimeStr, ctimeStr string
	if !x.Atime.IsZero() {
		atimeStr = x.Atime.Format(time.RFC3339)
	}
	if !x.Ctime.IsZero() {
		ctimeStr = x.Ctime.Format(time.RFC3339)
	}

	return Entry{
		Name:       name,
		Path:       fullPath,
		Type:       t,
		IsDir:      info.IsDir(),
		Size:       info.Size(),
		ModeStr:    permString(m),
		ModeOctal:  fmt.Sprintf("%04o", m.Perm()),
		Mtime:      info.ModTime().UTC().Format(time.RFC3339),
		Atime:      atimeStr,
		Ctime:      ctimeStr,
		Inode:      x.Inode,
		Nlink:      x.Nlink,
		Uid:        x.Uid,
		Gid:        x.Gid,
		Owner:      x.Owner,
		Group:      x.Group,
		LinkTarget: linkTarget,
	}
}

// followMode controls how symlinks are handled
// P: never follow; H: follow command-line argument only; L: follow everywhere
type followMode int

const (
	followP followMode = iota
	followH
	followL
)

// abs returns the absolute form of p, or p itself if resolution fails.
func abs(p string) string {
	if ap, err := filepath.Abs(p); err == nil {
		return ap
	}
	return p
}

// permString returns an ls-like permission string (e.g., "-rw-r--r--", "drwxr-xr-x").
// It includes file type, rwx bits, and suid/sgid/sticky handling.
func permString(m os.FileMode) string {
	// Type character
	typeCh := '-'
	if m&os.ModeDir != 0 {
		typeCh = 'd'
	} else if m&os.ModeSymlink != 0 {
		typeCh = 'l'
	} else if m&os.ModeNamedPipe != 0 {
		typeCh = 'p'
	} else if m&os.ModeSocket != 0 {
		typeCh = 's'
	} else if m&os.ModeDevice != 0 {
		if m&os.ModeCharDevice != 0 {
			typeCh = 'c'
		} else {
			typeCh = 'b'
		}
	}

	// Permission bits
	perm := m.Perm()
	chars := [9]byte{'-', '-', '-', '-', '-', '-', '-', '-', '-'}
	// User
	if perm&0400 != 0 {
		chars[0] = 'r'
	}
	if perm&0200 != 0 {
		chars[1] = 'w'
	}
	if perm&0100 != 0 {
		chars[2] = 'x'
	}
	// Group
	if perm&0040 != 0 {
		chars[3] = 'r'
	}
	if perm&0020 != 0 {
		chars[4] = 'w'
	}
	if perm&0010 != 0 {
		chars[5] = 'x'
	}
	// Other
	if perm&0004 != 0 {
		chars[6] = 'r'
	}
	if perm&0002 != 0 {
		chars[7] = 'w'
	}
	if perm&0001 != 0 {
		chars[8] = 'x'
	}

	// suid/sgid/sticky modifications
	if m&os.ModeSetuid != 0 {
		if chars[2] == 'x' {
			chars[2] = 's'
		} else {
			chars[2] = 'S'
		}
	}
	if m&os.ModeSetgid != 0 {
		if chars[5] == 'x' {
			chars[5] = 's'
		} else {
			chars[5] = 'S'
		}
	}
	if m&os.ModeSticky != 0 {
		if chars[8] == 'x' {
			chars[8] = 't'
		} else {
			chars[8] = 'T'
		}
	}

	return string(append([]byte{byte(typeCh)}, chars[:]...))
}

func Run(args []string) (int, error) {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var pFlag, lFlag, hFlag bool
	fs.BoolVar(&pFlag, "P", false, "If argument is a symbolic link, list the link itself (do not follow). Cancels -H and -L.")
	fs.BoolVar(&lFlag, "L", false, "Follow symlinks for all files.")
	fs.BoolVar(&hFlag, "H", false, "Follow symlink on command-line argument only.")

	if err := fs.Parse(args); err != nil {
		return 2, nil
	}

	mode := followP // default behavior is -P
	if pFlag {
		mode = followP
	} else if lFlag {
		mode = followL
	} else if hFlag {
		mode = followH
	}

	targets := fs.Args()
	if len(targets) == 0 {
		targets = []string{"."}
	}

	aggregated := make([]Entry, 0)
	exitCode := 0
	for _, t := range targets {
		items, err := listPath(t, mode)
		if err != nil {
			// Report via exit code but keep collecting from other targets
			exitCode = 1
			continue
		}
		aggregated = append(aggregated, items...)
	}

	out.JSON(aggregated)
	return exitCode, nil
}

func listPath(path string, mode followMode) ([]Entry, error) {
	// Determine info for target based on follow mode
	var info os.FileInfo
	var err error

	switch mode {
	case followL:
		info, err = os.Stat(path)
		if err != nil {
			// Fallback to Lstat so broken symlinks can still be listed
			info, err = os.Lstat(path)
		}
	case followH:
		info, err = os.Lstat(path)
		if err == nil && (info.Mode()&os.ModeSymlink) != 0 {
			if si, serr := os.Stat(path); serr == nil {
				info = si
			}
		}
	default: // followP
		info, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}

	// Non-directory target: return single Entry
	if !info.IsDir() {
		return []Entry{makeEntry(filepath.Base(path), abs(path), info)}, nil
	}

	// Directory case: list children of (possibly dereferenced) path.
	// Note: opening by original path is fine since symlink to dir is handled at info stage for H/L
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	de, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	items := make([]Entry, 0, len(de))
	for _, d := range de {
		joined := filepath.Join(path, d.Name())
		var fi os.FileInfo
		if mode == followL {
			fi, err = os.Stat(joined)
			if err != nil {
				// Fallback to Lstat to at least report symlink itself
				fi, err = os.Lstat(joined)
			}
		} else {
			fi, err = os.Lstat(joined)
		}
		if err != nil {
			// Skip entries we cannot stat, collect partial results like ls
			continue
		}
		items = append(items, makeEntry(d.Name(), abs(joined), fi))
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	return items, nil
}
