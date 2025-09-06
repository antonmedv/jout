//go:build darwin

package ls

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

type extraMeta struct {
	Inode uint64
	Nlink uint64
	Uid   uint32
	Gid   uint32
	Owner string
	Group string
	Atime time.Time
	Ctime time.Time
}

func getExtra(info os.FileInfo) extraMeta {
	x := extraMeta{}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return x
	}
	x.Inode = uint64(st.Ino)
	x.Nlink = uint64(st.Nlink)
	x.Uid = st.Uid
	x.Gid = st.Gid
	// atime/ctime
	x.Atime = time.Unix(st.Atimespec.Sec, st.Atimespec.Nsec).UTC()
	x.Ctime = time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec).UTC()
	// owner name
	if u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10)); err == nil && u != nil {
		x.Owner = u.Username
	}
	// group name
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); err == nil && g != nil {
		x.Group = g.Name
	}
	return x
}
