//go:build !linux && !darwin

package ls

import (
	"os"
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
	return extraMeta{}
}
