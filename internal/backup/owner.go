package backup

import (
	"os"
	"path/filepath"
	"syscall"
)

// owner returns who should own the backups: the owner of the backup
// folder's parent, unless that is root (then files stay root-only).
func (m *Manager) owner() (uid, gid int, ok bool) {
	info, err := os.Stat(filepath.Dir(m.Dir))
	if err != nil {
		return 0, 0, false
	}
	stat, isUnix := info.Sys().(*syscall.Stat_t)
	if !isUnix || stat.Uid == 0 || os.Geteuid() != 0 {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
