// Package backup keeps snapshots of the rule database: one at startup, one
// every few minutes while something changed, and any made by hand. Restoring
// one replaces every rule and setting and re-applies the firewall.
package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

// Kinds of backup.
const (
	Startup    = "startup"
	Auto       = "auto"
	Manual     = "manual"
	PreRestore = "pre-restore" // taken just before a restore, so it can be undone
	PreClear   = "pre-clear"   // taken just before every rule is removed
	Uploaded   = "uploaded"    // a database file added by the user
)

// FolderSetting is the setting that remembers the backup folder.
const FolderSetting = "backup.dir"

// MaxImportSize bounds an uploaded or imported backup.
const MaxImportSize = 64 << 20

const (
	Interval = 5 * time.Minute
	// Automatic (startup and auto) and safety (pre-restore, pre-clear)
	// backups are pruned to these counts; manual backups are kept until
	// deleted by hand.
	KeepAutomatic  = 100
	KeepPreRestore = 20
	timeFormat     = "20060102T150405.000Z"
)

var namePattern = regexp.MustCompile(`^rules-(\d{8}T\d{6}\.\d{3}Z)-(startup|auto|manual|pre-restore|pre-clear|uploaded)-(\d+)\.db$`)

// Store is the live database being backed up.
type Store interface {
	Backup(ctx context.Context, path string) error
	List(ctx context.Context) ([]store.Rule, error)
	Settings(ctx context.Context) (map[string]string, error)
}

// Info describes one backup file.
type Info struct {
	Name  string    `json:"name"`
	Kind  string    `json:"kind"`
	Time  time.Time `json:"time"`
	Rules int       `json:"rules"`
	Size  int64     `json:"size"`
}

type Manager struct {
	Store Store
	Dir   string
	// Apply replaces every rule and setting and applies them to the firewall.
	Apply func(ctx context.Context, rules []store.Rule, settings map[string]string) error
	Now   func() time.Time
	// SaveFolder remembers the folder after MoveTo, so it is used next time.
	SaveFolder func(string) error

	mu       sync.Mutex
	lastHash string
}

// Folder is the folder backups are saved in.
func (m *Manager) Folder() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.Dir
}

// Create writes a backup. An Auto backup is skipped (created is false) when
// nothing changed since the previous backup.
func (m *Manager) Create(ctx context.Context, kind string) (info Info, created bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.create(ctx, kind)
}

func (m *Manager) create(ctx context.Context, kind string) (Info, bool, error) {
	rules, settings, err := m.state(ctx)
	if err != nil {
		return Info{}, false, err
	}
	hash := fingerprint(rules, settings)
	if kind == Auto && hash == m.lastHash {
		return Info{}, false, nil
	}
	if err := m.ensureDir(); err != nil {
		return Info{}, false, err
	}
	when := m.now().UTC()
	name := fmt.Sprintf("rules-%s-%s-%d.db", when.Format(timeFormat), kind, len(rules))
	path := filepath.Join(m.Dir, name)
	if err := m.Store.Backup(ctx, path); err != nil {
		return Info{}, false, err
	}
	if err := m.protect(path); err != nil {
		return Info{}, false, err
	}
	m.lastHash = hash
	m.prune()
	stat, _ := os.Stat(path)
	size := int64(0)
	if stat != nil {
		size = stat.Size()
	}
	return Info{Name: name, Kind: kind, Time: when, Rules: len(rules), Size: size}, true, nil
}

// List returns the backups, newest first.
func (m *Manager) List() ([]Info, error) {
	return listIn(m.Folder())
}

func listIn(dir string) ([]Info, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Info{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list backups: %w", err)
	}
	backups := make([]Info, 0, len(entries))
	for _, entry := range entries {
		match := namePattern.FindStringSubmatch(entry.Name())
		if match == nil || !entry.Type().IsRegular() {
			continue
		}
		when, err := time.Parse(timeFormat, match[1])
		if err != nil {
			continue
		}
		count, _ := strconv.Atoi(match[3])
		info := Info{Name: entry.Name(), Kind: match[2], Time: when, Rules: count}
		if stat, err := entry.Info(); err == nil {
			info.Size = stat.Size()
		}
		backups = append(backups, info)
	}
	sort.Slice(backups, func(a, b int) bool {
		if !backups[a].Time.Equal(backups[b].Time) {
			return backups[a].Time.After(backups[b].Time)
		}
		return backups[a].Name > backups[b].Name
	})
	return backups, nil
}

// Restore makes the named backup the live state: it first backs up the
// current state (kind PreRestore), then replaces every rule and setting and
// re-applies the firewall.
func (m *Manager) Restore(ctx context.Context, name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%q is not a backup name", name)
	}
	if m.Apply == nil {
		return errors.New("restore is not configured")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, settings, err := readBackup(filepath.Join(m.Dir, name))
	if err != nil {
		return err
	}
	if _, _, err := m.create(ctx, PreRestore); err != nil {
		return fmt.Errorf("back up the current state before restoring: %w", err)
	}
	if err := m.Apply(ctx, rules, settings); err != nil {
		return fmt.Errorf("restore %s: %w", name, err)
	}
	m.lastHash = fingerprint(rules, settings)
	return nil
}

// Path returns the file of a named backup, refusing anything that is not a
// backup in this manager's folder.
func (m *Manager) Path(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("%q is not a backup name", name)
	}
	path := filepath.Join(m.Folder(), name)
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() {
		return "", fmt.Errorf("backup %s not found", name)
	}
	return path, nil
}

// Import validates a database file and adds it to the backups as kind
// Uploaded, ready to restore. Anything that is not an iptable-ui database
// with valid rules is refused.
func (m *Manager) Import(source io.Reader) (Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureDir(); err != nil {
		return Info{}, err
	}
	temporary, err := os.CreateTemp(m.Dir, ".import-*.db")
	if err != nil {
		return Info{}, fmt.Errorf("receive backup: %w", err)
	}
	defer os.Remove(temporary.Name())
	written, err := io.Copy(temporary, io.LimitReader(source, MaxImportSize+1))
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Info{}, fmt.Errorf("receive backup: %w", err)
	}
	if written > MaxImportSize {
		return Info{}, fmt.Errorf("backup is larger than %d MB", MaxImportSize>>20)
	}
	header := make([]byte, 16)
	if file, err := os.Open(temporary.Name()); err == nil {
		_, _ = io.ReadFull(file, header)
		file.Close()
	}
	if string(header) != "SQLite format 3\x00" || !hasRulesTable(temporary.Name()) {
		return Info{}, errors.New("that file is not an iptable-ui database backup")
	}
	rules, _, err := readBackup(temporary.Name())
	if err != nil {
		return Info{}, fmt.Errorf("that file is not an iptable-ui database backup: %w", err)
	}
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return Info{}, fmt.Errorf("rule %d in the backup is invalid: %w", rule.ID, err)
		}
	}
	when := m.now().UTC()
	name := fmt.Sprintf("rules-%s-%s-%d.db", when.Format(timeFormat), Uploaded, len(rules))
	path := filepath.Join(m.Dir, name)
	if err := os.Rename(temporary.Name(), path); err != nil {
		return Info{}, fmt.Errorf("save backup: %w", err)
	}
	if err := m.protect(path); err != nil {
		return Info{}, err
	}
	return Info{Name: name, Kind: Uploaded, Time: when, Rules: len(rules), Size: written}, nil
}

// MoveTo makes dir the backup folder, moving the existing backups into it.
func (m *Manager) MoveTo(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("the backup folder must be an absolute path, such as /home/ubuntu/iptable-ui-backups")
	}
	dir = filepath.Clean(dir)
	m.mu.Lock()
	defer m.mu.Unlock()
	if dir == filepath.Clean(m.Dir) {
		return nil
	}
	old := m.Dir
	m.Dir = dir
	if err := m.ensureDir(); err != nil {
		m.Dir = old
		return err
	}
	entries, err := os.ReadDir(old)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read old backup folder: %w", err)
	}
	for _, entry := range entries {
		if !namePattern.MatchString(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}
		target := filepath.Join(dir, entry.Name())
		if err := moveFile(filepath.Join(old, entry.Name()), target); err != nil {
			return fmt.Errorf("move %s: %w", entry.Name(), err)
		}
		if err := m.protect(target); err != nil {
			return err
		}
	}
	_ = os.Remove(old) // only succeeds when nothing else is left in it
	if m.SaveFolder != nil {
		if err := m.SaveFolder(dir); err != nil {
			return fmt.Errorf("backups moved to %s, but the folder could not be saved for next time: %w", dir, err)
		}
	}
	return nil
}

// ensureDir creates the backup folder, owned like its parent folder: a
// folder in a user's home belongs to that user, so they can download
// backups over SFTP without root.
func (m *Manager) ensureDir() error {
	if err := os.MkdirAll(m.Dir, 0700); err != nil {
		return fmt.Errorf("create backup folder: %w", err)
	}
	if uid, gid, ok := m.owner(); ok {
		if err := os.Chown(m.Dir, uid, gid); err != nil {
			return fmt.Errorf("give the backup folder to its owner: %w", err)
		}
	}
	return nil
}

// protect makes a backup readable only by the folder's owner.
func (m *Manager) protect(path string) error {
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("protect backup: %w", err)
	}
	if uid, gid, ok := m.owner(); ok {
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("give the backup to its owner: %w", err)
		}
	}
	return nil
}

// hasRulesTable checks that a SQLite file is an iptable-ui database before
// anything adds tables to it, so an unrelated database is never mistaken
// for an empty backup (restoring that would remove every rule).
func hasRulesTable(path string) bool {
	database, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return false
	}
	defer database.Close()
	var name string
	err = database.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'rules'`).Scan(&name)
	return err == nil
}

func moveFile(source, target string) error {
	if err := os.Rename(source, target); err == nil {
		return nil
	}
	// Different filesystems: copy, then remove the original.
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(target)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(source)
}

// Run takes an Auto backup every Interval until ctx is done.
func (m *Manager) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, _, err := m.Create(ctx, Auto); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (m *Manager) state(ctx context.Context) ([]store.Rule, map[string]string, error) {
	rules, err := m.Store.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	settings, err := m.Store.Settings(ctx)
	if err != nil {
		return nil, nil, err
	}
	return rules, settings, nil
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// prune deletes the oldest automatic and pre-restore backups beyond their limits.
func (m *Manager) prune() {
	backups, err := listIn(m.Dir)
	if err != nil {
		return
	}
	automatic, preRestore := 0, 0
	for _, info := range backups { // newest first
		remove := false
		switch info.Kind {
		case Startup, Auto:
			automatic++
			remove = automatic > KeepAutomatic
		case PreRestore, PreClear:
			preRestore++
			remove = preRestore > KeepPreRestore
		}
		if remove {
			_ = os.Remove(filepath.Join(m.Dir, info.Name))
		}
	}
}

// readBackup loads a backup through a temporary copy, so upgrading an old
// backup's schema never modifies the backup file itself.
func readBackup(path string) ([]store.Rule, map[string]string, error) {
	source, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open backup: %w", err)
	}
	defer source.Close()
	copyFile, err := os.CreateTemp("", "iptable-ui-restore-*.db")
	if err != nil {
		return nil, nil, fmt.Errorf("prepare restore: %w", err)
	}
	defer os.Remove(copyFile.Name())
	if _, err := io.Copy(copyFile, source); err != nil {
		copyFile.Close()
		return nil, nil, fmt.Errorf("read backup: %w", err)
	}
	if err := copyFile.Close(); err != nil {
		return nil, nil, err
	}
	database, err := store.Open(copyFile.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("read backup: %w", err)
	}
	defer database.Close()
	rules, err := database.List(context.Background())
	if err != nil {
		return nil, nil, err
	}
	settings, err := database.Settings(context.Background())
	if err != nil {
		return nil, nil, err
	}
	return rules, settings, nil
}

func fingerprint(rules []store.Rule, settings map[string]string) string {
	encoded, _ := json.Marshal(struct {
		Rules    []store.Rule
		Settings map[string]string
	}{rules, settings})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
