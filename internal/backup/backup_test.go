package backup

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HeresJohnny320/iptable-ui/internal/store"
)

type clock struct{ now time.Time }

func (c *clock) tick() time.Time {
	c.now = c.now.Add(time.Second)
	return c.now
}

func newManager(t *testing.T) (*Manager, *store.Store, *int) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	applied := 0
	c := &clock{now: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)}
	manager := &Manager{Store: database, Dir: filepath.Join(t.TempDir(), "backups"), Now: c.tick,
		Apply: func(ctx context.Context, rules []store.Rule, settings map[string]string) error {
			applied++
			return database.ReplaceAll(ctx, rules, settings)
		}}
	return manager, database, &applied
}

func TestAutoBackupSkipsWhenNothingChanged(t *testing.T) {
	manager, database, _ := newManager(t)
	ctx := context.Background()
	if _, created, err := manager.Create(ctx, Startup); err != nil || !created {
		t.Fatalf("startup backup: %v %v", created, err)
	}
	if _, created, _ := manager.Create(ctx, Auto); created {
		t.Fatal("nothing changed, so the 5-minute backup should be skipped")
	}
	if _, err := database.Add(ctx, store.Rule{PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	info, created, err := manager.Create(ctx, Auto)
	if err != nil || !created || info.Rules != 1 || info.Kind != Auto {
		t.Fatalf("a change should be backed up: %+v %v %v", info, created, err)
	}
	if _, created, _ := manager.Create(ctx, Manual); !created {
		t.Fatal("manual backups are always taken")
	}
	backups, err := manager.List()
	if err != nil || len(backups) != 3 || backups[0].Kind != Manual || backups[2].Kind != Startup {
		t.Fatalf("expected 3 backups, newest first: %+v %v", backups, err)
	}
	stat, _ := os.Stat(filepath.Join(manager.Dir, backups[0].Name))
	if stat.Mode().Perm() != 0600 {
		t.Fatalf("backups must be private, got %v", stat.Mode().Perm())
	}
}

func TestRestoreReplacesEverythingAndCanBeUndone(t *testing.T) {
	manager, database, applied := newManager(t)
	ctx := context.Background()
	if _, err := database.Add(ctx, store.Rule{Name: "old", PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	_ = database.SetSetting(ctx, "theme", "ocean")
	saved, _, err := manager.Create(ctx, Manual)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Add(ctx, store.Rule{Name: "new", PublicPort: 443, DestIP: "10.0.0.3", DestPort: 443, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	_ = database.SetSetting(ctx, "theme", "midnight")

	if err := manager.Restore(ctx, saved.Name); err != nil {
		t.Fatal(err)
	}
	rules, _ := database.List(ctx)
	theme, _ := database.Setting(ctx, "theme")
	if *applied != 1 || len(rules) != 1 || rules[0].Name != "old" || theme != "ocean" {
		t.Fatalf("restore should bring back the saved rules and theme: %+v theme=%q applied=%d", rules, theme, *applied)
	}
	backups, _ := manager.List()
	var undo Info
	for _, info := range backups {
		if info.Kind == PreRestore {
			undo = info
		}
	}
	if undo.Name == "" || undo.Rules != 2 {
		t.Fatalf("restoring should first back up the state it replaces: %+v", backups)
	}
	if _, created, _ := manager.Create(ctx, Auto); created {
		t.Fatal("right after a restore nothing changed, so no auto backup is needed")
	}
	if err := manager.Restore(ctx, undo.Name); err != nil {
		t.Fatal(err)
	}
	if rules, _ := database.List(ctx); len(rules) != 2 {
		t.Fatalf("restoring the pre-restore backup should undo the restore, got %d rules", len(rules))
	}
}

func TestRestoreRejectsNamesOutsideTheBackupFolder(t *testing.T) {
	manager, _, applied := newManager(t)
	for _, name := range []string{"../rules.db", "/etc/passwd", "rules-x.db", "rules-20261003T010000.000Z-manual-1.db/../../x"} {
		if err := manager.Restore(context.Background(), name); err == nil {
			t.Errorf("%q should be rejected", name)
		}
	}
	if err := manager.Restore(context.Background(), "rules-20261003T010000.000Z-manual-1.db"); err == nil || !strings.Contains(err.Error(), "open backup") {
		t.Fatalf("a missing backup should fail cleanly, got %v", err)
	}
	if *applied != 0 {
		t.Fatal("nothing may be applied for a rejected restore")
	}
}

func TestPruneKeepsManualBackups(t *testing.T) {
	manager, _, _ := newManager(t)
	if err := os.MkdirAll(manager.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for index := 0; index < KeepAutomatic+5; index++ {
		name := fmt.Sprintf("rules-%s-auto-0.db", start.Add(time.Duration(index)*time.Minute).Format(timeFormat))
		_ = os.WriteFile(filepath.Join(manager.Dir, name), nil, 0600)
	}
	manual := fmt.Sprintf("rules-%s-manual-0.db", start.Add(-time.Hour).Format(timeFormat))
	_ = os.WriteFile(filepath.Join(manager.Dir, manual), nil, 0600)
	if _, _, err := manager.Create(context.Background(), Startup); err != nil {
		t.Fatal(err)
	}
	backups, _ := manager.List()
	automatic := 0
	for _, info := range backups {
		if info.Kind == Auto || info.Kind == Startup {
			automatic++
		}
	}
	if automatic != KeepAutomatic {
		t.Fatalf("kept %d automatic backups, want %d", automatic, KeepAutomatic)
	}
	if _, err := os.Stat(filepath.Join(manager.Dir, manual)); err != nil {
		t.Fatal("the oldest manual backup must never be pruned")
	}
}

func TestPathOnlyReturnsBackups(t *testing.T) {
	manager, _, _ := newManager(t)
	info, _, err := manager.Create(context.Background(), PreClear)
	if err != nil || info.Kind != PreClear {
		t.Fatalf("pre-clear backup: %+v %v", info, err)
	}
	path, err := manager.Path(info.Name)
	if err != nil || path != filepath.Join(manager.Dir, info.Name) {
		t.Fatalf("Path(%q) = %q, %v", info.Name, path, err)
	}
	for _, name := range []string{"../rules.db", "rules-20261003T010000.000Z-manual-1.db", ""} {
		if _, err := manager.Path(name); err == nil {
			t.Errorf("%q should not resolve", name)
		}
	}
	if backups, _ := manager.List(); len(backups) != 1 || backups[0].Kind != PreClear {
		t.Fatalf("pre-clear backups should be listed: %+v", backups)
	}
}

func TestImportAcceptsOnlyValidBackups(t *testing.T) {
	manager, database, _ := newManager(t)
	ctx := context.Background()
	if _, err := database.Add(ctx, store.Rule{PublicPort: 80, DestIP: "10.0.0.2", DestPort: 80, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(t.TempDir(), "exported.db")
	if err := database.Backup(ctx, exported); err != nil {
		t.Fatal(err)
	}
	file, _ := os.Open(exported)
	info, err := manager.Import(file)
	file.Close()
	if err != nil || info.Kind != Uploaded || info.Rules != 1 {
		t.Fatalf("import: %+v %v", info, err)
	}
	if err := manager.Restore(ctx, info.Name); err != nil {
		t.Fatalf("an imported backup should restore: %v", err)
	}
	for name, content := range map[string]string{
		"text":  "hello, this is not a database",
		"empty": "",
	} {
		if _, err := manager.Import(strings.NewReader(content)); err == nil || !strings.Contains(err.Error(), "not an iptable-ui database") {
			t.Errorf("%s should be refused, got %v", name, err)
		}
	}
	other := filepath.Join(t.TempDir(), "other.db")
	otherDB, _ := sql.Open("sqlite", other)
	otherDB.Exec(`CREATE TABLE photos (id INTEGER)`)
	otherDB.Close()
	file, _ = os.Open(other)
	_, err = manager.Import(file)
	file.Close()
	if err == nil || !strings.Contains(err.Error(), "not an iptable-ui database") {
		t.Fatalf("an unrelated SQLite database must be refused (restoring it would remove every rule), got %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(manager.Dir, ".import-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestMoveToCarriesBackupsAlong(t *testing.T) {
	manager, _, _ := newManager(t)
	ctx := context.Background()
	first, _, _ := manager.Create(ctx, Manual)
	unrelated := filepath.Join(manager.Dir, "notes.txt")
	_ = os.WriteFile(unrelated, []byte("keep"), 0600)
	target := filepath.Join(t.TempDir(), "elsewhere", "iptable-ui-backups")
	if err := manager.MoveTo(target); err != nil {
		t.Fatal(err)
	}
	if manager.Folder() != target {
		t.Fatalf("folder is %q", manager.Folder())
	}
	backups, _ := manager.List()
	if len(backups) != 1 || backups[0].Name != first.Name {
		t.Fatalf("the backup should move along: %+v", backups)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("files that are not backups must be left where they are")
	}
	if err := manager.MoveTo("relative/path"); err == nil {
		t.Fatal("a relative folder must be refused")
	}
}
