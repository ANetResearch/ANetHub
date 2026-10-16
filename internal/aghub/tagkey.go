package aghub

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/ANetResearch/ANetCore/evidence"

	"github.com/ANetResearch/ANetHub/internal/hubid"
)

// The review tag key, hub_tag_key (hub-payment-privacy §3.3; core L31).
//
// A review this hub stores is attested with a tag, HMAC(hub_tag_key,
// reviewer ‖ subject) cut to 16 bytes, in place of the reviewer: one
// reviewer gets one tag per subject, so a reader counts distinct reviewers
// without learning who they are, and without the key cannot match tags across
// subjects. The key is 32 random bytes in <data>/keys/review_tag.key (0600,
// directory 0700), never in hub.db and never in a backup (core §2.16);
// hub_meta.tag_key_id names it. A new key starts the reviewer counts over, so
// each key has its own id and the counts are kept per (tag_key_id, tag).
//
// A new key is made when the file is missing (a new hub, or a data directory
// whose key was lost) and by an emergency rotation of the hub's identity (KEL
// H-33): whoever may hold the identity key may hold this file too, and could
// then tell from a tag whether a given AID wrote a review.
//
// The new id is committed before the key is written. A start that stops in
// between finds no key and makes another under the next id: an id can be
// skipped, but no two keys ever share one, so tags of different keys are
// never counted as one reviewer's.

const (
	keysDir      = "keys"
	tagKeyFile   = "review_tag.key"
	tagKeyIDMeta = "tag_key_id"
)

// ReviewTagKeyName is the name the key is listed under among the secrets a
// hub emergency rotation regenerates (hubid.EmergencySecrets).
const ReviewTagKeyName = "hub_tag_key"

func init() {
	hubid.RegisterEmergencySecret(hubid.EmergencySecret{Name: ReviewTagKeyName, Regenerate: RegenerateReviewTagKey})
}

// ErrTagKeyFile is a review tag key file that holds something other than a
// key. The hub does not start on it: making a new key would start every
// reviewer count over, which is the operator's call, not a start's.
var ErrTagKeyFile = errors.New("hub: the review tag key file is not a key")

// tagKeyState is the key as this process loaded it.
type tagKeyState struct {
	mu  sync.Mutex
	key []byte
	id  uint64
}

// TagKeyPath is where the review tag key of the data directory dir is kept.
func TagKeyPath(dir string) string { return filepath.Join(dir, keysDir, tagKeyFile) }

// LoadReviewTagKey loads the review tag key, making one when the data
// directory has none, and returns its id. anet-hub calls it before it serves,
// so a key file it cannot use stops the start rather than the first review;
// without that call the key is loaded at the first review.
func (s *Store) LoadReviewTagKey() (uint64, error) {
	_, id, err := s.reviewTagKey()
	return id, err
}

// reviewTagKey is the key and its id.
func (s *Store) reviewTagKey() ([]byte, uint64, error) {
	s.tagKey.mu.Lock()
	defer s.tagKey.mu.Unlock()
	if s.tagKey.key == nil {
		key, id, err := s.loadTagKey()
		if err != nil {
			return nil, 0, err
		}
		s.tagKey.key, s.tagKey.id = key, id
	}
	return s.tagKey.key, s.tagKey.id, nil
}

// loadTagKey reads the key file, or makes a key when there is none.
func (s *Store) loadTagKey() ([]byte, uint64, error) {
	if s.dir == "" {
		return nil, 0, errors.New("hub: the store has no data directory for its review tag key")
	}
	path := TagKeyPath(s.dir)
	key, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s.newTagKey()
	case err != nil:
		return nil, 0, fmt.Errorf("hub: read the review tag key: %w", err)
	case len(key) != evidence.TagKeySize:
		return nil, 0, fmt.Errorf("%w: %s holds %d bytes, not %d; remove it and start the hub to make a new one (reviewer counts then start over)",
			ErrTagKeyFile, path, len(key), evidence.TagKeySize)
	}
	id, err := tagKeyIDOf(s.db)
	if err != nil {
		return nil, 0, err
	}
	if id == 0 {
		// A key and a database that never had one: the database was made
		// anew beside an existing keys directory. It holds no tag yet, so
		// the key becomes its first.
		if id, err = s.bumpTagKeyID(); err != nil {
			return nil, 0, err
		}
	}
	return key, id, nil
}

// newTagKey makes a key under the next id: the id is committed first, then
// the file is written (see the file comment).
func (s *Store) newTagKey() ([]byte, uint64, error) {
	key := make([]byte, evidence.TagKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, 0, err
	}
	id, err := s.bumpTagKeyID()
	if err != nil {
		return nil, 0, err
	}
	if err := writeSecretFile(TagKeyPath(s.dir), key); err != nil {
		return nil, 0, fmt.Errorf("hub: write the review tag key: %w", err)
	}
	if id == 1 {
		log.Printf("hub: made the review tag key (tag_key_id 1)")
	} else {
		log.Printf("hub: new review tag key (tag_key_id %d); reviewer counts start over from here", id)
	}
	return key, id, nil
}

// tagKeyIDOf reads hub_meta.tag_key_id: 0 when there is none.
func tagKeyIDOf(q rowQuerier) (uint64, error) {
	var v string
	err := q.QueryRow(`SELECT value FROM hub_meta WHERE key=?`, tagKeyIDMeta).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("hub: read tag_key_id: %w", err)
	}
	id, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("hub: tag_key_id %q is not a number", v)
	}
	return id, nil
}

// bumpTagKeyID adds 1 to hub_meta.tag_key_id and returns the new value.
func (s *Store) bumpTagKeyID() (uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	id, err := tagKeyIDOf(tx)
	if err != nil {
		return 0, err
	}
	id++
	if _, err := tx.Exec(`INSERT INTO hub_meta(key, value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, tagKeyIDMeta, strconv.FormatUint(id, 10)); err != nil {
		return 0, fmt.Errorf("hub: write tag_key_id: %w", err)
	}
	return id, tx.Commit()
}

// RegenerateReviewTagKey replaces the review tag key of the hub whose data
// directory is dir with a new one under the next id: the emergency rotation's
// step for hub_tag_key (KEL H-33). It runs while the hub is stopped. The old
// key is overwritten and removed before the new id is taken, so a run cut
// short leaves no key behind and the next start makes one.
func RegenerateReviewTagKey(dir string) error {
	s, err := Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.regenerateTagKey()
	return err
}

// regenerateTagKey drops the current key and makes a new one.
func (s *Store) regenerateTagKey() (uint64, error) {
	s.tagKey.mu.Lock()
	defer s.tagKey.mu.Unlock()
	s.tagKey.key, s.tagKey.id = nil, 0
	if err := removeSecretFile(TagKeyPath(s.dir)); err != nil {
		return 0, fmt.Errorf("hub: remove the review tag key: %w", err)
	}
	key, id, err := s.newTagKey()
	if err != nil {
		return 0, err
	}
	s.tagKey.key, s.tagKey.id = key, id
	return id, nil
}

// writeSecretFile writes b to path, readable by this account only, and
// durably: a temporary file in the same directory (0700) is written, synced
// and renamed over path, and the directory is synced.
func writeSecretFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // after the rename there is nothing to remove
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// removeSecretFile overwrites the file at path with zeros, removes it and
// syncs its directory. A file that is not there is not an error.
func removeSecretFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil {
		_, err = f.WriteAt(make([]byte, st.Size()), 0)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir makes a rename or a removal in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
