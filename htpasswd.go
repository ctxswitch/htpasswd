package htpasswd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// A File reads htpasswd files and provides authentication
//
// As returned by Open, a File reads in an htpasswd file searching for
// bcrypt hashed passwords that conform to the published formats:
// https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
// CheckInterval can be customized before the first call to AutoReload
// to specify the wait interval between reload checks.  If CheckInterval
// is not set, AutoReload will not be run.
type File struct {
	// CheckInterval is the number of seconds between checks.
	// If automatic reloading is enabled, this value is used as the wait time
	// between checks.  If disabled, this value has no effect.
	CheckInterval int64
	// lastModified is the modification timestamp of the htpasswd file.
	// It's default value is '1970-01-01 00:00:00 +0000 UTC' or 0 seconds
	// from epoch, but is set to the modification timestamp after the file
	// is parsed for the first time.
	lastModified time.Time
	// lastSize is the last size of the htpasswd file
	lastSize int64
	// mutex provides locks for reading and updating the users map.
	mutex sync.Mutex
	// Path is the location of the htpasswd formatted file.
	// It is set to the default value of '.htpasswd' in the current working
	// directory.
	path string
	// users is a map of usernames to hashes
	users map[string]string
}

var (
	// Regexp for the 2a, 2b, or 2y bcrypt specifications.
	bexp = regexp.MustCompile("^[a-zA-Z]+[a-zA-Z0-9_-]*:\\$2[aby]\\$[0-9]{2}\\$[A-Za-z0-9./]{53}$")
	// Regexp for comment lines
	cexp = regexp.MustCompile("^#.*$")
)

// Authenticate checks a user and password against the hashed value in the
// users map.
func (h *File) Authenticate(u string, p string) bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	err := bcrypt.CompareHashAndPassword([]byte(h.users[u]), []byte(p))
	return err == nil
}

// Open returns a new File populated with users from the specified
// htpasswd file path.
func Open(p string) (*File, error) {
	path, _ := filepath.Abs(p)
	h := &File{
		CheckInterval: 0,
		lastModified:  time.Unix(0, 0),
		lastSize:      0,
		mutex:         sync.Mutex{},
		path:          path,
		users:         make(map[string]string),
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	err := h.readFile()
	if err != nil {
		return nil, err
	}

	return h, nil
}

// Reload checks the modification time of the htpasswd file and reads the file
// in again if it has changed
func (h *File) Reload() error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	stat, err := os.Stat(h.path)
	if err != nil {
		return err
	}

	if stat.ModTime() != h.lastModified || stat.Size() != h.lastSize {
		if err := h.readFile(); err != nil {
			return err
		}
	}
	return nil
}

// isValidLine checks for a match against the supplied regular expression.
func isValidLine(r *regexp.Regexp, line string) bool {
	return r.MatchString(line)
}

// readFile locks and reads in the htpasswd file and populates the users map
// and the lastModified fields of the File struct.
func (h *File) readFile() error {
	users := make(map[string]string)

	file, err := os.Open(h.path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || isValidLine(cexp, line) {
			// Don't do anything for comments or empty lines
		} else if isValidLine(bexp, line) {
			user := strings.SplitN(line, ":", 2)
			users[user[0]] = user[1]
		} else {
			return fmt.Errorf("Invalid line found: %s", line)
		}
	}

	stat, err := os.Stat(h.path)
	h.lastModified = stat.ModTime()
	h.lastSize = stat.Size()
	h.users = users
	return nil
}
