package htpasswd

import (
	"bufio"
	"os"
	"testing"
)

func TestIsValidBcryptLine(t *testing.T) {
	var tests = []struct {
		in  string
		out bool
	}{
		// Valid, 2a specification
		{"example:$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.xPs2Gghu", true},
		// Valid, 2y specification
		{"example:$2y$05$Vdk6E1bKMHVG.t0SLw5yiO224pZyGC27TcDCPPx3gmyf7us3X8yNa", true},
		// Invalid, hash is shorter than 53 characters
		{"example:$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.", false},
		// Invalid, hash is longer than 53 characters
		{"example:$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.xPs2GghuXXXXXXX", false},
		// Invalid, line has no username
		{"$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.xPs2Gghu", false},
		// Invalid, username starts with a digit
		{"1:$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.xPs2Gghu", false},
		// Invalid, line is just crap
		{"Well I'll be a monkey's ass", false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			i := isValidLine(bexp, tt.in)
			if i != tt.out {
				t.Errorf("isValidLine[bcrypt] got %t, want %t", i, tt.out)
			}
		})
	}
}

func TestIsValidCommentLine(t *testing.T) {
	var tests = []struct {
		in  string
		out bool
	}{
		// Valid, line is a comment
		{"# Hi", true},
		// Invalid, not an appropriate comment for an htpasswd file
		{"// Not a comment", false},
		// Invalid, garbage line
		{"That really shouldn't happen, no. really.", false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			i := isValidLine(cexp, tt.in)
			if i != tt.out {
				t.Errorf("isValidLine[comment] got %t, want %t", i, tt.out)
			}
		})
	}
}

func TestReadValidFile(t *testing.T) {
	h, err := Open("testdata/htpasswd.valid")
	if err != nil {
		t.Errorf("read[open] Open returned nil: %s", err)
		return
	}
	if _, exist := h.users["example1"]; !exist {
		t.Errorf("read[example1] did not contain the example1 user")
	}

	if _, exist := h.users["example2"]; !exist {
		t.Errorf("read[example2] did not contain the example2 user")
	}
}

func TestReadInvalidFiles(t *testing.T) {
	// File with invalid lines
	_, err := Open("testdata/htpasswd.invalid")
	if err == nil {
		t.Errorf("read[open] invalid file did not return an error")
	}
}

func TestReadNonExistentFile(t *testing.T) {
	// Non-existent file
	_, err := Open("testdata/htpasswd")
	if err == nil {
		t.Errorf("read[open] non-existent file did not return an error")
	}
}

func TestUserAuthenticate(t *testing.T) {
	h, err := Open("testdata/htpasswd.valid")
	if err != nil {
		t.Errorf("authenticate[open] could not open file %v", err)
		return
	}

	if !h.Authenticate("example1", "secret") {
		t.Errorf("authenticate[example1] authentication failed")
	}

	if !h.Authenticate("example2", "secret") {
		t.Errorf("authenticate[example2] authentication failed")
	}
}

var reloadoriginalcontents = `
example1:$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.xPs2Gghu
`

var reloadupdatedcontents = `
example1:$2a$10$3cz0nlM0jWIAs1wXcBu7XuLJjNg9Mz36RSExfwSW.0rs.xPs2Gghu
example2:$2y$05$Vdk6E1bKMHVG.t0SLw5yiO224pZyGC27TcDCPPx3gmyf7us3X8yNa
`

func TestReload(t *testing.T) {
	f, err := os.Create("/tmp/htpasswd.testing")
	if err != nil {
		t.Errorf("reload[create] unable to create file")
		return
	}

	// Populate the file with the original contents
	w := bufio.NewWriter(f)
	_, err = w.WriteString(reloadoriginalcontents)
	if err != nil {
		t.Errorf("reload[write original] unable to write contents")
		return
	}
	w.Flush()

	// Load and make sure that we get the appropriate users
	h, err := Open("/tmp/htpasswd.testing")
	if err != nil {
		t.Errorf("authenticate[open] could not open file %v", err)
		return
	}

	if _, exist := h.users["example1"]; !exist {
		t.Errorf("read[example1] did not contain the example1 user")
	}

	if _, exist := h.users["example2"]; exist {
		t.Errorf("read[example2] contained the example2 user")
	}

	// When we reload without changing the users remain the same
	h.Reload()

	if _, exist := h.users["example1"]; !exist {
		t.Errorf("read[example1] did not contain the example1 user")
	}

	if _, exist := h.users["example2"]; exist {
		t.Errorf("read[example2] contained the example2 user")
	}

	// Update the file and reload
	w = bufio.NewWriter(f)
	_, err = w.WriteString(reloadupdatedcontents)
	if err != nil {
		t.Errorf("reload[write updated] unable to write contents")
		return
	}
	w.Flush()

	// Make sure we get the new users after the reload
	h.Reload()
	if _, exist := h.users["example1"]; !exist {
		t.Errorf("read[example1] did not contain the example1 user")
	}

	if _, exist := h.users["example2"]; !exist {
		t.Errorf("read[example2] did not contain the example2 user")
	}

}
