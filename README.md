# Htpasswd Authentication

Htpasswd is a go package for reading and authenticating using htpasswd files.

## Installation

`go get -u github.com/rlyon/htpasswd`

## Quick Start

```go
h, err := htpasswd.Open('/path/to/.htpasswd')
h.Authenticate('username', 'password')

// At any point you can reload the users if anything has changed
h.Reload()
```

At some point a process that reloads the contents at a specified check interval will be added, but it has not been implimented.  It will look like this:

```go
h, err := htpasswd.Open('/path/to/.htpasswd')
// Set the check interval for 30 seconds
h.CheckInterval = 30
// Start the process to automatically reload the file at the specified check interval
h.AutoReload()
```

## Development Status

Though the standard interface will be stable, the project is new and should not yet be considered stable for production use.

## Contributing

Contributions are encouraged.  In the interest of fostering an open and welcoming environment, we pledge to making participation in our project and our community a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, education, socio-economic status, nationality, personal appearance, race, religion, or sexual identity and orientation.
