# Htpasswd Authentication

Provides authentication functions for golang applications.  

Accept bcrypt or md5 passwords

Crypt only supports the 2a specification since golang crypt library does not currently support the latest 2y specification

type File struct {
	path
	lastModified
	checkIntervalChannel
	mutex
	Users
}

type User struct {

}

parseLine(map, string) user, format, hash
	returns the user format and hash if the line is a valid line
isModified(file)
	checks to see if Htpasswd.lastModified is less than the Htpasswd.path modification time and reloads.
isValidLine(string)
	checks to see if the line matches the bcrypt or md5 formats
setUser(user, hash)
	adds the user to Htpasswd.Users if it doesn't exist or overwrites the hash if it does exist
NewReader(file, checkInterval=0) (*HtpasswdFile, error)
Load(file, checkInterval=0)
	loads a file and if check is true then start a thread to reload the file at the given interval.
Reload(file)
	checks the last modified and if it has changed then reload the users.
Authenticate(user, password)
	grabs a lock on the interface and checks to see if the user and password match

file, err := htpasswd.New('/tmp/.htpasswd', 0)