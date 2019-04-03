package chromiumcookies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

const SQLSelectAll = `select host_key,name,value,encrypted_value,path,is_secure,is_httponly,is_persistent,expires_utc,creation_utc,last_access_utc from cookies`

var (
	salt = "saltysalt"
	iv   = bytes.Repeat([]byte(" "), 16)
)

// Cookie - Items for a cookie
type Cookie struct {
	Name           string
	Value          string
	Domain         string
	Path           string
	Secure         bool
	HttpOnly       bool
	Persistent     bool
	Expires        time.Time
	Creation       time.Time
	LastAccess     time.Time
	EncryptedValue []byte
}

// DecryptedValue - Get the unencrypted value of a Chrome cookie
func (c *Cookie) Decrypt(key []byte) (err error) {
	if c.Value > "" {
		return nil
	}

	if len(c.EncryptedValue) <= 3 {
		return nil
	}

	encrypted := c.EncryptedValue[3:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	decrypted := make([]byte, len(encrypted))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decrypted, encrypted)

	if len(decrypted)%16 != 0 {
		return errors.New("decrypted data block length is not multiple of 16 bytes")
	}

	padLen := int(decrypted[len(decrypted)-1])
	if padLen > 16 {
		return fmt.Errorf("invalid padding length: %v", padLen)
	}

	c.Value = string(decrypted[:len(decrypted)-padLen])

	return nil
}

func getSecret() (secret string, err error) {
	result, err := exec.Command("secret-tool", "lookup", "application", "chromium").Output()
	if err != nil {
		return "", nil
	}
	return string(result), nil
}

func LoadAll() (cookies []*Cookie, err error) {
	// get secret
	secret, err := getSecret()
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(secret), []byte(salt), 1, 16, sha1.New)

	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	cookiesFile := fmt.Sprintf("%s/.config/chromium/Default/Cookies", usr.HomeDir)

	db, err := sql.Open("sqlite3", cookiesFile)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query(SQLSelectAll)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	cookies = make([]*Cookie, 0, 256)
	for rows.Next() {
		var (
			c             = &Cookie{}
			expiresUTC    int64
			creationUTC   int64
			lastAccessUTC int64
		)

		if err = rows.Scan(&c.Domain,
			&c.Name,
			&c.Value,
			&c.EncryptedValue,
			&c.Path,
			&c.Secure,
			&c.HttpOnly,
			&c.Persistent,
			&expiresUTC,
			&creationUTC,
			&lastAccessUTC,
		); err != nil {
			return nil, err
		}

		c.Expires = time.Unix(expiresUTC/1000000-11644473600, 0)
		c.Creation = time.Unix(creationUTC/1000000-11644473600, 0)
		c.LastAccess = time.Unix(lastAccessUTC/1000000-11644473600, 0)

		if err = c.Decrypt(key); err != nil {
			return nil, err
		}
		cookies = append(cookies, c)
	}

	return cookies, nil
}
