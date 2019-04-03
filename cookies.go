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
	"net/http"
	"net/url"
	"os/exec"
	"os/user"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

var (
	salt = "saltysalt"
	iv   = bytes.Repeat([]byte(" "), 16)
)

// DecryptedValue - Get the unencrypted value of a Chrome cookie
func decrypt(key []byte, encrypted []byte) (value string, err error) {

	if len(encrypted) <= 3 {
		return "", errors.New("too short encrypted valud")
	}

	encrypted = encrypted[3:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(encrypted))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decrypted, encrypted)

	if len(decrypted)%16 != 0 {
		return "", errors.New("decrypted data block length is not multiple of 16 bytes")
	}

	padLen := int(decrypted[len(decrypted)-1])
	if padLen > 16 {
		return "", fmt.Errorf("invalid padding length: %v", padLen)
	}

	return string(decrypted[:len(decrypted)-padLen]), nil
}

func getSecret() (secret string, err error) {
	result, err := exec.Command("secret-tool", "lookup", "application", "chromium").Output()
	if err != nil {
		return "", nil
	}
	return string(result), nil
}

func LoadIntoJar(jar http.CookieJar) (err error) {
	// get secret
	secret, err := getSecret()
	if err != nil {
		return err
	}

	key := pbkdf2.Key([]byte(secret), []byte(salt), 1, 16, sha1.New)

	usr, err := user.Current()
	if err != nil {
		return err
	}

	cookiesFile := fmt.Sprintf("%s/.config/chromium/Default/Cookies", usr.HomeDir)

	db, err := sql.Open("sqlite3", cookiesFile)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = db.Close()
	}()

	rows, err := db.Query("select host_key,name,value,encrypted_value,path,is_secure,is_httponly from cookies")
	if err != nil {
		return err
	}
	defer func() {
		_ = rows.Close()
	}()

	for rows.Next() {
		var (
			cookie         = &http.Cookie{}
			encryptedValue []byte
		)

		if err = rows.Scan(
			&cookie.Domain,
			&cookie.Name,
			&cookie.Value,
			&encryptedValue,
			&cookie.Path,
			&cookie.Secure,
			&cookie.HttpOnly,
		); err != nil {
			return err
		}

		if len(encryptedValue) > 3 {
			if ver := string(encryptedValue[:3]); ver != "v11" {
				return fmt.Errorf("unsupported encryption version: %v", ver)
			}
			if cookie.Value, err = decrypt(key, encryptedValue); err != nil {
				return errors.New("decryption failed")
			}
		}

		jar.SetCookies(&url.URL{Scheme: "http", Host: cookie.Domain}, []*http.Cookie{
			cookie,
		})
	}

	return nil
}
