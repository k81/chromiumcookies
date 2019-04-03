package chromiumcookies_test

import (
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/k81/chromiumcookies"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/publicsuffix"
)

func TestCookiesLoad(t *testing.T) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	require.NoError(t, err)
	err = chromiumcookies.LoadIntoJar(jar)
	require.NoError(t, err)
	cookies := jar.Cookies(&url.URL{Scheme: "http", Host: "pub.alimama.com"})
	require.NotEmpty(t, cookies)
}
