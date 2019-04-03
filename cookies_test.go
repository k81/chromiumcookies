package chromiumcookies_test

import (
	"testing"

	"github.com/k81/chromiumcookies"
	"github.com/stretchr/testify/require"
)

func TestCookiesLoad(t *testing.T) {
	cookies, err := chromiumcookies.LoadAll()
	require.NoError(t, err)
	require.NotEmpty(t, cookies)
}
