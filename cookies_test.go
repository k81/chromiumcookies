package cookies_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/k81/cookies"
)

func TestCookiesLoad(t *testing.T) {
	cookies, err := cookies.LoadAll()
	require.NoError(t, err)
	require.NotEmpty(t, cookies)
}
