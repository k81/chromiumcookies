Load chromium cookies from sqlite on linux.

Example Code:
```go
    jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	_ = chromiumcookies.LoadIntoJar(jar)
```
