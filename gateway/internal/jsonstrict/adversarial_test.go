package jsonstrict

import (
	"strings"
	"testing"
	"time"
)

// A small body must not be able to cost a lot of time. These all run in
// microseconds locally; the threshold is loose because a shared CI runner
// under load is not a quiet machine, and this test is here to catch a
// quadratic blow-up rather than to measure performance.
func TestCheckIsFastOnAdversarialInput(t *testing.T) {
	cases := map[string]string{
		"64 KiB of open brackets": strings.Repeat("[", 64<<10),
		"64 KiB of open braces":   strings.Repeat("{", 64<<10),
		"64 KiB of commas":        strings.Repeat(",", 64<<10),
		"64 KiB of nested arrays": strings.Repeat("[", 32<<10) + strings.Repeat("]", 32<<10),
		"64 KiB one-char keys":    "{" + strings.Repeat(`"a":1,`, 10000) + `"z":1}`,
		"64 KiB distinct keys":    "{" + distinct(8000) + `"zz":1}`,
		"64 KiB of quotes":        strings.Repeat(`"`, 64<<10),
		"64 KiB of backslashes":   `{"a":"` + strings.Repeat(`\`, 60<<10) + `"}`,
	}

	for name, body := range cases {
		started := time.Now()
		_ = Check([]byte(body))
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("%s took %v, want well under the limit", name, elapsed)
		} else {
			t.Logf("%-26s %v", name, elapsed)
		}
	}
}

func distinct(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(`"k`)
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + (i/26)%26)))
		b.WriteString(string(rune('a' + (i/676)%26)))
		b.WriteString(`":1,`)
	}
	return b.String()
}
