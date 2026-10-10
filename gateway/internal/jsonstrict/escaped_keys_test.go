package jsonstrict

import (
	"errors"
	"testing"
)

func TestEscapedDuplicateKeysAreCaught(t *testing.T) {
	cases := map[string]string{
		"plain duplicate":          `{"a":1,"a":2}`,
		"second key escaped":       `{"a":1,"a":2}`,
		"first key escaped":        `{"a":1,"a":2}`,
		"both escaped differently": `{"a":1,"a":2}`,
		"task_id escaped":          `{"task_id":"x","task_id":"y"}`,
		"escaped mid-key":          `{"text":"a","text":"b"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Check([]byte(body)); !errors.Is(err, ErrDuplicateKey) {
				t.Errorf("error = %v, want ErrDuplicateKey — an escaped key is "+
					"the same key, and Go keeps the last one", err)
			}
		})
	}

	// And keys that merely look similar must NOT be rejected.
	for name, body := range map[string]string{
		"trailing space": `{"text":"a","text ":"b"}`,
		"different case": `{"TEXT":"a","text":"b"}`,
		"combining form": `{"ä":1,"ä":2}`,
	} {
		t.Run("not a duplicate: "+name, func(t *testing.T) {
			if err := Check([]byte(body)); err != nil {
				t.Errorf("Check() rejected distinct keys: %v", err)
			}
		})
	}
}
