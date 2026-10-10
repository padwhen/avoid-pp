package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/padwhen/avoid-pp/gateway/internal/auth"
	"github.com/padwhen/avoid-pp/gateway/internal/contract"
)

// EnvAPIKeys names the variable carrying caller credentials.
//
// One variable rather than one per caller, because Load reads configuration
// through an injected Getenv and cannot enumerate the environment; a
// per-caller scheme would need a separate index variable listing the names,
// which is the same packing problem with an extra step.
const EnvAPIKeys = "AVOIDPP_API_KEYS"

// The packed format, documented in docs/configuration.md:
//
//	name:task[+task...]:key[,name:task:key...]
//
// Keys are generated, not typed by hand, so forbidding the separators in them
// costs nothing. The key is last so that a reader scanning the variable in a
// terminal sees names and tasks before the secret.
const (
	keyEntrySeparator = ","
	keyFieldSeparator = ":"
	keyTaskSeparator  = "+"
)

// parseAPIKeys turns the packed variable into caller specs.
//
// Messages name the entry's position and the requirement. They never quote the
// value, because the value is partly a credential and these errors are logged
// at startup. Position is enough to find the problem in a variable the
// operator can see.
func parseAPIKeys(raw string) ([]auth.KeySpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%s: required; see docs/configuration.md", EnvAPIKeys)
	}

	var (
		specs    []auth.KeySpec
		problems []error
	)
	for i, entry := range strings.Split(raw, keyEntrySeparator) {
		position := i + 1
		entry = strings.TrimSpace(entry)
		if entry == "" {
			problems = append(problems, fmt.Errorf(
				"%s entry %d: empty", EnvAPIKeys, position))
			continue
		}

		fields := strings.Split(entry, keyFieldSeparator)
		if len(fields) != 3 {
			// Three fields exactly. A key containing a colon would split into
			// four and land here rather than being silently truncated.
			problems = append(problems, fmt.Errorf(
				"%s entry %d: expected name%stasks%skey", EnvAPIKeys, position,
				keyFieldSeparator, keyFieldSeparator))
			continue
		}

		name := strings.TrimSpace(fields[0])
		key := strings.TrimSpace(fields[2])
		if name == "" {
			problems = append(problems, fmt.Errorf(
				"%s entry %d: caller name is empty", EnvAPIKeys, position))
			continue
		}
		if key == "" {
			problems = append(problems, fmt.Errorf(
				"%s entry %d: key is empty", EnvAPIKeys, position))
			continue
		}

		var tasks []contract.TaskID
		for _, task := range strings.Split(fields[1], keyTaskSeparator) {
			task = strings.TrimSpace(task)
			if task != "" {
				tasks = append(tasks, contract.TaskID(task))
			}
		}
		if len(tasks) == 0 {
			problems = append(problems, fmt.Errorf(
				"%s entry %d: no tasks listed for caller %q", EnvAPIKeys, position, name))
			continue
		}

		specs = append(specs, auth.KeySpec{Name: name, Key: key, Tasks: tasks})
	}

	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return specs, nil
}
