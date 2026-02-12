package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ApplyEnvFile loads a JSON config file and sets env vars for keys
// that are not already set in the environment.
func ApplyEnvFile(path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for k, v := range raw {
		if os.Getenv(k) != "" {
			continue
		}
		os.Setenv(k, formatValue(v))
	}
	return nil
}

// ApplyOverrides sets env vars for non-empty values, overriding existing env.
func ApplyOverrides(values map[string]string) {
	for k, v := range values {
		if v == "" {
			continue
		}
		_ = os.Setenv(k, v)
	}
}

func formatValue(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%f", t)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, formatValue(item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(v)
	}
}
