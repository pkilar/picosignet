package cli

import "testing"

func TestInitRejectsOutOfRangeRetryBudgetsBeforeDeviceAccess(t *testing.T) {
	for _, retries := range []string{"0", "256", "999"} {
		if err := cmdInit([]string{"--prod", "--max-retries", retries}); err == nil {
			t.Errorf("cmdInit(--max-retries %s) succeeded", retries)
		}
	}
}
