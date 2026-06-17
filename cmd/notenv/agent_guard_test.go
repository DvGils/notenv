package main

import (
	"strings"
	"testing"
)

func TestAgentName(t *testing.T) {
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"claude"}, true},
		{[]string{"/usr/local/bin/codex", "-m"}, true}, // matched on basename
		{[]string{"aider"}, true},
		{[]string{"agent", "mcp"}, true},
		{[]string{"cn"}, true},
		{[]string{"opencode"}, true},
		{[]string{"pytest", "-q"}, false},
		{[]string{"npx", "claude"}, false}, // a wrapper is not matched, by design
		{nil, false},
	}
	for _, c := range cases {
		if _, ok := agentName(c.argv); ok != c.want {
			t.Errorf("agentName(%v) ok = %v, want %v", c.argv, ok, c.want)
		}
	}
}

func TestGuardAgentRun(t *testing.T) {
	savedInteractive, savedConfirm := interactiveFn, confirmFn
	defer func() { interactiveFn, confirmFn = savedInteractive, savedConfirm }()

	t.Run("non-agent command is never prompted", func(t *testing.T) {
		t.Setenv(sessionEnv, "")
		prompted := false
		interactiveFn = func() bool { return true }
		confirmFn = func(string, bool) (bool, error) { prompted = true; return false, nil }
		if err := guardAgentRun([]string{"pytest", "-q"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prompted {
			t.Fatal("a non-agent command must not prompt")
		}
	})

	t.Run("agent in a non-interactive shell proceeds silently", func(t *testing.T) {
		t.Setenv(sessionEnv, "")
		prompted := false
		interactiveFn = func() bool { return false }
		confirmFn = func(string, bool) (bool, error) { prompted = true; return false, nil }
		if err := guardAgentRun([]string{"claude"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prompted {
			t.Fatal("with no human to ask, run must proceed without prompting")
		}
	})

	t.Run("agent already inside a handoff proceeds silently", func(t *testing.T) {
		t.Setenv(sessionEnv, "0::/some/scope")
		prompted := false
		interactiveFn = func() bool { return true }
		confirmFn = func(string, bool) (bool, error) { prompted = true; return false, nil }
		if err := guardAgentRun([]string{"claude"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if prompted {
			t.Fatal("inside a handoff session there is nothing to suggest")
		}
	})

	t.Run("declining stops and points at handoff", func(t *testing.T) {
		t.Setenv(sessionEnv, "")
		interactiveFn = func() bool { return true }
		confirmFn = func(string, bool) (bool, error) { return false, nil }
		err := guardAgentRun([]string{"claude", "--dangerously-skip-permissions"})
		if err == nil {
			t.Fatal("declining the prompt must abort the run")
		}
		if !strings.Contains(err.Error(), "handoff") {
			t.Errorf("the error should point at handoff, got: %v", err)
		}
	})

	t.Run("confirming proceeds", func(t *testing.T) {
		t.Setenv(sessionEnv, "")
		interactiveFn = func() bool { return true }
		confirmFn = func(string, bool) (bool, error) { return true, nil }
		if err := guardAgentRun([]string{"aider"}); err != nil {
			t.Fatalf("confirming should let the run proceed: %v", err)
		}
	})
}
