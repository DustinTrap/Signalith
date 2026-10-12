package assistant

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestAnthropicRetriesOnParseError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != "k" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("request %s %v", r.URL.Path, r.Header)
		}
		var body struct {
			Model    string    `json:"model"`
			System   string    `json:"system"`
			Messages []message `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Model != "claude-sonnet-5-5" || !strings.Contains(body.System, "Authentication") {
			t.Errorf("body model %q", body.Model)
		}
		text := "datamodel=Authentication | stats count by"
		if len(body.Messages) == 3 {
			if !strings.Contains(body.Messages[2].Content, "does not parse") {
				t.Errorf("retry message %q", body.Messages[2].Content)
			}
			text = "```\ndatamodel=Authentication action=failure | stats count by src\n```"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	}))
	defer srv.Close()
	c := New(Anthropic, srv.URL, "", "k")
	q, err := c.Translate(context.Background(), "failed logins by source", "")
	if err != nil || q != "datamodel=Authentication action=failure | stats count by src" || calls != 2 {
		t.Fatalf("q=%q err=%v calls=%d", q, err, calls)
	}
}

func TestOpenAICompatible(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "" {
			t.Errorf("request %s auth %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": "datamodel=Endpoint process_name=cmd.exe"}}}})
	}))
	defer srv.Close()
	c := New(OpenAI, srv.URL+"/v1", "llama3.1", "")
	q, err := c.Translate(context.Background(), "cmd", "")
	if err != nil || q != "datamodel=Endpoint process_name=cmd.exe" {
		t.Fatalf("q=%q err=%v", q, err)
	}
}

func TestErrorsAreReadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid x-api-key"}}`))
	}))
	defer srv.Close()
	_, err := New(Anthropic, srv.URL, "", "bad").Translate(context.Background(), "x", "")
	if err == nil || !strings.Contains(err.Error(), "invalid x-api-key") {
		t.Fatalf("err = %v", err)
	}
}

func TestOffWhenNoProvider(t *testing.T) {
	if New("", "", "", "") != nil {
		t.Error("want nil client")
	}
}

func TestPromptExamplesParse(t *testing.T) {
	p := SystemPrompt()
	ex := p[strings.Index(p, "Examples:"):]
	n := 0
	for _, line := range strings.Split(ex, "\n") {
		if line == "" || strings.HasPrefix(line, "Q:") || line == "Examples:" {
			continue
		}
		n++
		if _, err := query.Parse(line); err != nil {
			t.Errorf("example %q: %v", line, err)
		}
	}
	if n != 3 {
		t.Errorf("found %d examples", n)
	}
}
