// Package store talks to OpenSearch over its REST API using only net/http,
// so the server stays a single dependency-light binary on Windows and Linux.
package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Searcher runs a search request body against an index pattern.
type Searcher interface {
	Search(ctx context.Context, index string, body map[string]any) (map[string]any, error)
}

// Config holds connection settings.
type Config struct {
	URL           string
	Username      string
	Password      string
	TLSSkipVerify bool
	Timeout       time.Duration
}

// Client is an OpenSearch REST client.
type Client struct {
	base string
	cfg  Config
	http *http.Client
}

// New returns a client for one OpenSearch endpoint.
func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for self-signed lab clusters
	}
	return &Client{
		base: strings.TrimRight(cfg.URL, "/"),
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout, Transport: tr},
	}
}

// Error is a non-2xx response from OpenSearch.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	body := e.Body
	var parsed struct {
		Error struct {
			Type      string `json:"type"`
			Reason    string `json:"reason"`
			RootCause []struct {
				Reason string `json:"reason"`
			} `json:"root_cause"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(e.Body), &parsed) == nil && parsed.Error.Reason != "" {
		body = parsed.Error.Type + ": " + parsed.Error.Reason
		if len(parsed.Error.RootCause) > 0 && parsed.Error.RootCause[0].Reason != parsed.Error.Reason {
			body += " (" + parsed.Error.RootCause[0].Reason + ")"
		}
	}
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	return fmt.Sprintf("opensearch returned %d: %s", e.Status, body)
}

// Do sends a request and decodes a JSON response into out (if non-nil).
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	contentType := "application/json"
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
		contentType = "application/x-ndjson"
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if rd != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.cfg.Username != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("opensearch unreachable at %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &Error{Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		return dec.Decode(out)
	}
	return nil
}

// Search implements Searcher.
func (c *Client) Search(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	var out map[string]any
	path := "/" + url.PathEscape(index) + "/_search?ignore_unavailable=true&allow_no_indices=true"
	err := c.Do(ctx, http.MethodPost, path, body, &out)
	return out, err
}

// Health returns cluster health ("green", "yellow", "red").
func (c *Client) Health(ctx context.Context) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	err := c.Do(ctx, http.MethodGet, "/_cluster/health", nil, &out)
	return out.Status, err
}

// BulkItemError describes one rejected document in a bulk request.
type BulkItemError struct {
	Index  string
	Reason string
	// Pos is the document's position in the request, from 0, and Type the
	// OpenSearch error type, such as mapper_parsing_exception.
	Pos  int    `json:"-"`
	Type string `json:"-"`
}

// Bulk indexes documents. docs maps each document to its target index.
func (c *Client) Bulk(ctx context.Context, docs []IndexedDoc) ([]BulkItemError, error) {
	if len(docs) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, d := range docs {
		if err := enc.Encode(map[string]any{"create": map[string]any{"_index": d.Index}}); err != nil {
			return nil, err
		}
		if err := enc.Encode(d.Doc); err != nil {
			return nil, err
		}
	}
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Index  string `json:"_index"`
			Status int    `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := c.Do(ctx, http.MethodPost, "/_bulk", buf.Bytes(), &out); err != nil {
		return nil, err
	}
	var errs []BulkItemError
	if out.Errors {
		for i, item := range out.Items {
			for _, r := range item {
				if r.Error != nil {
					errs = append(errs, BulkItemError{Index: r.Index, Reason: r.Error.Type + ": " + r.Error.Reason, Pos: i, Type: r.Error.Type})
				}
			}
		}
	}
	return errs, nil
}

// IndexedDoc is one document and the index it goes to.
type IndexedDoc struct {
	Index string
	Doc   map[string]any
}

// PutIndexTemplate creates or replaces a composable index template.
func (c *Client) PutIndexTemplate(ctx context.Context, name string, tmpl map[string]any) error {
	return c.Do(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(name), tmpl, nil)
}

// ListIndices returns index names matching a pattern.
func (c *Client) ListIndices(ctx context.Context, pattern string) ([]string, error) {
	var out []struct {
		Index string `json:"index"`
	}
	err := c.Do(ctx, http.MethodGet, "/_cat/indices/"+url.PathEscape(pattern)+"?format=json&h=index&expand_wildcards=open", nil, &out)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out))
	for _, o := range out {
		names = append(names, o.Index)
	}
	return names, nil
}

// DeleteIndex deletes one index.
func (c *Client) DeleteIndex(ctx context.Context, name string) error {
	return c.Do(ctx, http.MethodDelete, "/"+url.PathEscape(name), nil, nil)
}

// Mapping returns the merged field -> type map for an index pattern,
// flattening object fields to dotted names.
func (c *Client) Mapping(ctx context.Context, pattern string) (map[string]string, error) {
	var out map[string]struct {
		Mappings struct {
			Properties map[string]any `json:"properties"`
		} `json:"mappings"`
	}
	err := c.Do(ctx, http.MethodGet, "/"+url.PathEscape(pattern)+"/_mapping?ignore_unavailable=true&allow_no_indices=true", nil, &out)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for _, idx := range out {
		flattenMapping("", idx.Mappings.Properties, fields)
	}
	return fields, nil
}

func flattenMapping(prefix string, props map[string]any, out map[string]string) {
	for name, v := range props {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		if sub, ok := m["properties"].(map[string]any); ok {
			flattenMapping(full, sub, out)
			continue
		}
		if t, ok := m["type"].(string); ok {
			out[full] = t
		}
	}
}
