package ingest

// IndexTemplate returns the OpenSearch index template every Signalith index
// uses: strings are exact-match keywords (fast filters and stats), the raw
// message is full-text, and ports, IDs and counts stay numeric.
//
// The field limit is set on purpose: the syslog receiver lets each daily
// index gain at most a few hundred vendor-specific (cef_*, sd_*) field names
// per run, and this leaves room for those on top of the data model fields,
// even across restarts. device_time (a syslog sender's own timestamp when
// it was too old or too far ahead to be the event time) is a keyword, so any
// value a sender wrote is stored rather than rejected as a bad date.
func IndexTemplate(prefix string, replicas int) map[string]any {
	return map[string]any{
		"index_patterns": []string{prefix + "-*"},
		"priority":       100,
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   1,
				"number_of_replicas": replicas,
				"refresh_interval":   "5s",
				"mapping":            map[string]any{"total_fields": map[string]any{"limit": 2000}},
			},
			"mappings": map[string]any{
				"dynamic_templates": []any{
					map[string]any{"strings_as_keywords": map[string]any{
						"match_mapping_type": "string",
						"mapping":            map[string]any{"type": "keyword", "ignore_above": 8191},
					}},
				},
				"properties": map[string]any{
					"@timestamp":      map[string]any{"type": "date"},
					"message":         map[string]any{"type": "text"},
					"process":         map[string]any{"type": "keyword", "ignore_above": 8191},
					"src_port":        map[string]any{"type": "long"},
					"dest_port":       map[string]any{"type": "long"},
					"process_id":      map[string]any{"type": "long"},
					"logon_type":      map[string]any{"type": "long"},
					"bytes":           map[string]any{"type": "long"},
					"bytes_in":        map[string]any{"type": "long"},
					"bytes_out":       map[string]any{"type": "long"},
					"facility":        map[string]any{"type": "keyword"},
					"severity":        map[string]any{"type": "keyword"},
					"risk_score":      map[string]any{"type": "double"},
					"risk_base_score": map[string]any{"type": "double"},
					"signature_id":    map[string]any{"type": "keyword"},
					"device_time":     map[string]any{"type": "keyword"},
				},
			},
		},
	}
}
