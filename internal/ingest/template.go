package ingest

// IndexTemplate returns the OpenSearch index template every Signalith index
// uses: strings are exact-match keywords (fast filters and stats), the raw
// message is full-text, and ports, IDs and counts stay numeric.
func IndexTemplate(prefix string, replicas int) map[string]any {
	return map[string]any{
		"index_patterns": []string{prefix + "-*"},
		"priority":       100,
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   1,
				"number_of_replicas": replicas,
				"refresh_interval":   "5s",
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
					"risk_score":      map[string]any{"type": "double"},
					"risk_base_score": map[string]any{"type": "double"},
					"signature_id":    map[string]any{"type": "keyword"},
				},
			},
		},
	}
}
