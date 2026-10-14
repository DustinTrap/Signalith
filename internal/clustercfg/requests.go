package clustercfg

// Requests of the content (see shared.Requests): work any member asks of
// the server that runs the background jobs.
const (
	// RequestFeedRefresh downloads one feed now.
	RequestFeedRefresh = "feed_refresh"
	// RequestRetentionRun runs retention now, or after a change of the
	// policies (trigger policy_change).
	RequestRetentionRun = "retention_run"
)

// FeedRefreshArgs are the arguments of a feed_refresh request.
type FeedRefreshArgs struct {
	Feed string `json:"feed"`
}

// RetentionRunArgs are the arguments of a retention_run request.
type RetentionRunArgs struct {
	// Trigger is retention.TriggerManual (the default) or
	// retention.TriggerChange.
	Trigger string `json:"trigger,omitempty"`
}
