// Agent session helpers — expiry, stale detection, etc.
use chrono::Utc;
use ghoststrike_common::AgentInfo;

pub fn is_stale(agent: &AgentInfo) -> bool {
    let elapsed = Utc::now()
        .signed_duration_since(agent.last_seen)
        .num_seconds();
    // If we haven't heard from the agent in 3× its sleep interval, mark stale.
    let threshold = (agent.sleep_ms as i64 / 1000) * 3;
    elapsed > threshold.max(30)
}
