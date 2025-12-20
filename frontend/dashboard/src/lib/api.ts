const API = process.env.NEXT_PUBLIC_API_URL;
console.log(">>> API URL =", API);
// 1. Lấy danh sách sensors
export async function fetchSensors() {
  const res = await fetch(`${API}/api/v1/sensors`, { cache: "no-store" });
  return res.json();
}

// 2. Lấy history ruleset
export async function fetchRuleSets() {
  const res = await fetch(`${API}/api/v1/rulesets`, { cache: "no-store" });
  return res.json();
}

// 3. Lấy active bundle
export async function fetchActiveRuleBundle() {
  const res = await fetch(`${API}/api/v1/rules/active_bundle`);
  return res.json();
}

// 4. Publish rule
export async function publishRules() {
  const res = await fetch(`${API}/api/v1/rules/publish`, {
    method: "POST"
  });
  return res.json();
}

// 5. Rollback rule
export async function activateRuleSet(id: string) {
  const res = await fetch(`${API}/api/v1/deployment/activate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rule_set_id: id })
  });
  return res.json();
}

// Lấy ruleset đang active
export async function fetchActiveRuleSet() {
  const res = await fetch(`${API}/api/v1/deployment/status`, { cache: "no-store" });

  if (!res.ok) {
    throw new Error("Failed to fetch active ruleset");
  }

  return res.json();
}
//lay mitre data
export async function fetchMitreLogs(params?: {
  sensor_id?: string;
  tactic?: string;
  limit?: number;
  skip?: number;
}) {
  const query = new URLSearchParams();

  if (params?.sensor_id) query.append("sensor_id", params.sensor_id);
  if (params?.tactic) query.append("tactic", params.tactic);
  if (params?.limit) query.append("limit", String(params.limit));
  if (params?.skip) query.append("skip", String(params.skip));

  const res = await fetch(
    `http://100.100.100.100:5000/api/v1/mitre/results?${query.toString()}`
  );

  if (!res.ok) {
    throw new Error("Failed to fetch MITRE logs");
  }

  return res.json(); // { count, data }
}
