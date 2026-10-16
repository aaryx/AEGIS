export type Location = { page: string; selected: { resource: string; id: string } | null };
const pages: Record<string, string> = {
  dashboard: "Dashboard", alerts: "Alerts", incidents: "Incidents", storylines: "Storylines", cases: "Cases",
  hunting: "Threat Hunting", events: "Events", entities: "Entities", rules: "Detection Rules",
  iocs: "Threat Intelligence", mitre: "MITRE ATT&CK", reports: "Reports", playbooks: "Playbooks",
  collectors: "Collectors", health: "System Health", audit: "Audit", settings: "Settings"
};
export function parseLocation(hash: string): Location {
  const [key, rawId] = hash.replace(/^#\/?/, "").split("/");
  const page = pages[key] || "Dashboard";
  let id = "";
  try { id = rawId ? decodeURIComponent(rawId) : ""; } catch { return { page, selected: null }; }
  return { page, selected: pages[key] && id && /^[A-Za-z0-9_-]{1,80}$/.test(id) && !["dashboard", "hunting", "health", "settings", "mitre"].includes(key) ? { resource: key, id } : null };
}
export function pageHash(page: string) { return "#/" + (Object.keys(pages).find(key => pages[key] === page) || "dashboard"); }
