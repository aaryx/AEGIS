"use client";

import { FormEvent, useEffect, useState } from "react";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, Bell, BellRing, ChevronRight, CircleHelp, Command, Cpu, Crosshair, Database, Download, FileSearch, FileText, Flame, FolderKanban, Grid, HeartPulse, History, Layers, LayoutDashboard, LogOut, Menu, Radio, Search, Settings, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sun, Workflow, X } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, csv, display, download, Page, Row, User } from "@/lib/api";
import { strings } from "@/lib/strings";
import { Badge, DataTable, JsonView, State } from "./ui";
import { Investigation } from "./investigation";
import { ResourceEditor } from "./editor";
import { IntegrationsPanel } from "./integrations";
import { Storylines } from "./storylines";
import { DetectionLab } from "./detection_lab";
import { Playbooks } from "./playbooks";
import { Intelligence } from "./intelligence";
import { pageHash, parseLocation } from "@/lib/navigation";

const navIcons: Record<string, React.ReactNode> = {
  "Dashboard": <LayoutDashboard size={16} />,
  "Alerts": <BellRing size={16} />,
  "Incidents": <Flame size={16} />,
  "Cases": <FolderKanban size={16} />,
  "Threat Hunting": <Crosshair size={16} />,
  "Events": <Layers size={16} />,
  "Entities": <Cpu size={16} />,
  "Detection Rules": <ShieldCheck size={16} />,
  "Threat Intelligence": <Database size={16} />,
  "MITRE ATT&CK": <Grid size={16} />,
  "Reports": <FileText size={16} />,
  "Playbooks": <Workflow size={16} />,
  "Collectors": <Radio size={16} />,
  "System Health": <HeartPulse size={16} />,
  "Audit": <History size={16} />,
  "Settings": <Settings size={16} />
};

const resources: Record<string, string> = { Alerts: "alerts", Incidents: "incidents", Cases: "cases", Entities: "entities", "Detection Rules": "rules", "Threat Intelligence": "iocs", Reports: "reports", Playbooks: "playbooks", Collectors: "collectors", Audit: "audit" };
const columns: Record<string, string[]> = {
  alerts: ["severity", "title", "rule_id", "risk_score", "status", "event_count", "last_seen"],
  incidents: ["severity", "title", "status", "priority", "assignee", "created_at"],
  cases: ["title", "status", "assignee", "created_at"], entities: ["type", "value", "risk_score", "last_seen"],
  rules: ["rule_id", "version", "enabled", "created_at"], iocs: ["type", "value", "severity", "confidence", "source"],
  reports: ["id", "incident_id", "generated_by", "created_at"], playbooks: ["action", "target", "status", "requested_by", "approved_by"],
  collectors: ["name", "type", "events_received", "events_processed", "errors", "last_heartbeat"],
  audit: ["created_at", "actor", "action", "resource_id", "result"]
};

export function ConsoleApp() {
  const [client] = useState(() => new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 15000, refetchOnWindowFocus: false } } }));
  return <QueryClientProvider client={client}><Workspace /></QueryClientProvider>;
}

function Workspace() {
  const queryClient = useQueryClient();
  const user = useQuery({ queryKey: ["me"], queryFn: () => api<User>("auth/me"), retry: false });
  const [page, setPage] = useState("Dashboard");
  const [selected, setSelected] = useState<{ resource: string; id: string } | null>(null);
  const [navOpen, setNavOpen] = useState(false);
  const [help, setHelp] = useState(false);
  const [light, setLight] = useState(false);
  const [connected, setConnected] = useState(false);
  useEffect(() => {
    const restore = () => { const location = parseLocation(window.location.hash); setPage(location.page); setSelected(location.selected); };
    restore(); window.addEventListener("hashchange", restore);
    return () => window.removeEventListener("hashchange", restore);
  }, []);
  useEffect(() => {
    if (!user.data) return;
    const stream = new EventSource("/api/v1/stream");
    stream.onopen = () => setConnected(true);
    stream.onerror = () => setConnected(false);
    stream.onmessage = () => queryClient.invalidateQueries({ predicate: query => query.queryKey[0] !== "me" });
    stream.addEventListener("expired", () => { stream.close(); queryClient.clear(); user.refetch(); });
    return () => stream.close();
  }, [user.data, queryClient]);
  useEffect(() => {
    let prefix = false;
    const handler = (event: KeyboardEvent) => {
      if ((event.target as HTMLElement).matches("input,textarea,select") || event.ctrlKey || event.metaKey || event.altKey) return;
      if (event.key === "/") { event.preventDefault(); setPage("Threat Hunting"); setSelected(null); setTimeout(() => document.getElementById("hunt-query")?.focus(), 100); }
      if (event.key === "?") setHelp(value => !value);
      if (event.key === "Escape") { setSelected(null); setHelp(false); }
      if (prefix) { const target = ({ a: "Alerts", i: "Incidents", h: "Threat Hunting", e: "Events" } as Record<string, string>)[event.key]; if (target) { setPage(target); setSelected(null); } }
      prefix = event.key === "g";
    };
    window.addEventListener("keydown", handler); return () => window.removeEventListener("keydown", handler);
  }, []);
  function navigate(name: string) { window.location.hash = pageHash(name); setPage(name); setSelected(null); setNavOpen(false); }
  if (user.isPending) return <State loading />;
  if (!user.data) return <Login onSuccess={() => user.refetch()} />;
  const open = (resource: string, row: Row) => { const id = String(row.id || row.event_id); window.location.hash = `#/${resource}/${encodeURIComponent(id)}`; setSelected({ resource, id }); };
  return <div className={`app ${light ? "light" : ""}`}>
    <a href="#main" className="skip-link">Skip to main content</a>
    <aside className={`sidebar ${navOpen ? "open" : ""}`} aria-label="Primary navigation">
      <div className="brand"><span className="brand-mark"><Shield size={25} /></span><div><strong>AEGIS</strong><span>SECURITY OPERATIONS</span></div></div>
      <div className="workspace-label"><span className="dot" /> Operations workspace <ChevronRight size={14} /></div>
      <div className="nav-heading">WORKSPACE</div>
      <nav>{strings.nav.filter(name => name !== "Audit" || user.data.permissions.includes("audit.read")).map(name => <button key={name} className={page === name ? "active" : ""} onClick={() => navigate(name)} aria-current={page === name ? "page" : undefined}>
        {navIcons[name] || <FileSearch size={16} />}<span>{name}</span>
      </button>)}</nav>
      <div className="sidebar-footer"><div className={`connection ${connected ? "online" : ""}`}><span className="dot" />{connected ? "Live connection" : "Reconnecting"}</div><span>AEGIS · {user.data.role.replaceAll("_", " ")}</span></div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><button className="icon-button mobile-menu" aria-label="Toggle navigation" onClick={() => setNavOpen(!navOpen)}><Menu size={20} /></button><div className="breadcrumb">Workspace <ChevronRight size={13} /><strong>{page}</strong></div>
        <div className="topbar-actions"><button className="global-search" onClick={() => navigate("Threat Hunting")}><Search size={15} /><span>Search security data</span><kbd>/</kbd></button><button className="icon-button" aria-label="Toggle color theme" onClick={() => setLight(!light)}><Sun size={17} /></button><button className="icon-button" aria-label="Keyboard shortcuts" onClick={() => setHelp(!help)}><CircleHelp size={17} /></button><span className="avatar">{user.data.username.slice(0, 2).toUpperCase()}</span><button className="icon-button" aria-label="Sign out" onClick={async () => { await api("auth/logout", "POST"); queryClient.clear(); user.refetch(); }}><LogOut size={17} /></button></div>
      </header>
      <main id="main">
        {help && <section className="panel shortcuts"><h2><Command size={17} /> Keyboard shortcuts</h2><p><kbd>/</kbd> Hunt · <kbd>g a</kbd> Alerts · <kbd>g i</kbd> Incidents · <kbd>g h</kbd> Hunting · <kbd>g e</kbd> Events · <kbd>Esc</kbd> Close detail</p><button onClick={() => setHelp(false)}>Close</button></section>}
        <div className="page-heading"><div><div className="eyebrow">SECURITY INTELLIGENCE & OPERATIONS</div><h1>{selected ? (selected.resource === "alerts" || selected.resource === "incidents" ? "Investigation workspace" : "Resource details") : page}</h1><p>{selected ? selected.id : page === "Dashboard" ? "Your security posture, grounded in live evidence." : "Explore, investigate, and act on your organization’s security data."}</p></div><div className="heading-status"><span className={`dot ${connected ? "" : "muted-dot"}`} /> {connected ? "Live updates" : "Connecting"}<span className="divider" />{new Date().toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}</div></div>
        {selected ? <><button className="back-button" onClick={() => navigate(page)}>← Back to {page}</button>{selected.resource === "observables" ? <Intelligence id={selected.id} user={user.data} onOpen={open} /> : selected.resource === "storylines" ? <Storylines id={selected.id} user={user.data} onOpen={open} /> : ["alerts", "incidents"].includes(selected.resource) ? <Investigation key={selected.id} id={selected.id} user={user.data} onOpen={open} /> : <ResourceEditor key={selected.id} resource={selected.resource} id={selected.id} user={user.data} onOpen={open} />}</> :
          page === "Dashboard" ? <Dashboard onOpen={open} navigate={navigate} /> :
          ["Threat Hunting", "Events"].includes(page) ? <Hunting onOpen={row => open("events", row)} /> :
          page === "System Health" ? <Health /> : page === "Settings" ? <><SettingsPanel user={user.data} />{user.data.permissions.includes("integrations.manage") && <IntegrationsPanel />}</> :
          page === "MITRE ATT&CK" ? <Mitre /> :
          page === "Storylines" ? <Storylines user={user.data} onOpen={open} /> :
          page === "Detection Rules" ? <DetectionLab user={user.data} onOpen={open} /> :
          page === "Playbooks" ? <Playbooks user={user.data} /> :
          page === "Threat Intelligence" ? <><Intelligence user={user.data} onOpen={open} /><ResourceList resource="iocs" user={user.data} onOpen={row => open("iocs", row)} /></> :
          <ResourceList resource={resources[page]} user={user.data} onOpen={row => open(resources[page], row)} />}
      </main>
      <footer className="footer"><span>AEGIS / Security Intelligence & Operations</span><span>Evidence first. Analyst controlled.</span></footer>
    </div>
  </div>;
}

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError(""); const data = new FormData(event.currentTarget);
    try { await api("auth/login", "POST", { username: data.get("username"), password: data.get("password") }); onSuccess(); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  return <main className="login-screen"><section className="login-card"><div className="brand"><Shield size={32} /><div><strong>AEGIS</strong><span>SECURITY OPERATIONS</span></div></div><h1>Sign in to your workspace</h1><p>Security intelligence. Connected evidence. Informed response.</p><form onSubmit={submit}><label>Username<input name="username" autoComplete="username" required autoFocus /></label><label>Password<input name="password" type="password" autoComplete="current-password" required /></label>{error && <p role="alert" className="error-text">{error}</p>}<button className="primary" disabled={busy}>{busy ? "Authenticating…" : "Sign in"}</button></form><p className="hint">Initial setup: create an administrator with <code>aegis bootstrap</code>.</p></section></main>;
}

type DashboardData = { events: number; events_processed: number; alerts: number; open_incidents: number; severity: Record<string, number>; events_per_second: number; alerts_per_1000_events: number; recent_alerts: Row[]; top_entities: Row[]; top_rules: { rule_id: string; count: number }[] };
function Dashboard({ onOpen, navigate }: { onOpen: (resource: string, row: Row) => void; navigate: (page: string) => void }) {
  const query = useQuery({ queryKey: ["dashboard"], queryFn: () => api<DashboardData>("dashboard") });
  if (!query.data) return <State loading={query.isPending} error={query.error} retry={() => query.refetch()} />;
  const d = query.data;
  const postureScore = Math.max(35, 100 - (d.severity.critical || 0) * 15 - (d.severity.high || 0) * 5);
  return <><div className="summary-strip"><span><Activity size={16} /> Operations overview</span><span>{d.events_processed.toLocaleString()} events processed · all-time scope</span></div>
    <div className="posture-widget">
      <div className="posture-gauge">{postureScore}%</div>
      <div className="posture-info">
        <strong>SOC Posture Index & Operational Readiness</strong>
        <p>{(d.severity.critical || 0) > 0 ? "Elevated Alert Status: Critical detections require priority analyst triage" : "Optimal Security Posture: Deterministic detections active across all monitored workloads"}</p>
      </div>
    </div>
    <section className="metric-grid" aria-label="Security overview">{[
      ["Critical alerts", d.severity.critical || 0, "critical", "Require immediate triage", "Alerts"],
      ["High alerts", d.severity.high || 0, "high", "Open high-severity detections", "Alerts"],
      ["Open incidents", d.open_incidents, "accent", "Active investigations", "Incidents"],
      ["Events / second", d.events_per_second, "", "Accepted over the last 60 seconds", "Events"]
    ].map(([label, value, color, detail, target]) => <article className={`metric ${color}`} key={String(label)} onClick={() => navigate(String(target))} style={{ cursor: "pointer" }} title={`View ${label}`}><div><span>{String(label)}</span><Activity size={16} /></div><strong>{String(value)}</strong><p>{String(detail)}</p></article>)}</section>
    <div className="dashboard-grid"><section className="panel detection-chart"><div className="panel-heading"><h2>Detection activity</h2><span className="subtle">Alerts by rule · all time</span></div>{d.top_rules.length ? <div className="chart"><ResponsiveContainer width="100%" height={240}><BarChart data={d.top_rules} margin={{ top: 15, right: 20, left: -15, bottom: 5 }}><defs><linearGradient id="ruleBarGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity={0.9} /><stop offset="100%" stopColor="#2563eb" stopOpacity={0.4} /></linearGradient></defs><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.06)" /><XAxis dataKey="rule_id" tick={{ fill: "var(--muted)", fontSize: 10 }} tickFormatter={value => value.replace("AEGIS-", "")} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "var(--muted)", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: "rgba(56, 189, 248, 0.05)" }} contentStyle={{ background: "rgba(13, 21, 39, 0.95)", backdropFilter: "blur(8px)", borderColor: "rgba(56, 189, 248, 0.2)", borderRadius: 6, color: "var(--text)" }} /><Bar dataKey="count" name="Alerts" fill="url(#ruleBarGrad)" radius={[4, 4, 0, 0]} maxBarSize={34} /></BarChart></ResponsiveContainer></div> : <State empty />}<div className="chart-footer"><span><strong>{d.events.toLocaleString()}</strong> events ingested</span><span><strong>{d.alerts_per_1000_events}</strong> alerts / 1k processed events</span></div></section>
      <section className="panel"><div className="panel-heading"><h2>Alert severity</h2><ShieldAlert size={17} /></div><div className="severity-list">{["critical", "high", "medium", "low", "informational"].map(severity => <div key={severity}><div><Badge value={severity} /><strong>{d.severity[severity] || 0}</strong></div><progress aria-label={`${severity} alerts`} value={d.severity[severity] || 0} max={Math.max(1, ...Object.values(d.severity))} /></div>)}</div><p className="panel-note">Excludes resolved, closed, and false-positive alerts.</p></section></div>
    <section className="panel"><div className="panel-heading"><h2><span className="dot" /> Recent alerts</h2><button className="text-button" onClick={() => navigate("Alerts")}>View all alerts →</button></div>{d.recent_alerts.length ? <DataTable rows={d.recent_alerts} columns={["severity", "title", "risk_score", "status", "created_at"]} onOpen={row => onOpen("alerts", row)} /> : <State empty />}</section>
    <div className="dashboard-grid"><section className="panel"><div className="panel-heading"><h2>Highest-risk entities</h2><button className="text-button" onClick={() => navigate("Entities")}>Explore entities →</button></div>{d.top_entities.length ? <DataTable rows={d.top_entities} columns={["type", "value", "risk_score"]} onOpen={row => onOpen("entities", row)} /> : <State empty />}</section><section className="panel quick-investigation"><FileSearch size={24} /><h2>Follow the evidence</h2><p>Pivot across authentication, process and network telemetry. Every alert links back to the events that triggered it.</p><button onClick={() => navigate("Threat Hunting")}>Open threat hunting <ChevronRight size={14} /></button></section></div>
  </>;
}

function ResourceList({ resource, user, onOpen }: { resource: string; user: User; onOpen: (row: Row) => void }) {
  const [filter, setFilter] = useState(""); const [severity, setSeverity] = useState(""); const [cursor, setCursor] = useState(""); const [create, setCreate] = useState(false);
  useEffect(() => { setCursor(""); setFilter(""); setCreate(false); }, [resource]);
  const query = useQuery({ queryKey: [resource, filter, severity, cursor], queryFn: () => api<Page>(`${resource}?q=${encodeURIComponent(filter)}&severity=${severity}&cursor=${cursor}&limit=50`) });
  const canCreate = user.permissions.includes(({ iocs: "iocs.write", cases: "cases.write", incidents: "incidents.create", rules: "rules.write" } as Record<string, string>)[resource]);
  return <><div className="toolbar"><label className="search-field"><Search size={16} /><input aria-label="Filter resources" placeholder="Filter by name or identifier…" value={filter} onChange={event => { setFilter(event.target.value); setCursor(""); }} /></label>{["alerts", "incidents", "iocs"].includes(resource) && <select aria-label="Severity" value={severity} onChange={event => { setSeverity(event.target.value); setCursor(""); }}><option value="">All severities</option>{["critical", "high", "medium", "low"].map(value => <option key={value}>{value}</option>)}</select>}<button onClick={() => download(`aegis-${resource}.csv`, csv(query.data?.items || []), "text/csv")}><Download size={15} />Export page</button>{canCreate && <button className="primary" onClick={() => setCreate(!create)}>Create {resource === "iocs" ? "indicator" : resource.slice(0, -1)}</button>}</div>
    {create && <ResourceEditor resource={resource} id="new" user={user} onOpen={(_, row) => { setCreate(false); onOpen(row); }} />}
    <section className="panel"><State loading={query.isPending} error={query.error} retry={() => query.refetch()} empty={query.data?.items.length === 0} />{query.data && query.data.items.length > 0 && <DataTable rows={query.data.items} columns={columns[resource]} onOpen={onOpen} />}<div className="pagination"><span>{query.data?.items.length || 0} results on this page</span><div><button disabled={!cursor} onClick={() => setCursor("")}>First page</button><button disabled={!query.data?.next_cursor} onClick={() => setCursor(query.data?.next_cursor || "")}>Next page →</button></div></div></section>
  </>;
}

const scenarioQueries = [
  { label: "Failed Authentication", q: 'event.category = "authentication" AND outcome = "failure"' },
  { label: "PowerShell Telemetry", q: 'event.category = "process" AND process.name = "powershell.exe"' },
  { label: "Web Path Traversal", q: 'event.category = "web" AND http.status = 403' },
  { label: "Network Beaconing", q: 'event.category = "network" AND action = "connect"' },
  { label: "Cloud IAM Events", q: 'event.category = "cloud"' }
];

function Hunting({ onOpen }: { onOpen: (row: Row) => void }) {
  const [text, setText] = useState(""); const [hours, setHours] = useState("24"); const [aggregate, setAggregate] = useState("source_ip");
  const [search, setSearch] = useState<Row | null>(null); const [error, setError] = useState("");
  const [liveTail, setLiveTail] = useState(false);
  const query = useQuery({
    queryKey: ["events-search", search],
    queryFn: () => api<Page>("events/search", "POST", search),
    enabled: !!search,
    refetchInterval: liveTail ? 3000 : false,
  });
  async function run(event?: FormEvent) {
    event?.preventDefault(); setError("");
    try { const parsed = await api<Row>("hunts/parse", "POST", { question: text || " " }); setSearch({ ...parsed, start: new Date(Date.now() - Number(hours) * 3600000).toISOString(), end: new Date().toISOString(), aggregate, limit: 50, cursor: null }); }
    catch (err) { setError((err as Error).message); }
  }
  return <><section className="panel hunt-builder"><div className="panel-heading"><h2><SlidersHorizontal size={17} /> Evidence query</h2><span className="subtle">Validated query language</span></div><form onSubmit={run}><label className="query-input"><Search size={18} /><input id="hunt-query" value={text} onChange={event => setText(event.target.value)} placeholder={'event.category = "authentication" AND outcome = "failure"'} aria-label="Hunting query" /></label><div className="query-chips"><span className="subtle">Quick scenarios:</span>{scenarioQueries.map(chip => <button key={chip.label} type="button" className="query-chip" onClick={() => { setText(chip.q); }}>{chip.label}</button>)}</div><div className="toolbar"><label>Time range<select value={hours} onChange={event => setHours(event.target.value)}><option value="1">Last hour</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option></select></label><label>Aggregate by<select value={aggregate} onChange={event => setAggregate(event.target.value)}>{["source_ip", "host", "username", "event_category", "action"].map(value => <option key={value}>{value}</option>)}</select></label><button className="primary" type="submit">Run query</button><button type="button" disabled={!search} onClick={async () => { const name = window.prompt("Saved search name"); if (name) { try { await api("hunts", "POST", { name, query: search }); } catch (err) { setError((err as Error).message); } } }}>Save search</button></div></form><p className="hint">Use plain text or field = &quot;value&quot; clauses joined with AND. Results are scoped to your organization.</p>{error && <p role="alert" className="error-text">{error}</p>}</section>
    {search ? <><div className="toolbar"><span>{query.data?.total?.toLocaleString() || 0} matching events</span><button type="button" className={`pill-button ${liveTail ? "live" : ""}`} onClick={() => setLiveTail(!liveTail)}><span className={liveTail ? "pulse-dot" : ""} />{liveTail ? "Streaming Tail Active (3s)" : "Stream Live Tail"}</button><button onClick={() => download("aegis-events.json", JSON.stringify(query.data?.items || [], null, 2))}><Download size={15} />Export page</button></div>{query.data?.aggregations && <div className="aggregation-chips">{Object.entries(query.data.aggregations).slice(0, 8).map(([key, count]) => <button key={key} onClick={() => setText(`${aggregate} = ${JSON.stringify(key)}`)}>{key}<strong>{count}</strong></button>)}</div>}<section className="panel"><State loading={query.isPending} error={query.error} retry={() => query.refetch()} empty={query.data?.items.length === 0} />{query.data && <DataTable rows={query.data.items} columns={["timestamp", "event_category", "host", "source_ip", "username", "message"]} onOpen={onOpen} />}<div className="pagination"><span>50 events per page</span><button disabled={!query.data?.next_cursor} onClick={() => setSearch({ ...search, cursor: query.data?.next_cursor })}>Next events →</button></div></section></> : <div className="state"><FileSearch size={32} /><h2>Start with a question</h2><p>Find failed logins, inspect an IP, or follow an entity through your event data.</p><button onClick={() => setText('outcome = "failure"')}>Use failed authentication query</button></div>}
  </>;
}

function Health() {
  const query = useQuery({ queryKey: ["health"], queryFn: () => api<Row>("system/health"), refetchInterval: 30000 });
  return <><State loading={query.isPending} error={query.error} retry={() => query.refetch()} />{query.data && <><div className="toolbar"><Badge value={query.data.status} /><span>Deployment mode: {display(query.data.mode)}</span><button onClick={() => query.refetch()}>Refresh health</button></div><div className="health-grid">{Object.entries(query.data.components as Record<string, string>).map(([component, status]) => <section className="panel health-card" key={component}><Activity size={21} /><h2>{component}</h2><Badge value={status} /></section>)}</div><section className="panel padded"><h2>Queue & integrations</h2><JsonView value={{ queue: query.data.queue, ai: query.data.ai, threat_intelligence: query.data.threat_intelligence }} /></section></>}</>;
}

function Mitre() {
  const query = useQuery({ queryKey: ["mitre"], queryFn: () => api<Page & { catalog: string }>("mitre") });
  const tactics = [...new Set(query.data?.items.map(item => display(item.tactic)) || [])];
  return <><State loading={query.isPending} error={query.error} retry={() => query.refetch()} /><p className="hint">{query.data?.catalog}</p><div className="mitre-matrix">{tactics.map(tactic => <section key={tactic}><h2>{tactic.replaceAll("-", " ")}</h2>{query.data?.items.filter(item => item.tactic === tactic).map(item => <a className="technique" key={item.id} href={display(item.url)} target="_blank" rel="noopener noreferrer"><code>{item.id}</code><strong>{display(item.name)}</strong></a>)}</section>)}</div></>;
}

function SettingsPanel({ user }: { user: User }) {
  const query = useQuery({ queryKey: ["config"], queryFn: () => api<Row>("system/config") });
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<Page>("users"), enabled: user.permissions.includes("users.manage") });
  const [error, setError] = useState("");
  return <><section className="panel padded"><h2>System configuration</h2><p className="hint">Configuration is environment-driven and validated at startup. Secret values are never returned.</p><State loading={query.isPending} error={query.error} retry={() => query.refetch()} />{query.data && <dl className="fields">{Object.entries(query.data).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{display(value)}</dd></div>)}</dl>}</section>{user.permissions.includes("users.manage") && <section className="panel padded"><h2>Users & access</h2><State loading={users.isPending} error={users.error} retry={() => users.refetch()} />{users.data && <DataTable rows={users.data.items} columns={["username", "role", "active"]} />}<h3>Add user</h3><form className="inline-form" onSubmit={async event => { event.preventDefault(); const form = event.currentTarget; const data = Object.fromEntries(new FormData(form)); try { await api("users", "POST", data); form.reset(); users.refetch(); setError(""); } catch (err) { setError((err as Error).message); } }}><label>Username<input name="username" required autoComplete="off" /></label><label>Initial password<input name="password" type="password" minLength={14} required autoComplete="new-password" /></label><label>Role<select name="role">{["VIEWER", "ANALYST", "SENIOR_ANALYST", "SOC_MANAGER", "SECURITY_ADMIN"].map(role => <option key={role}>{role}</option>)}</select></label><button className="primary">Create user</button></form>{error && <p role="alert" className="error-text">{error}</p>}</section>}</>;
}
