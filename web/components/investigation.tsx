"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, FileText, GitBranch, ShieldAlert } from "lucide-react";
import { api, display, download, Row, User } from "@/lib/api";
import { Badge, CopyButton, DataTable, JsonView, RiskMeter, State } from "./ui";

type InvestigationData = { resource: Row; kind: string; evidence: { hash: string; event: Row }[]; entities: Row[]; relationships: Row[]; alerts: Row[]; related_alerts: Row[]; incidents: Row[]; iocs: Row[]; mitre_techniques: string[]; notes: Row[]; activity: Row[] };

function EntityGraph({
  entities,
  relationships,
  rootTitle,
  rootKind,
  onOpen,
}: {
  entities: Row[];
  relationships: Row[];
  rootTitle: string;
  rootKind: string;
  onOpen: (resource: string, row: Row) => void;
}) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>("ALL");

  const filteredEntities =
    filterType === "ALL"
      ? entities
      : entities.filter(e => String(e.type).toUpperCase() === filterType);

  const cx = 380;
  const cy = 180;
  const rx = Math.min(300, Math.max(180, filteredEntities.length * 28));
  const ry = Math.min(130, Math.max(90, filteredEntities.length * 15));

  const nodePositions = filteredEntities.map((entity, i) => {
    const angle = (2 * Math.PI * i) / (filteredEntities.length || 1) - Math.PI / 2;
    return {
      entity,
      id: String(entity.id),
      x: cx + rx * Math.cos(angle),
      y: cy + ry * Math.sin(angle),
    };
  });

  const posMap = new Map(nodePositions.map(p => [p.id, p]));

  function getColor(type: string) {
    switch (String(type).toLowerCase()) {
      case "host":
        return "#00e5ff";
      case "user":
        return "#ffb300";
      case "ip":
        return "#b388ff";
      case "process":
        return "#00e676";
      case "domain":
      case "url":
        return "#ff7043";
      default:
        return "#38bdf8";
    }
  }

  const types = ["ALL", ...new Set(entities.map(e => String(e.type).toUpperCase()))];

  return (
    <div className="entity-graph-container">
      <div className="entity-graph-toolbar">
        <div className="graph-filter-chips">
          {types.map(t => (
            <button
              key={t}
              type="button"
              className={`filter-chip ${filterType === t ? "active" : ""}`}
              onClick={() => setFilterType(t)}
            >
              {t}{" "}
              {t === "ALL"
                ? `(${entities.length})`
                : `(${entities.filter(e => String(e.type).toUpperCase() === t).length})`}
            </button>
          ))}
        </div>
        <div className="graph-legend">
          <span style={{ color: "#00e5ff" }}>● Host</span>
          <span style={{ color: "#ffb300" }}>● User</span>
          <span style={{ color: "#b388ff" }}>● IP</span>
          <span style={{ color: "#00e676" }}>● Process</span>
        </div>
      </div>

      <svg viewBox="0 0 760 360" className="entity-graph-svg" aria-label="Entity relationship graph">
        <defs>
          <radialGradient id="root-grad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#0284c7" stopOpacity="0.4" />
          </radialGradient>
        </defs>

        <rect width="100%" height="100%" fill="none" rx="8" stroke="rgba(255, 255, 255, 0.05)" />

        {nodePositions.map(p => {
          const isHovered = hoveredNode === p.id;
          return (
            <line
              key={`root-${p.id}`}
              x1={cx}
              y1={cy}
              x2={p.x}
              y2={p.y}
              stroke={isHovered ? getColor(String(p.entity.type)) : "rgba(148, 163, 184, 0.22)"}
              strokeWidth={isHovered ? 2 : 1}
              strokeDasharray={isHovered ? "none" : "3 3"}
            />
          );
        })}

        {relationships.map((rel, idx) => {
          const source = posMap.get(String(rel.source_id));
          const target = posMap.get(String(rel.target_id));
          if (!source || !target) return null;
          const isHighlighted = hoveredNode === source.id || hoveredNode === target.id;
          const midX = (source.x + target.x) / 2;
          const midY = (source.y + target.y) / 2;
          return (
            <g key={`rel-${idx}`}>
              <line
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={isHighlighted ? "#38bdf8" : "rgba(56, 189, 248, 0.45)"}
                strokeWidth={isHighlighted ? 2.5 : 1.5}
              />
              <text
                x={midX}
                y={midY - 4}
                textAnchor="middle"
                fill="rgba(203, 213, 225, 0.7)"
                fontSize="9"
                fontFamily="var(--font-mono)"
              >
                {String(rel.relation || "observed_with")}
              </text>
            </g>
          );
        })}

        <g className="graph-node-root">
          <circle cx={cx} cy={cy} r={28} fill="url(#root-grad)" stroke="#38bdf8" strokeWidth={2} />
          <text x={cx} y={cy - 4} textAnchor="middle" fill="#ffffff" fontSize="10" fontWeight="bold">
            {rootKind === "alerts" ? "ALERT" : "INCIDENT"}
          </text>
          <text x={cx} y={cy + 9} textAnchor="middle" fill="#cbd5e1" fontSize="8" fontFamily="var(--font-mono)">
            {rootTitle.length > 20 ? rootTitle.slice(0, 18) + "…" : rootTitle}
          </text>
        </g>

        {nodePositions.map(p => {
          const color = getColor(String(p.entity.type));
          const isHovered = hoveredNode === p.id;
          const risk = Number(p.entity.risk_score || 0);
          const hasRisk = risk >= 50;

          return (
            <g
              key={p.id}
              className="graph-node-entity"
              style={{ cursor: "pointer" }}
              onMouseEnter={() => setHoveredNode(p.id)}
              onMouseLeave={() => setHoveredNode(null)}
              onClick={() => onOpen("entities", p.entity)}
            >
              {hasRisk && (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={isHovered ? 26 : 22}
                  fill="none"
                  stroke={risk >= 75 ? "#f43f5e" : "#f59e0b"}
                  strokeWidth={1.5}
                  strokeDasharray="2 2"
                  opacity={0.8}
                />
              )}
              <circle
                cx={p.x}
                cy={p.y}
                r={isHovered ? 20 : 17}
                fill="#0d1527"
                stroke={color}
                strokeWidth={isHovered ? 2.5 : 1.5}
              />
              <text
                x={p.x}
                y={p.y + 4}
                textAnchor="middle"
                fill={color}
                fontSize="10"
                fontWeight="bold"
                fontFamily="var(--font-mono)"
              >
                {String(p.entity.type).slice(0, 1).toUpperCase()}
              </text>
              <text
                x={p.x}
                y={p.y + 28}
                textAnchor="middle"
                fill="#f1f5f9"
                fontSize="10"
                fontWeight="500"
                fontFamily="var(--font-mono)"
              >
                {String(p.entity.value).length > 18
                  ? String(p.entity.value).slice(0, 16) + "…"
                  : String(p.entity.value)}
              </text>
              <text
                x={p.x}
                y={p.y + 40}
                textAnchor="middle"
                fill={risk > 50 ? "#fda4af" : "#94a3b8"}
                fontSize="9"
              >
                {String(p.entity.type)} · {risk}%
              </text>
            </g>
          );
        })}
      </svg>
      {hoveredNode && posMap.has(hoveredNode) && (
        <div className="entity-hover-card">
          <strong>{String(posMap.get(hoveredNode)?.entity.value)}</strong>
          <span>Type: {String(posMap.get(hoveredNode)?.entity.type)}</span>
          <span>Risk: {String(posMap.get(hoveredNode)?.entity.risk_score || 0)}/100</span>
          <span className="hint">Click to inspect entity profile ↗</span>
        </div>
      )}
    </div>
  );
}

export function Investigation({ id, user, onOpen }: { id: string; user: User; onOpen: (resource: string, row: Row) => void }) {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ["investigation", id], queryFn: () => api<InvestigationData>(`investigations/${id}`) });
  const [tab, setTab] = useState("Overview"); const [error, setError] = useState(""); const [analysis, setAnalysis] = useState<Row | null>(null); const [busy, setBusy] = useState(false);
  const [entityViewMode, setEntityViewMode] = useState<"graph" | "table">("graph");
  async function action(operation: () => Promise<unknown>) {
    setError(""); setBusy(true);
    try { await operation(); await client.invalidateQueries(); } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  if (!query.data) return <State loading={query.isPending} error={query.error} retry={() => query.refetch()} />;
  const d = query.data, resource = d.resource, alert = d.alerts[0];
  const statuses = d.kind === "alerts" ? ["NEW", "ACKNOWLEDGED", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE", "CLOSED"] : ["OPEN", "TRIAGED", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "RESOLVED", "CLOSED"];
  const canUpdate = user.permissions.includes(d.kind + ".update");
  return <><section className="panel investigation-summary"><div><div className="eyebrow">{d.kind === "alerts" ? "DETECTION SIGNAL" : "SECURITY INCIDENT"}</div><h2>{resource.title}</h2><div className="tags"><Badge value={resource.severity} /><Badge value={resource.status} />{d.mitre_techniques.map(technique => <span className="tag mono" key={technique}>{technique}</span>)}</div></div><RiskMeter score={typeof alert?.risk_score === "number" ? alert.risk_score : 0} /></section>
    <div className="toolbar">{canUpdate && <label>Status<select aria-label="Update status" value={resource.status} disabled={busy} onChange={event => { const status = event.target.value; const resolution = ["RESOLVED", "CLOSED"].includes(status) && d.kind === "incidents" ? window.prompt("Resolution notes") : ""; if (resolution === null) return; action(() => api(`${d.kind}/${id}/status`, "PATCH", { status, revision: resource.revision, assignee: resource.assignee, resolution })); }}>{statuses.map(status => <option key={status}>{status}</option>)}</select></label>}
      {d.kind === "alerts" && user.permissions.includes("incidents.create") && <button onClick={() => action(async () => { const result = await api<Row>("incidents", "POST", { title: resource.title, severity: resource.severity, alert_ids: [id] }); onOpen("incidents", result); })}>Create incident</button>}
      {d.kind === "incidents" && user.permissions.includes("reports.create") && <button onClick={() => action(async () => { const result = await api<Row>(`reports/${id}`, "POST"); download(`${result.id}.json`, JSON.stringify(result, null, 2)); })}><FileText size={15} />Generate report</button>}
      <button onClick={() => download(`${id}-evidence.json`, JSON.stringify(d, null, 2))}>Export investigation</button>
    </div>{error && <p role="alert" className="error-text">{error}</p>}
    <div role="tablist" aria-label="Investigation sections" className="tabs">{["Overview", "Evidence", "Timeline", "Entities", "Related alerts", "Intelligence", "Notes", "AI Analysis", "Response", "Activity"].map(name => <button key={name} role="tab" aria-selected={tab === name} onClick={() => setTab(name)}>{name}</button>)}</div>
    <section className="panel padded" role="tabpanel" aria-label={tab}>
      {tab === "Overview" && <><h2><ShieldAlert size={18} /> Why this detection fired</h2>{d.alerts.map(item => <article className="explanation" key={item.id}><h3>{item.title}</h3><p>{display((item.explanation as Row)?.why)}</p><dl className="fields"><div><dt>Rule</dt><dd className="mono">{display(item.rule_id)} · v{display(item.rule_version)}</dd></div><div><dt>Matched evidence</dt><dd>{display(item.event_count)} events</dd></div><div><dt>Confidence</dt><dd>{display(item.confidence)}%</dd></div></dl><h4>Risk contributions</h4><div className="risk-factors">{Object.entries((item.risk_factors || {}) as Row).map(([factor, value]) => <div key={factor}><span>{factor.replaceAll("_", " ")}</span><strong>+{display(value)}</strong></div>)}</div><details><summary>Detection conditions and matched fields</summary><JsonView value={item.explanation} /></details></article>)}<h3>Associated incidents</h3>{d.incidents.length ? <DataTable rows={d.incidents} columns={["title", "severity", "status"]} onOpen={row => onOpen("incidents", row)} /> : <p className="hint">No incident attached. Create one when the signal merits investigation.</p>}</>}
      {tab === "Evidence" && <><h2>Source evidence</h2><p className="hint">Original and normalized representations are preserved. SHA-256 hashes identify the original evidence. First 500 events shown.</p>{d.evidence.map(item => <details key={String(item.event.event_id)} className="evidence"><summary><Badge value={item.event.event_category} /><span className="mono">{display(item.event.timestamp)}</span><span>{display(item.event.message).slice(0, 120)}</span></summary><div className="evidence-body"><p className="mono hash">SHA-256 {item.hash} <CopyButton text={item.hash} label="Copy Hash" /></p><button onClick={() => onOpen("events", item.event)}>Open event & pivots</button><h4>Original evidence</h4><JsonView value={item.event.raw_event} /><h4>Normalized event</h4><JsonView value={item.event} /></div></details>)}</>}
      {tab === "Timeline" && <ol className="timeline">{d.evidence.map(item => <li key={String(item.event.event_id)}><time>{display(item.event.timestamp)}</time><div><Badge value={item.event.event_category} /><strong>{display(item.event.action)}</strong><p>{display(item.event.message)}</p><button className="text-button" onClick={() => onOpen("events", item.event)}>Inspect evidence →</button></div></li>)}</ol>}
      {tab === "Entities" && <>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <h2><GitBranch size={18} /> Evidence-backed relationships ({d.entities.length})</h2>
          <div style={{ display: "flex", gap: 6 }}>
            <button type="button" className={`pill-button ${entityViewMode === "graph" ? "live" : ""}`} onClick={() => setEntityViewMode("graph")}>Visual Graph</button>
            <button type="button" className={`pill-button ${entityViewMode === "table" ? "live" : ""}`} onClick={() => setEntityViewMode("table")}>Relationship Table</button>
          </div>
        </div>
        {entityViewMode === "graph" ? (
          <EntityGraph
            entities={d.entities}
            relationships={d.relationships}
            rootTitle={String(resource.title || "Investigation")}
            rootKind={d.kind}
            onOpen={onOpen}
          />
        ) : (
          <>
            <DataTable rows={d.entities} columns={["type", "value", "risk_score"]} onOpen={row => onOpen("entities", row)} />
            <div className="relationship-list">
              {d.relationships.slice(0, 40).map(edge => (
                <div key={edge.id}>
                  <button onClick={() => onOpen("entities", { id: String(edge.source_id) })}>
                    {display(d.entities.find(entity => entity.id === edge.source_id)?.value)}
                  </button>
                  <span>— {display(edge.relation || "observed with")} →</span>
                  <button onClick={() => onOpen("entities", { id: String(edge.target_id) })}>
                    {display(d.entities.find(entity => entity.id === edge.target_id)?.value)}
                  </button>
                  <button className="text-button" onClick={() => onOpen("events", { id: String(edge.event_id) })}>
                    Evidence ↗
                  </button>
                </div>
              ))}
            </div>
          </>
        )}
      </>}
      {tab === "Related alerts" && <><DataTable rows={d.related_alerts} columns={["severity", "title", "risk_score", "status"]} onOpen={row => onOpen("alerts", row)} /><State empty={!d.related_alerts.length} /></>}
      {tab === "Intelligence" && <><h2>Threat intelligence matches</h2><DataTable rows={d.iocs} columns={["type", "value", "source", "confidence", "severity"]} onOpen={row => onOpen("iocs", row)} /><State empty={!d.iocs.length} /><h3>MITRE ATT&CK</h3><div className="tags">{d.mitre_techniques.map(value => <a key={value} className="tag mono" href={`https://attack.mitre.org/techniques/${value.replace(".", "/")}/`} target="_blank" rel="noopener noreferrer">{value} ↗</a>)}</div></>}
      {tab === "Notes" && <><h2>Analyst findings</h2>{d.notes.map(note => <article className="note" key={note.id}><div className="subtle">{display(note.author)} · {display(note.created_at)}</div><p>{display(note.text)}</p></article>)}{canUpdate && <form onSubmit={event => { event.preventDefault(); const form = event.currentTarget; const data = new FormData(form); action(async () => { await api(`${d.kind}/${id}/notes`, "POST", { text: data.get("text") }); form.reset(); }); }}><label>Add a note<textarea name="text" rows={4} required maxLength={10000} placeholder="Record observed evidence, hypotheses and investigation findings…" /></label><button className="primary" disabled={busy}>Add note</button></form>}</>}
      {tab === "AI Analysis" && <><h2><Bot size={18} /> Advisory investigation assistant</h2><p className="hint">Observed, inferred, possible, and unknown findings are distinguished. External providers receive minimized evidence. Generated content requires analyst verification.</p><button className="primary" disabled={busy || !user.permissions.includes("ai.use")} onClick={() => action(async () => setAnalysis(await api<Row>(`investigations/${id}/ai`, "POST")))}>{busy ? "Analyzing evidence…" : "Analyze evidence"}</button>{analysis && <div className="analysis"><p className="eyebrow">{display(analysis.provider)} · {analysis.generated ? "AI-GENERATED" : "DETERMINISTIC EVIDENCE SUMMARY"}</p>{(analysis.claims as Row[]).map((claim, index) => <article className="note" key={index}><Badge value={claim.category} /><p>{display(claim.text)}</p><div className="tags">{(claim.event_ids as string[]).map(eventId => <button key={eventId} className="tag mono" onClick={() => onOpen("events", { id: eventId })}>{eventId.slice(0, 12)} ↗</button>)}</div></article>)}<h3>Recommended investigation</h3><ul>{(analysis.recommended_steps as string[]).map(step => <li key={step}>{step}</li>)}</ul><JsonView value={{ suggested_queries: analysis.suggested_queries, limitations: analysis.limitations }} /></div>}</>}
      {tab === "Response" && <><h2>Controlled response & Endpoint Containment</h2><p>High-impact requests require independent human approval. Active endpoint agents enforce live host containment and verify cryptographic HMAC execution receipts.</p>{user.permissions.includes("playbooks.execute") && <form className="inline-form" onSubmit={event => { event.preventDefault(); const data = new FormData(event.currentTarget); action(async () => { const result = await api<Row>("playbooks/request", "POST", { action: data.get("action"), target: data.get("target") }); onOpen("playbooks", result); }); }}><label>Action<select name="action"><option value="isolate_host">Enforce host isolation (Containment)</option><option value="unisolate_host">Restore host network (Unisolate)</option><option value="terminate_process">Terminate offending process</option><option value="disable_account">Record account disable policy</option><option value="block_ioc">Record IOC blocking policy</option><option value="gather_evidence">Gather evidence</option><option value="notify_analyst">Notify analyst</option></select></label><label>Target ID<input name="target" defaultValue={id} required /></label><button className="primary">Request response</button></form>}<p className="hint">Host isolation and un-isolation targets require a host entity ID. Gather/notify targets accept this alert or incident ID.</p></>}
      {tab === "Activity" && <DataTable rows={d.activity} columns={["created_at", "actor", "action", "result"]} />}
    </section>
  </>;
}

