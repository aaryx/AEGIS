"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, display, Row, User } from "@/lib/api";
import { Badge, DataTable, State } from "./ui";

type Story = Row & { incident_id: string; window_seconds: number; summary: {
  confidence: number; risk_score: number; first_seen: string; last_seen: string;
  risk_factors: Record<string, number>; timeline: Row[]; mitre_techniques: string[];
}; members?: { alert_id: string; reasons: { type: string; value: string; distance_seconds: number }[] }[] };

export function Storylines({ user, id, onOpen }: { user: User; id?: string; onOpen: (resource: string, row: Row) => void }) {
  const client = useQueryClient();
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [offset, setOffset] = useState(0);
  const [windowSeconds, setWindowSeconds] = useState(1800);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const list = useQuery({ queryKey: ["storylines", status, severity, offset], enabled: !id,
    queryFn: () => api<{ items: Story[]; next_offset: number | null }>(`storylines?status=${status}&severity=${severity}&offset=${offset}`) });
  const detail = useQuery({ queryKey: ["storyline", id], enabled: Boolean(id), queryFn: () => api<Story>(`storylines/${id}`) });
  async function correlate() {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await api<{ changed: number; unassigned_alerts: number }>(`storylines/correlate?window_seconds=${windowSeconds}`, "POST");
      setMessage(`${result.changed} storylines updated; ${result.unassigned_alerts} alerts have no eligible correlation.`);
      await client.invalidateQueries();
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  if (id) {
    if (!detail.data) return <State loading={detail.isPending} error={detail.error} retry={() => detail.refetch()} />;
    const story = detail.data;
    return <section className="panel padded"><h2>Attack storyline</h2>
      <p>{story.summary.first_seen} — {story.summary.last_seen}</p>
      <p>Confidence: {story.summary.confidence}/100 (evidence strength) · Risk: {story.summary.risk_score}/100 · Window: {story.window_seconds}s</p>
      <p>Risk factors: {Object.entries(story.summary.risk_factors).map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`).join("; ")}</p>
      <div className="tags">{story.summary.mitre_techniques.map(t => <span className="tag mono" key={t}>{t}</span>)}</div>
      <button onClick={() => onOpen("incidents", { id: story.incident_id })}>Investigate incident</button>
      <h3>Detection timeline and correlation evidence</h3>
      {story.summary.timeline.map(item => <article key={String(item.alert_id)} className="panel padded">
        <p>{display(item.timestamp)} · <Badge value={String(item.severity)} /> {display(item.rule_name)}</p>
        <button onClick={() => onOpen("alerts", { id: String(item.alert_id) })}>Open detection evidence</button>
        {story.members?.find(m => m.alert_id === item.alert_id)?.reasons.map((reason, i) =>
          <p key={i}>Shared {reason.type}: {reason.value}; {reason.distance_seconds}s from anchor.</p>)}
        {story.members?.find(m => m.alert_id === item.alert_id)?.reasons.length === 0 && <p>Anchor detection for this storyline.</p>}
      </article>)}
    </section>;
  }
  return <>
    <section className="panel padded"><p>Group persisted detections by shared host, identity, or IP and a bounded time window.</p>
      {user.permissions.includes("incidents.create") && <div className="toolbar">
        <label>Correlation window (seconds)<input aria-label="Correlation window (seconds)" type="number" min={1} max={86400} value={windowSeconds} onChange={e => setWindowSeconds(Number(e.target.value))} /></label>
        <button disabled={busy || windowSeconds < 1 || windowSeconds > 86400} onClick={correlate}>{busy ? "Correlating…" : "Correlate alerts"}</button>
      </div>}
      {message && <p role="status">{message}</p>}{error && <p role="alert">{error}</p>}
      <div className="toolbar"><label>Status<select aria-label="Storyline status" value={status} onChange={e => { setStatus(e.target.value); setOffset(0); }}>
        {["", "OPEN", "TRIAGED", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "RESOLVED", "CLOSED"].map(s => <option value={s} key={s}>{s || "All statuses"}</option>)}
      </select></label><label>Severity<select aria-label="Storyline severity" value={severity} onChange={e => { setSeverity(e.target.value); setOffset(0); }}>
        {["", "low", "medium", "high", "critical"].map(s => <option value={s} key={s}>{s || "All severities"}</option>)}
      </select></label></div>
    </section>
    {!list.data ? <State loading={list.isPending} error={list.error} retry={() => list.refetch()} /> : list.data.items.length === 0 ? <p>No correlated storylines. Ingest detections and run correlation.</p> :
      <DataTable rows={list.data.items.map(s => ({ ...s, confidence: s.summary.confidence, risk_score: s.summary.risk_score }))} columns={["title", "severity", "status", "confidence", "risk_score"]} onOpen={row => onOpen("storylines", row)} />}
    <div className="toolbar"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</button>
      <button disabled={list.data?.next_offset == null} onClick={() => setOffset(list.data?.next_offset ?? offset)}>Next</button></div>
  </>;
}
