"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, Row, User } from "@/lib/api";
import { DataTable, JsonView, State } from "./ui";

type Detail = Row & { profile_id: string; explanation: string; recommendation: string; evidence: (Row & { available: boolean; event_id: string })[]; related: Record<string, string[]> };
type Props = { user: User; id?: string; onOpen: (resource: string, row: Row) => void };

export function Ueba({ user, id, onOpen }: Props) {
  const cache = useQueryClient();
  const [entity, setEntity] = useState(""); const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState(""); const [detector, setDetector] = useState("");
  const [since, setSince] = useState(""); const [until, setUntil] = useState(""); const [offset, setOffset] = useState(0);
  const [profile, setProfile] = useState(""); const [evidenceOffset, setEvidenceOffset] = useState(0);
  const [date, setDate] = useState(new Date().toISOString().slice(0, 10));
  const [reason, setReason] = useState(""); const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(""); const [error, setError] = useState("");
  const params = new URLSearchParams({ entity, detector, offset: String(offset) });
  if (status) params.set("status", status); if (severity) params.set("severity", severity);
  if (since) params.set("since", `${since}T00:00:00Z`); if (until) params.set("until", `${until}T23:59:59Z`);
  const list = useQuery({ queryKey: ["ueba", "findings", params.toString()], enabled: !id,
    queryFn: () => api<{ items: Row[] }>(`ueba/findings?${params}`) });
  const profiles = useQuery({ queryKey: ["ueba", "profiles", entity], enabled: !id,
    queryFn: () => api<{ items: Row[] }>(`ueba/profiles?entity=${encodeURIComponent(entity)}`) });
  const summary = useQuery({ queryKey: ["ueba", "summary"], queryFn: () => api<{ profiles: number; active_findings_by_severity: Record<string, number> }>("ueba/summary") });
  const detectors = useQuery({ queryKey: ["ueba", "detectors"], queryFn: () => api<{ items: Row[]; config: Row }>("ueba/detectors") });
  const jobs = useQuery({ queryKey: ["ueba", "jobs"], refetchInterval: 5000, queryFn: () => api<{ items: Row[] }>("ueba/jobs") });
  const detail = useQuery({ queryKey: ["ueba", id, evidenceOffset], enabled: Boolean(id),
    queryFn: () => api<Detail>(`ueba/findings/${id}?offset=${evidenceOffset}`) });
  const profileDetail = useQuery({ queryKey: ["ueba", "profile", profile], enabled: Boolean(profile),
    queryFn: () => api<Row>(`ueba/profiles/${profile}`) });
  async function mutate(path: string, body: Row) {
    setBusy(true); setError(""); setMessage("");
    try { const result = await api<Row>(path, "POST", body); setMessage(`Saved: ${String(result.state || result.status)}. Analysis jobs run in the worker.`);
      await cache.invalidateQueries({ queryKey: ["ueba"] });
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel padded"><h2>Behavioral risk intelligence</h2>
    <p>Explainable deviations from prior activity. Priority scores are not probabilities of compromise. Cold-start entities produce no findings.</p>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <State error={summary.error} loading={summary.isPending} retry={() => summary.refetch()} />
    {summary.data && <><p>{summary.data.profiles} behavioral profiles</p><h3>Active finding risk distribution</h3>
      {Object.entries(summary.data.active_findings_by_severity).map(([level, count]) => <div key={level}>{level}: {count} <meter aria-label={`${level} findings`} min={0} max={Math.max(1, ...Object.values(summary.data.active_findings_by_severity))} value={count} /></div>)}</>}
    {user.permissions.includes("ueba.execute") && <div className="toolbar"><label>Window end (UTC, exclusive)<input type="date" value={date} onChange={e => setDate(e.target.value)} /></label>
      <button disabled={busy || !date} onClick={() => mutate("ueba/analyze", { window_end: `${date}T00:00:00Z`, refresh_only: false })}>Analyze previous day</button>
      <button disabled={busy || !date} onClick={() => mutate("ueba/analyze", { window_end: `${date}T00:00:00Z`, refresh_only: true })}>Refresh baseline</button></div>}
    {!id && <><div className="toolbar"><label>Entity<input value={entity} onChange={e => { setEntity(e.target.value); setOffset(0); }} /></label>
      {[["Status", status, setStatus, ["NEW", "ACKNOWLEDGED", "RESOLVED", "SUPPRESSED"]], ["Severity", severity, setSeverity, ["low", "medium", "high", "critical"]], ["Detector", detector, setDetector, detectors.data?.items.map(r => String(r.id)) || []]].map(([label, value, setter, values]) => <label key={String(label)}>{String(label)}<select value={String(value)} onChange={e => { (setter as (v: string) => void)(e.target.value); setOffset(0); }}><option value="">All</option>{(values as string[]).map(v => <option key={v}>{v}</option>)}</select></label>)}
      <label>Since<input type="date" value={since} onChange={e => { setSince(e.target.value); setOffset(0); }} /></label><label>Until<input type="date" value={until} onChange={e => { setUntil(e.target.value); setOffset(0); }} /></label></div>
      <h3>Recent anomalies</h3><State loading={list.isPending} error={list.error} empty={list.data?.items.length === 0} retry={() => list.refetch()} />
      {list.data && <DataTable rows={list.data.items} columns={["entity", "detector", "risk_score", "confidence", "severity", "status", "repeated", "last_seen"]} onOpen={r => onOpen("ueba", r)} />}
      <button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous findings</button><button disabled={(list.data?.items.length || 0) < 50} onClick={() => setOffset(offset + 50)}>Next findings</button>
      <h3>Highest-risk entities (up to 50)</h3><State loading={profiles.isPending} error={profiles.error} empty={profiles.data?.items.length === 0} retry={() => profiles.refetch()} />
      {profiles.data && <DataTable rows={profiles.data.items} columns={["entity_type", "entity", "risk_score", "window_end"]} onOpen={r => setProfile(String(r.id))} />}</>}
    {id && <><State loading={detail.isPending} error={detail.error} retry={() => detail.refetch()} />{detail.data && <>
      <h3>{String(detail.data.detector)} · {String(detail.data.risk_score)}/100 · {String(detail.data.status)}</h3><p>{detail.data.explanation}</p><p>{detail.data.recommendation}</p>
      <JsonView value={detail.data.comparison} /><button onClick={() => setProfile(detail.data!.profile_id)}>View entity profile</button>
      {user.permissions.includes("ueba.update") && <div className="toolbar"><label>Decision reason<input value={reason} maxLength={500} onChange={e => setReason(e.target.value)} /></label>
        {["ACKNOWLEDGED", "RESOLVED", "SUPPRESSED", "NEW"].map(s => <button key={s} disabled={busy || reason.trim().length < 3} onClick={() => mutate(`ueba/findings/${id}/status`, { status: s, reason })}>{s}</button>)}</div>}
      <h3>Evidence references</h3>{detail.data.evidence.map(r => <p key={r.event_id}>{r.available ? <button onClick={() => onOpen("events", { id: r.event_id })}>{r.event_id}</button> : `${r.event_id} — event retained as hash only`} <code>{String(r.evidence_hash)}</code></p>)}
      <button disabled={!evidenceOffset} onClick={() => setEvidenceOffset(Math.max(0, evidenceOffset - 50))}>Previous evidence</button><button disabled={detail.data.evidence.length < 50} onClick={() => setEvidenceOffset(evidenceOffset + 50)}>Next evidence</button>
      <h3>Related investigations</h3>{Object.entries(detail.data.related).map(([resource, ids]) => <div key={resource}>{resource}: {ids.length ? ids.map(identifier => <button key={identifier} onClick={() => onOpen(resource, { id: identifier })}>{identifier}</button>) : "None"}</div>)}<JsonView value={detail.data.lifecycle} />
    </>}</>}
    {profile && <><h3>Entity baseline and risk history</h3><button onClick={() => setProfile("")}>Close profile</button><State loading={profileDetail.isPending} error={profileDetail.error} retry={() => profileDetail.refetch()} />{profileDetail.data && <JsonView value={profileDetail.data} />}</>}
    <details><summary>Detector configuration</summary><State error={detectors.error} loading={detectors.isPending} retry={() => detectors.refetch()} />{detectors.data && <JsonView value={detectors.data} />}</details>
    <details><summary>Recent analysis jobs</summary><State error={jobs.error} loading={jobs.isPending} retry={() => jobs.refetch()} />{jobs.data && <DataTable rows={jobs.data.items} columns={["window_end", "state", "attempts", "result"]} />}</details>
  </section>;
}

export function UebaContext({ kind, id, onOpen }: { kind: string; id: string; onOpen: Props["onOpen"] }) {
  const data = useQuery({ queryKey: ["ueba", "context", kind, id], queryFn: () => api<{ items: Row[] }>(`ueba/context/${kind}/${id}`) });
  return <section><h3>Behavioral findings</h3><State loading={data.isPending} error={data.error} empty={data.data?.items.length === 0} retry={() => data.refetch()} />
    {data.data && <DataTable rows={data.data.items} columns={["detector", "risk_score", "confidence", "status"]} onOpen={r => onOpen("ueba", r)} />}</section>;
}
