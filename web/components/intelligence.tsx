"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, display, Row, User } from "@/lib/api";
import { DataTable, State } from "./ui";

type Lookup = Row & { id: string; provider: string; status: string; enriched_at: number | null; expires_at: number; stale: boolean; assessment: Row; result: Row };
type Observable = Row & { id: string; type: string; value: string; external_allowed: boolean; lookups: Lookup[]; related: Record<string, string[]> };
const stamp = (value: number | null) => value ? new Date(value * 1000).toISOString() : "Not enriched";

export function Intelligence({ user, id, onOpen }: { user: User; id?: string; onOpen: (resource: string, row: Row) => void }) {
  const client = useQueryClient();
  const [type, setType] = useState("ip"); const [value, setValue] = useState("");
  const [provider, setProvider] = useState("virustotal"); const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState(""); const [busy, setBusy] = useState(false);
  const [error, setError] = useState(""); const [message, setMessage] = useState(""); const [historyId, setHistoryId] = useState("");
  const providers = useQuery({ queryKey: ["intel-providers"], queryFn: () => api<{ items: Row[] }>("iocs/providers") });
  const list = useQuery({ queryKey: ["intel-observables", offset, query], enabled: !id,
    queryFn: () => api<{ items: Row[] }>(`iocs/observables?offset=${offset}&q=${encodeURIComponent(query)}`) });
  const detail = useQuery({ queryKey: ["intel-observable", id], enabled: Boolean(id), refetchInterval: 3000,
    queryFn: () => api<Observable>(`iocs/observables/${id}`) });
  const history = useQuery({ queryKey: ["intel-history", historyId], enabled: Boolean(historyId),
    queryFn: () => api<{ items: Row[] }>(`iocs/enrichments/${historyId}/history`) });
  async function lookup(refresh = false) {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await api<{ observable: Observable; lookup: Lookup }>("iocs/enrich", "POST", {
        observable: { type: detail.data?.type ?? type, value: detail.data?.value ?? value }, provider, refresh });
      setMessage(`Lookup status: ${result.lookup.status}. Unknown does not mean clean.`);
      await client.invalidateQueries({ queryKey: ["intel-observables"] });
      await client.invalidateQueries({ queryKey: ["intel-observable"] });
      onOpen("observables", { id: result.observable.id });
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel padded"><h2>Observable intelligence</h2>
    <p>Provider evidence supports investigation. It does not establish that an alert is malicious. Mock results are test fixtures.</p>
    {providers.error && <p role="alert">{providers.error.message}</p>}
    {providers.isPending && <p>Loading provider status...</p>}
    {providers.data?.items.map(p => <p key={String(p.provider)}>{display(p.provider)}: {p.enabled && p.configured ? "Configured" : "Unavailable / not configured"}; last tenant lookup: {display(p.last_status)}</p>)}
    {user.permissions.includes("iocs.write") && <div className="toolbar">
      {!id && <><label>Observable type<select aria-label="Observable type" value={type} onChange={e => setType(e.target.value)}>{["ip", "domain", "url", "md5", "sha1", "sha256"].map(t => <option key={t}>{t}</option>)}</select></label>
        <label>Observable value<input aria-label="Observable value" value={value} maxLength={2048} onChange={e => setValue(e.target.value)} /></label></>}
      <label>Provider<select aria-label="Intelligence provider" value={provider} onChange={e => setProvider(e.target.value)}><option value="virustotal">VirusTotal</option><option value="mock">Mock (test data)</option></select></label>
      <button disabled={busy || (id ? !detail.data : !value)} onClick={() => lookup()}>Enrich observable</button>
      {id && <button disabled={busy || !detail.data} onClick={() => lookup(true)}>Request refresh</button>}
    </div>}
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {!id && <><label>Search observed values<input aria-label="Search observed values" value={query} onChange={e => { setQuery(e.target.value); setOffset(0); }} /></label>
      {!list.data ? <State loading={list.isPending} error={list.error} retry={() => list.refetch()} /> : <><DataTable rows={list.data.items} columns={["type", "value", "last_seen", "external_allowed"]} onOpen={row => onOpen("observables", row)} /><State empty={!list.data.items.length} /></>}
      <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous observations</button><button disabled={(list.data?.items.length ?? 0) < 50} onClick={() => setOffset(offset + 50)}>Next observations</button></>}
    {id && !detail.data && <State loading={detail.isPending} error={detail.error} retry={() => detail.refetch()} />}
    {detail.data && <><h3>{detail.data.type}: {detail.data.value}</h3><p>{detail.data.external_allowed ? "Eligible for configured external providers" : "External lookup suppressed by privacy/address policy"}</p>
      {!detail.data.lookups.length && <p>No enrichment requested. Verdict unknown.</p>}
      {detail.data.lookups.map(r => <article key={r.id}><h3>{r.provider} - {r.status}</h3>
        <p>Verdict: {display(r.assessment.verdict)}; confidence: {r.assessment.confidence == null ? "Not supplied" : display(r.assessment.confidence)}; origin: {display(r.assessment.assessment_origin)}</p>
        <p>Enriched: {stamp(r.enriched_at)}; expires: {stamp(r.expires_at)}{r.stale ? " (stale; not a current assessment)" : ""}</p>
        <p>Reason: {display(r.result.reason ?? r.assessment.reason)}</p><pre>{JSON.stringify(r.result.evidence ?? {}, null, 2)}</pre>
        <p>Provider reference: {display(r.result.provider_reference)}</p><button onClick={() => setHistoryId(r.id)}>Lookup history</button>
      </article>)}
      <h3>Related evidence and investigations (up to 100 per type)</h3>
      {Object.entries(detail.data.related).map(([resource, ids]) => <div key={resource}><h4>{resource}</h4>{ids.length ? ids.map(identifier => <button key={identifier} onClick={() => onOpen(resource, { id: identifier })}>{identifier}</button>) : <p>No related {resource}.</p>}</div>)}
    </>}
    {historyId && <><h3>Recent lookup history</h3>{history.error && <p role="alert">{history.error.message}</p>}{history.isPending && <p>Loading history...</p>}{history.data?.items.map(r => <article key={r.id}><p>{display(r.created_at)} - {display(r.status)}</p><pre>{JSON.stringify(r.result, null, 2)}</pre></article>)}</>}
  </section>;
}

export function IntelligenceContext({ user, sourceType, sourceId, onOpen }: { user: User; sourceType: string; sourceId: string; onOpen: (resource: string, row: Row) => void }) {
  const client = useQueryClient(); const [error, setError] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  const [provider, setProvider] = useState("virustotal");
  const context = useQuery({ queryKey: ["intel-context", sourceType, sourceId], refetchInterval: 5000,
    queryFn: () => api<{ items: Row[] }>(`iocs/source-context/${sourceType}/${sourceId}`) });
  async function enrich() {
    setBusy(true); setError(""); setMessage("");
    try { const response = await api<{ items: Row[] }>("iocs/enrich-source", "POST", { source_type: sourceType, source_id: sourceId, provider });
      setMessage(`${response.items.length} observable lookups requested or reused.`); await client.invalidateQueries({ queryKey: ["intel-context"] });
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  return <section><h3>Enrichment context</h3><p>Provider claims are advisory; missing or stale intelligence remains unknown.</p>
    {user.permissions.includes("iocs.write") && <><label>Provider<select aria-label="Source enrichment provider" value={provider} onChange={e => setProvider(e.target.value)}><option value="virustotal">VirusTotal</option><option value="mock">Mock (test data)</option></select></label><button disabled={busy} onClick={enrich}>Enrich source observables</button></>}
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    {!context.data ? <State loading={context.isPending} error={context.error} retry={() => context.refetch()} /> : <><DataTable rows={context.data.items} columns={["type", "value", "provider", "status", "verdict", "confidence", "assessment_origin"]} onOpen={row => onOpen("observables", { id: String(row.observable_id) })} /><State empty={!context.data.items.length} /></>}
  </section>;
}
