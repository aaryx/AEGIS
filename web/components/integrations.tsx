"use client";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, display, Page, Row } from "@/lib/api";
import { Badge, DataTable, State } from "./ui";

export function IntegrationsPanel() {
  const client = useQueryClient();
  const integrations = useQuery({ queryKey: ["integrations"], queryFn: () => api<Page>("integrations") });
  const [cursor, setCursor] = useState("");
  const deliveries = useQuery({ queryKey: ["deliveries", cursor], queryFn: () => api<Page>(`deliveries?cursor=${cursor}`) });
  const [error, setError] = useState(""); const [message, setMessage] = useState(""); const [busy, setBusy] = useState(false);
  async function run(operation: () => Promise<unknown>) {
    setError(""); setMessage(""); setBusy(true);
    try { await operation(); await client.invalidateQueries({ queryKey: ["integrations"] }); await client.invalidateQueries({ queryKey: ["deliveries"] }); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  return <section className="panel padded"><h2>Integrations & delivery</h2>
    <p className="hint">HTTPS endpoints require an operator-managed host allowlist. Secrets use environment references. Stored webhook paths are never returned. Delivery is at least once.</p>
    <State loading={integrations.isPending} error={integrations.error} retry={() => integrations.refetch()} />
    {integrations.data?.items.map(row => <article className="note" key={row.id}><div className="toolbar"><strong>{display(row.name)}</strong><Badge value={row.status} /><span>{display(row.kind)} · {display(row.endpoint)}</span>
      {row.kind === "ioc_feed" && <button disabled={busy || !row.enabled} onClick={() => run(async () => { const result = await api<Row>(`integrations/${row.id}/sync`, "POST"); setMessage(`Validated feed: ${result.added} added, ${result.received} received.`); })}>Sync indicators</button>}</div>
      <p className="hint">Revision {display(row.revision)} · Last success: {row.last_success ? new Date(Number(row.last_success) * 1000).toLocaleString() : "None"}</p></article>)}
    <h3>Configure integration</h3><form onSubmit={event => {
      event.preventDefault(); const form = event.currentTarget; const values = Object.fromEntries(new FormData(form));
      run(async () => { await api("integrations/new", "PUT", { ...values, secret_env: values.secret_env || null }); form.reset(); setMessage("Integration saved."); });
    }}><div className="inline-form"><label>Name<input name="name" maxLength={100} required /></label><label>Provider<select name="kind"><option value="webhook">Signed webhook</option><option value="slack">Slack webhook</option><option value="teams">Teams adaptive card webhook</option><option value="ioc_feed">JSON IOC feed</option></select></label></div>
      <label>HTTPS endpoint<input name="endpoint" type="url" required autoComplete="off" /></label><label>Secret environment reference<input name="secret_env" pattern="AEGIS_INTEGRATION_[A-Z0-9_]+" placeholder="AEGIS_INTEGRATION_SOC_WEBHOOK" autoComplete="off" /></label><button className="primary" disabled={busy}>Save integration</button></form>
    {error && <p role="alert" className="error-text">{error}</p>}{message && <p role="status">{message}</p>}
    <h3>Notification delivery queue</h3><State loading={deliveries.isPending} error={deliveries.error} retry={() => deliveries.refetch()} empty={deliveries.data?.items.length === 0} />
    {deliveries.data && <DataTable rows={deliveries.data.items} columns={["notification_id", "state", "attempts", "last_error", "delivered_at"]} />}
    {deliveries.data?.items.filter(row => row.state === "DEAD").map(row => <button key={row.id} disabled={busy} onClick={() => run(() => api(`deliveries/${row.id}/retry`, "POST"))}>Retry delivery {row.id?.slice(0, 8)}</button>)}
    <div className="pagination"><button disabled={!cursor} onClick={() => setCursor("")}>First page</button><button disabled={!deliveries.data?.next_cursor} onClick={() => setCursor(deliveries.data?.next_cursor || "")}>Next deliveries</button></div>
  </section>;
}
