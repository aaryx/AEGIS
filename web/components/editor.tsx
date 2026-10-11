"use client";
import { FormEvent, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, display, Row, User } from "@/lib/api";
import { Badge, DataTable, JsonView, State } from "./ui";

const starter = {
  id: "AEGIS-CUSTOM-001", name: "Custom authentication rule",
  description: "Detect failed authentication activity requiring analyst review.",
  selection: [{ field: "event_category", op: "eq", value: "authentication" }, { field: "outcome", op: "eq", value: "failure" }],
  condition: { type: "threshold", count: 10, window_seconds: 300, group_by: ["source_ip"] },
  severity: "high", confidence: 80, mitre_techniques: ["T1110"]
};

export function ResourceEditor({ resource, id, user, onOpen }: {
  resource: string; id: string; user: User; onOpen: (resource: string, row: Row) => void
}) {
  const query = useQuery({ queryKey: [resource, id], queryFn: () => api<Row>(`${resource}/${id}`), enabled: id !== "new" });
  const client = useQueryClient();
  const [error, setError] = useState("");
  const [result, setResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState(false);
  async function run(operation: () => Promise<unknown>) {
    setBusy(true); setError("");
    try { await operation(); client.invalidateQueries(); }
    catch (err) { setError((err as Error).message); }
    finally { setBusy(false); }
  }
  function formData(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); return Object.fromEntries(new FormData(event.currentTarget));
  }
  if (id !== "new" && !query.data) return <State loading={query.isPending} error={query.error} retry={() => query.refetch()} />;
  const data = query.data;
  let content;
  if (resource === "rules") {
    content = <form key={id + String(data?.version)} onSubmit={event => {
      const form = formData(event);
      run(async () => {
        const document = JSON.parse(String(form.document));
        const saved = await api<Row>(`rules/${document.id}`, "PUT", { document, summary: form.summary, version: data?.version || 0, enabled: form.enabled === "on" });
        onOpen("rules", saved);
      });
    }}>
      <div className="toolbar"><span>Version {display(data?.version || 0)}</span><label><input type="checkbox" name="enabled" defaultChecked={data?.enabled !== false} /> Enabled</label><Badge value={data?.enabled === false ? "disabled" : "active"} /></div>
      <label>Rule document (JSON)<textarea className="code-editor" name="document" rows={24} defaultValue={JSON.stringify(data?.document || starter, null, 2)} required spellCheck={false} /></label>
      <label>Change summary<input name="summary" minLength={10} maxLength={500} placeholder="Explain this rule change and its expected impact" required /></label>
      <div className="toolbar">
        <button type="button" onClick={event => {
          const form = event.currentTarget.form!;
          run(async () => setResult(await api<Row>("rules/validate", "POST", JSON.parse(String(new FormData(form).get("document"))))));
        }}>Validate</button>
        <button type="button" onClick={event => {
          const form = event.currentTarget.form!;
          const samples = window.prompt("Paste an array of EventInput objects to test");
          if (samples) run(async () => setResult(await api<Row>("rules/test", "POST", { document: JSON.parse(String(new FormData(form).get("document"))), events: JSON.parse(samples) })));
        }}>Test against events</button>
        <button className="primary" disabled={busy || !user.permissions.includes("rules.write")}>Save version</button>
      </div>{result && <JsonView value={result} />}
    </form>;
  } else if (id === "new") {
    content = <form onSubmit={event => {
      const form = formData(event);
      run(async () => onOpen(resource, await api<Row>(resource, "POST", form)));
    }}>
      {resource === "iocs" ? <>
        <label>Indicator type<select name="type">{["ip", "domain", "url", "hash", "email", "hostname"].map(type => <option key={type}>{type}</option>)}</select></label>
        <label>Value<input name="value" required /></label><label>Source<input name="source" defaultValue="analyst" required /></label>
        <label>Description<textarea name="description" rows={3} /></label>
      </> : <label>Title<input name="title" required minLength={5} /></label>}
      {resource !== "cases" && <label>Severity<select name="severity">{["high", "critical", "medium", "low"].map(level => <option key={level}>{level}</option>)}</select></label>}
      <button className="primary" disabled={busy}>Create</button>
    </form>;
  } else if (resource === "events") {
    content = <><h3>Normalized event</h3><div className="tags">
      {["source_ip", "destination_ip", "host", "username"].map(field => {
        const value = (data?.event as Row)?.[field];
        return value ? <button key={field} onClick={() => run(async () => {
          setResult(await api<Row>("events/search", "POST", { filters: [{ field, value }], limit: 50 }));
        })}>{field}: {display(value)} ↗</button> : null;
      })}
    </div><JsonView value={data} />{result && <><h3>Related events</h3><DataTable rows={result.items as Row[]} columns={["timestamp", "event_category", "host", "message"]} onOpen={row => onOpen("events", row)} /></>}</>;
  } else if (resource === "entities") {
    content = <><JsonView value={data?.resource} /><h3>Related entities</h3>
      <DataTable rows={(data?.entities || []) as Row[]} columns={["type", "value", "risk_score"]} onOpen={row => onOpen("entities", row)} />
      <h3>Recent related events</h3><DataTable rows={(data?.events || []) as Row[]} columns={["timestamp", "event_category", "message"]} onOpen={row => onOpen("events", row)} /></>;
  } else if (resource === "playbooks") {
    content = <><JsonView value={data} /><div className="toolbar">
      {user.permissions.includes("playbooks.approve") && data?.status === "APPROVAL_REQUIRED" && <button className="primary" disabled={busy} onClick={() => run(() => api(`playbooks/${id}/approve`, "POST"))}>Approve request</button>}
      {user.permissions.includes("playbooks.execute") && ["REQUESTED", "APPROVED"].includes(String(data?.status)) && <button className="primary" disabled={busy} onClick={() => run(() => api(`playbooks/${id}/execute`, "POST"))}>Execute approved action</button>}
    </div></>;
  } else if (resource === "reports") {
    content = <><a className="button primary" href={`/api/v1/reports/${id}/html`}>Download printable HTML report</a><JsonView value={data} /></>;
  } else if (resource === "cases") {
    content = <><JsonView value={data} />{user.permissions.includes("cases.write") && <>
      <form onSubmit={event => { const form = formData(event); run(() => api(`cases/${id}/evidence`, "POST", form)); }}>
        <h3>Attach evidence</h3><label>Resource type<select name="resource_type"><option>events</option><option>alerts</option><option>entities</option></select></label>
        <label>Resource ID<input name="resource_id" required /></label><button>Attach evidence</button>
      </form>
      <form onSubmit={event => { const form = formData(event); run(() => api(`cases/${id}/notes`, "POST", form)); }}>
        <label>Analyst note<textarea name="text" required /></label><button>Add note</button>
      </form>
    </>}</>;
  } else content = <JsonView value={data} />;
  return <section className="panel padded"><h2>{resource === "rules" ? "Detection rule editor" : id === "new" ? "Create resource" : "Evidence & resource details"}</h2>{error && <p role="alert" className="error-text">{error}</p>}{content}</section>;
}
