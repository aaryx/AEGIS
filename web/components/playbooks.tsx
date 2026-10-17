"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, User } from "@/lib/api";

type Book = { id: string; name: string; version: number; enabled: boolean; versions?: { version: number; document: Record<string, unknown> }[] };
type Run = { id: string; playbook_id: string; version: number; status: string; source_id: string; source_type: string;
  dry_run: boolean; attempts: number; deadline: number; requested_by: string;
  history: { step: string; status: string; attempt?: number; started_at?: number; completed_at?: number; error?: string; output?: unknown }[] };
const example = { description: "Review an incident using AEGIS data", trigger: { source: "incident" },
  steps: [{ id: "enrich", action: "enrich" }, { id: "summary", action: "summary" }] };
const active = ["QUEUED", "RUNNING", "WAITING_FOR_APPROVAL"];

export function Playbooks({ user }: { user: User }) {
  const cache = useQueryClient();
  const [selected, setSelected] = useState("");
  const [execution, setExecution] = useState("");
  const [name, setName] = useState("");
  const [definition, setDefinition] = useState(JSON.stringify(example, null, 2));
  const [expectedVersion, setExpectedVersion] = useState(0);
  const [enabled, setEnabled] = useState(false);
  const [sourceType, setSourceType] = useState("incident");
  const [source, setSource] = useState("");
  const [inputs, setInputs] = useState("{}");
  const [dryRun, setDryRun] = useState(true);
  const [pendingOnly, setPendingOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [bookOffset, setBookOffset] = useState(0);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const books = useQuery({ queryKey: ["soar-books", bookOffset], queryFn: () => api<{ items: Book[] }>(`soar/playbooks?offset=${bookOffset}`) });
  const book = useQuery({ queryKey: ["soar-book", selected], enabled: Boolean(selected), queryFn: () => api<Book>(`soar/playbooks/${selected}`) });
  const runs = useQuery({ queryKey: ["soar-runs", pendingOnly, offset], refetchInterval: 3000,
    queryFn: () => api<{ items: Run[] }>(`soar/executions?offset=${offset}${pendingOnly ? "&status=WAITING_FOR_APPROVAL" : ""}`) });
  const run = useQuery({ queryKey: ["soar-run", execution], enabled: Boolean(execution), refetchInterval: 3000,
    queryFn: () => api<Run>(`soar/executions/${execution}`) });
  async function act(fn: () => Promise<void>) {
    setBusy(true); setError(""); setMessage("");
    try { await fn(); await cache.invalidateQueries({ queryKey: ["soar-books"] });
      await cache.invalidateQueries({ queryKey: ["soar-book"] });
      await cache.invalidateQueries({ queryKey: ["soar-runs"] }); await cache.invalidateQueries({ queryKey: ["soar-run"] });
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  }
  function decision(value: string) {
    return act(async () => { await api(`soar/executions/${execution}/decision`, "POST", { decision: value }); setMessage(`Decision recorded: ${value}`); });
  }
  const canExecute = user.permissions.includes("playbooks.execute") && user.permissions.includes("incidents.update");
  return <>
    <section className="panel padded"><h2>Playbook library</h2><p>Versioned workflows with durable execution. Containment actions are simulations only.</p>
      {books.isPending && <p>Loading playbooks…</p>}{books.error && <p role="alert">{books.error.message}</p>}
      {books.data?.items.length === 0 && <p>No playbooks yet.</p>}
      {books.data?.items.map(b => <p key={b.id}><button onClick={() => setSelected(b.id)}>{b.name}</button> · Version {b.version} · {b.enabled ? "Enabled" : "Disabled"}</p>)}
      <button disabled={!bookOffset} onClick={() => setBookOffset(Math.max(0, bookOffset - 50))}>Previous playbooks</button>
      <button disabled={(books.data?.items.length ?? 0) < 50} onClick={() => setBookOffset(bookOffset + 50)}>Next playbooks</button>
      {book.error && <p role="alert">{book.error.message}</p>}
      {book.data && <><h3>{book.data.name}</h3>{book.data.versions?.map(v => <details key={v.version}><summary>Version {v.version}</summary><pre>{JSON.stringify(v.document, null, 2)}</pre></details>)}
        {user.permissions.includes("playbooks.write") && <button onClick={() => { setName(book.data!.name); setExpectedVersion(book.data!.version); setEnabled(book.data!.enabled); setDefinition(JSON.stringify(book.data!.versions?.[0].document, null, 2)); }}>Edit as new version</button>}
      </>}
    </section>
    {user.permissions.includes("playbooks.write") && <section className="panel padded"><h2>Create or version a playbook</h2>
      <label>Name<input aria-label="Playbook name" value={name} onChange={e => setName(e.target.value)} /></label>
      <p>Expected current version: {expectedVersion} (0 creates a new name)</p>
      <label>Definition JSON<textarea aria-label="Definition JSON" rows={12} value={definition} onChange={e => { setDefinition(e.target.value); setMessage(""); }} /></label>
      <label><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Enabled after validation</label>
      <button disabled={busy} onClick={() => act(async () => { await api("soar/validate", "POST", JSON.parse(definition)); setMessage("Definition is valid."); })}>Validate</button>
      <button disabled={busy || !name} onClick={() => act(async () => { const b = await api<Book>("soar/playbooks", "POST", { name, definition: JSON.parse(definition), enabled, expected_version: expectedVersion }); setSelected(b.id); setExpectedVersion(b.version); setMessage(`Saved version ${b.version}.`); })}>Save version</button>
      <button onClick={() => { setName(""); setExpectedVersion(0); }}>New playbook</button>
    </section>}
    {canExecute && <section className="panel padded"><h2>Trigger selected playbook</h2>
      <label>Source type<select aria-label="Source type" value={sourceType} onChange={e => setSourceType(e.target.value)}>{["incident", "alert", "storyline"].map(s => <option key={s}>{s}</option>)}</select></label>
      <label>Source ID<input aria-label="Source ID" value={source} onChange={e => setSource(e.target.value)} /></label>
      <label>Input references JSON<input aria-label="Input references JSON" value={inputs} onChange={e => setInputs(e.target.value)} /></label>
      <label><input type="checkbox" checked={dryRun} onChange={e => setDryRun(e.target.checked)} />Dry run (no incident notes written)</label>
      <p>{dryRun ? "DRY RUN" : "Local changes enabled; containment simulations require independent approval."}</p>
      <button disabled={busy || !selected || !source || !book.data?.enabled} onClick={() => act(async () => {
        const r = await api<Run>(`soar/playbooks/${selected}/execute`, "POST", { source_type: sourceType, source_id: source, inputs: JSON.parse(inputs), dry_run: dryRun, idempotency_key: crypto.randomUUID() });
        setExecution(r.id); setMessage(`Execution ${r.status}.`);
      })}>Queue execution</button>
    </section>}
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <section className="panel padded"><h2>Execution history</h2>
      <label><input type="checkbox" checked={pendingOnly} onChange={e => { setPendingOnly(e.target.checked); setOffset(0); }} />Pending approval queue</label>
      {runs.isPending && <p>Loading executions…</p>}{runs.error && <p role="alert">{runs.error.message}</p>}
      {runs.data?.items.length === 0 && <p>No executions in this view.</p>}
      {runs.data?.items.map(r => <p key={r.id}><button onClick={() => setExecution(r.id)}>{r.id}</button> · {r.status} · {r.dry_run ? "DRY RUN" : "Local actions / containment simulation"} · Version {r.version}</p>)}
      <button disabled={!offset} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous executions</button>
      <button disabled={(runs.data?.items.length ?? 0) < 50} onClick={() => setOffset(offset + 50)}>Next executions</button>
    </section>
    {run.error && <p role="alert">{run.error.message}</p>}
    {run.data && <section className="panel padded"><h2>Execution timeline</h2><p>{run.data.status} · {run.data.dry_run ? "DRY RUN" : "Local actions / containment simulation"}</p><p>{run.data.source_type}: {run.data.source_id}</p>
      {run.data.history.map((step, i) => <article key={i}><h3>{step.step} · {step.status}</h3><p>Attempt {step.attempt ?? "—"} · {step.completed_at ? new Date(step.completed_at * 1000).toISOString() : "Pending"}</p>{step.error && <p role="alert">{step.error}</p>}{step.output != null && <pre>{JSON.stringify(step.output, null, 2)}</pre>}</article>)}
      {run.data.status === "WAITING_FOR_APPROVAL" && <p>Current action is waiting for independent human approval.</p>}
      {run.data.status === "WAITING_FOR_APPROVAL" && user.permissions.includes("playbooks.approve") && run.data.requested_by !== user.id && <><button disabled={busy} onClick={() => decision("approve")}>Approve pending action</button><button disabled={busy} onClick={() => decision("reject")}>Reject pending action</button></>}
      {canExecute && active.includes(run.data.status) && <button disabled={busy} onClick={() => decision("cancel")}>Cancel execution</button>}
      {canExecute && run.data.status === "FAILED" && run.data.attempts < 4 && run.data.deadline * 1000 > Date.now() && <button disabled={busy} onClick={() => decision("retry")}>Retry failed step</button>}
    </section>}
  </>;
}
