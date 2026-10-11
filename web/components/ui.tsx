"use client";
import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { display, Row } from "@/lib/api";
import { strings } from "@/lib/strings";

export function Badge({ value }: { value: unknown }) {
  return <span className={`badge ${String(value).toLowerCase()}`}>{display(value).replaceAll("_", " ")}</span>;
}

export function State({ loading, error, retry, empty }: { loading?: boolean; error?: Error | null; retry?: () => void; empty?: boolean }) {
  if (loading) return <div role="status" className="state"><span className="spinner" />{strings.loading}</div>;
  if (error) return <div role="alert" className="state error"><strong>Unable to load data</strong><p>{error.message}</p><button onClick={retry}>{strings.retry}</button></div>;
  if (empty) return <div className="state"><strong>{strings.empty}</strong><p>{strings.emptyHelp}</p></div>;
  return null;
}

export function DataTable({ rows, columns, onOpen }: { rows: Row[]; columns?: string[]; onOpen?: (row: Row) => void }) {
  const fields = columns || ["severity", "title", "status", "risk_score", "created_at"];
  return <div className="table-wrap"><table><thead><tr>{fields.map(field => <th key={field} scope="col">{field.replaceAll("_", " ")}</th>)}{onOpen && <th scope="col">Details</th>}</tr></thead>
    <tbody>{rows.map((row, i) => <tr key={row.id || String(row.event_id) || i}>{fields.map(field => <td key={field}>
      {["severity", "status"].includes(field) ? <Badge value={row[field]} /> : <span title={display(row[field])} className={field.includes("id") ? "mono" : ""}>{display(row[field])}</span>}
    </td>)}{onOpen && <td><button className="text-button" aria-label={`Open ${row.title || row.id || row.event_id || "event"}`} onClick={() => onOpen(row)}>Investigate ↗</button></td>}</tr>)}</tbody></table></div>;
}

export function JsonView({ value }: { value: unknown }) {
  return <pre className="json-view">{JSON.stringify(value, null, 2)}</pre>;
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };
  return (
    <button
      type="button"
      className={`copy-btn ${copied ? "copied" : ""}`}
      onClick={handleCopy}
      title="Copy to clipboard"
      aria-label={copied ? "Copied to clipboard" : label}
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      <span>{copied ? "Copied!" : label}</span>
    </button>
  );
}

export function RiskMeter({ score }: { score: number | undefined | null }) {
  const numeric = typeof score === "number" ? Math.min(100, Math.max(0, score)) : 0;
  const level = numeric >= 80 ? "critical" : numeric >= 60 ? "high" : numeric >= 40 ? "medium" : "low";
  return (
    <div className={`risk-meter ${level}`}>
      <div className="risk-meter-header">
        <span className="risk-label">EXPLAINABLE RISK</span>
        <span className={`risk-pill ${level}`}>{level.toUpperCase()}</span>
      </div>
      <div className="risk-score-value">
        <strong>{numeric}</strong>
        <span>/ 100</span>
      </div>
      <div className="risk-bar-track">
        <div className={`risk-bar-fill ${level}`} style={{ width: `${numeric}%` }} />
      </div>
    </div>
  );
}

export function Toast({ message, type = "info", onClose }: { message: string; type?: "info" | "success" | "error"; onClose: () => void }) {
  return (
    <div className={`toast-banner toast-${type}`} role="status">
      <span>{message}</span>
      <button className="toast-close" onClick={onClose} aria-label="Close notification">✕</button>
    </div>
  );
}
