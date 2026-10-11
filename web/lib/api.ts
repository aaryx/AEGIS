export type Row = Record<string, unknown> & { id?: string; title?: string; status?: string; severity?: string };
export type Page = { items: Row[]; next_cursor?: string | null; total?: number; aggregations?: Record<string, number> };
export type User = { id: string; username: string; role: string; permissions: string[] };

export function csrfToken(cookie: string): string {
  return decodeURIComponent(cookie.split("; ").find(item => item.startsWith("aegis_csrf="))?.slice(11) || "");
}

export async function api<T = Row>(path: string, method = "GET", body?: unknown): Promise<T> {
  const response = await fetch(`/api/v1/${path}`, {
    method, credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken(document.cookie), "Idempotency-Key": crypto.randomUUID() },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message || `Request failed (${response.status})`);
  return data;
}

export function display(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function csv(rows: Row[]): string {
  if (!rows.length) return "";
  const keys = Object.keys(rows[0]);
  const escape = (value: unknown) => {
    let text = display(value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    return `"${text.replaceAll('"', '""')}"`;
  };
  return [keys.map(escape).join(","), ...rows.map(row => keys.map(key => escape(row[key])).join(","))].join("\r\n");
}

export function download(name: string, content: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url);
}
