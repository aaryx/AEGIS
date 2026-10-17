import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { Ueba } from "../components/ueba";
import { api } from "../lib/api";
vi.mock("../lib/api", async original => ({ ...await original<typeof import("../lib/api")>(), api: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
function mount(id?: string, permissions = ["ueba.read", "ueba.execute", "ueba.update"]) {
  const open = vi.fn();
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Ueba user={{ id: "a", username: "a", role: "ANALYST", permissions }} id={id} onOpen={open} /></QueryClientProvider>);
  return open;
}
function defaults(path: string) {
  if (path === "ueba/summary") return { profiles: 3, active_findings_by_severity: { high: 2 } };
  if (path.startsWith("ueba/findings/f")) return { id: "f", profile_id: "p", detector: "failure_burst", risk_score: 65, status: "NEW", explanation: "Failure count increased", comparison: {}, lifecycle: [], recommendation: "Review logs", evidence: [{ event_id: "event-1", evidence_hash: "hash", available: true }], related: { storylines: ["story-1"] } };
  return { items: [], config: {} };
}
it("shows actual summary, empty state, and submits bounded analysis", async () => {
  vi.mocked(api).mockImplementation(async (path, method) => (method === "POST" ? { state: "PENDING" } : defaults(path)) as never);
  mount();
  expect(await screen.findByText("3 behavioral profiles")).toBeInTheDocument();
  expect(screen.getByLabelText("high findings")).toHaveAttribute("value", "2");
  fireEvent.click(screen.getByText("Analyze previous day"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("ueba/analyze", "POST", expect.objectContaining({ refresh_only: false })));
});
it("shows evidence, navigates to existing storylines, and records analyst decisions", async () => {
  vi.mocked(api).mockImplementation(async path => defaults(path) as never);
  const open = mount("f");
  fireEvent.click(await screen.findByText("event-1"));
  expect(open).toHaveBeenCalledWith("events", { id: "event-1" });
  fireEvent.click(screen.getByText("story-1"));
  expect(open).toHaveBeenCalledWith("storylines", { id: "story-1" });
  fireEvent.change(screen.getByLabelText("Decision reason"), { target: { value: "Reviewed logs" } });
  fireEvent.click(screen.getByText("ACKNOWLEDGED"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("ueba/findings/f/status", "POST", { status: "ACKNOWLEDGED", reason: "Reviewed logs" }));
});
it("shows API failures and hides writes for read-only users", async () => {
  vi.mocked(api).mockRejectedValue(new Error("UEBA unavailable"));
  mount(undefined, ["ueba.read"]);
  expect((await screen.findAllByText("UEBA unavailable")).length).toBeGreaterThan(0);
  expect(screen.queryByText("Analyze previous day")).not.toBeInTheDocument();
});
it("passes filters to the API", async () => {
  vi.mocked(api).mockImplementation(async path => defaults(path) as never);
  mount();
  fireEvent.change(screen.getByLabelText("Entity"), { target: { value: "alice" } });
  fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
  await waitFor(() => expect(api).toHaveBeenCalledWith(expect.stringContaining("entity=alice&detector=&offset=0&severity=high")));
});
