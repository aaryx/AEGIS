import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { Intelligence, IntelligenceContext } from "../components/intelligence";
import { api } from "../lib/api";
vi.mock("../lib/api", async original => ({ ...await original<typeof import("../lib/api")>(), api: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
const user = { id: "analyst", username: "analyst", role: "SENIOR_ANALYST", permissions: ["iocs.read", "iocs.write"] };
function mount(id?: string, permissions = user.permissions) {
  const open = vi.fn();
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><Intelligence user={{ ...user, permissions }} id={id} onOpen={open} /></QueryClientProvider>);
  return open;
}
it("submits a bounded observable lookup and opens its persisted detail", async () => {
  vi.mocked(api).mockResolvedValue({ items: [] });
  const open = mount();
  fireEvent.change(screen.getByLabelText("Observable value"), { target: { value: "8.8.8.8" } });
  vi.mocked(api).mockResolvedValueOnce({ observable: { id: "obs-1" }, lookup: { status: "QUEUED" } });
  fireEvent.click(screen.getByText("Enrich observable"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("iocs/enrich", "POST", { observable: { type: "ip", value: "8.8.8.8" }, provider: "virustotal", refresh: false }));
  await waitFor(() => expect(open).toHaveBeenCalledWith("observables", { id: "obs-1" }));
});
it("keeps stale intelligence unknown and shows unavailable provider evidence", async () => {
  vi.mocked(api).mockImplementation(async path => (path === "iocs/providers" ? { items: [{ provider: "virustotal", enabled: false, configured: false, last_status: "NOT_CHECKED" }] } : {
    id: "obs-1", type: "ip", value: "8.8.8.8", external_allowed: true,
    related: { events: ["event-1"], incidents: [], alerts: [], storylines: [] },
    lookups: [{ id: "lookup-1", provider: "virustotal", status: "UNAVAILABLE", stale: true, enriched_at: 100, expires_at: 200,
      assessment: { verdict: "unknown", confidence: null }, result: { reason: "provider_not_configured", evidence: {} } }]
  }) as never);
  const open = mount("obs-1");
  expect(await screen.findByText(/Verdict: unknown; confidence: Not supplied/)).toBeInTheDocument();
  expect(screen.getByText(/stale; not a current assessment/)).toBeInTheDocument();
  fireEvent.click(screen.getByText("event-1"));
  expect(open).toHaveBeenCalledWith("events", { id: "event-1" });
});
it("hides writes for readers and displays loading failure", async () => {
  vi.mocked(api).mockRejectedValue(new Error("Intelligence unavailable"));
  mount(undefined, ["iocs.read"]);
  expect((await screen.findAllByText("Intelligence unavailable")).length).toBeGreaterThan(0);
  expect(screen.queryByText("Enrich observable")).not.toBeInTheDocument();
});
it("requests enrichment from a persisted investigation source", async () => {
  vi.mocked(api).mockResolvedValue({ items: [] });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><IntelligenceContext user={user} sourceType="incident" sourceId="INC-1" onOpen={vi.fn()} /></QueryClientProvider>);
  fireEvent.click(screen.getByText("Enrich source observables"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("iocs/enrich-source", "POST", { source_type: "incident", source_id: "INC-1", provider: "virustotal" }));
});
it("displays empty lookups and allows searching observables", async () => {
  vi.mocked(api).mockImplementation(async (path: string) => {
    if (path.startsWith("iocs/observables?")) return { items: [] } as never;
    if (path === "iocs/providers") return { items: [] } as never;
    return {} as never;
  });
  mount();
  expect(await screen.findByText("Loading provider status...")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Search observed values"), { target: { value: "test.com" } });
  await waitFor(() => expect(api).toHaveBeenCalledWith(expect.stringContaining("q=test.com")));
});
