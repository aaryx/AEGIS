import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { Storylines } from "../components/storylines";
import { api } from "../lib/api";

vi.mock("../lib/api", async importOriginal => ({ ...await importOriginal<typeof import("../lib/api")>(), api: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
const user = { id: "analyst", username: "analyst", role: "ANALYST", permissions: ["incidents.create"] };
function mount(id?: string, permissions = user.permissions) {
  const onOpen = vi.fn();
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <Storylines user={{ ...user, permissions }} id={id} onOpen={onOpen} />
  </QueryClientProvider>);
  return onOpen;
}

it("loads backend data, correlates and reports completion", async () => {
  vi.mocked(api).mockResolvedValueOnce({ items: [], next_offset: null })
    .mockResolvedValueOnce({ changed: 1, unassigned_alerts: 2 })
    .mockResolvedValue({ items: [], next_offset: null });
  mount();
  expect(await screen.findByText(/No correlated storylines/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Correlation window (seconds)"), { target: { value: "600" } });
  fireEvent.click(screen.getByText("Correlate alerts"));
  expect(await screen.findByRole("status")).toHaveTextContent("1 storylines updated");
  expect(api).toHaveBeenCalledWith("storylines/correlate?window_seconds=600", "POST");
});

it("reports API errors and hides unauthorized actions", async () => {
  vi.mocked(api).mockRejectedValue(new Error("Service unavailable"));
  mount(undefined, []);
  expect(await screen.findByText("Service unavailable")).toBeInTheDocument();
  expect(screen.queryByText("Correlate alerts")).not.toBeInTheDocument();
});

it("renders correlation evidence safely and opens the persisted incident", async () => {
  vi.mocked(api).mockResolvedValue({ id: "STL-1", incident_id: "INC-1", window_seconds: 1800,
    summary: { confidence: 55, risk_score: 72, first_seen: "2026-01-01", last_seen: "2026-01-01",
      risk_factors: { severity: 70 }, mitre_techniques: ["T1110"],
      timeline: [{ alert_id: "ALT-1", timestamp: "2026-01-01", severity: "high", rule_name: "Test rule" }] },
    members: [{ alert_id: "ALT-1", reasons: [{ type: "host", value: "<img src=x onerror=alert(1)>", distance_seconds: 12 }] }] });
  const open = mount("STL-1");
  expect(await screen.findByText(/Shared host:/)).toHaveTextContent("<img src=x onerror=alert(1)>");
  expect(document.querySelector("img")).toBeNull();
  fireEvent.click(screen.getByText("Investigate incident"));
  expect(open).toHaveBeenCalledWith("incidents", { id: "INC-1" });
});

it("sends filters to the server", async () => {
  vi.mocked(api).mockResolvedValue({ items: [], next_offset: null });
  mount();
  fireEvent.change(screen.getByLabelText("Storyline status"), { target: { value: "RESOLVED" } });
  await waitFor(() => expect(api).toHaveBeenCalledWith("storylines?status=RESOLVED&severity=&offset=0"));
});
