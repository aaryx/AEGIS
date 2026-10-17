import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@testing-library/jest-dom/vitest";
import { Playbooks } from "../components/playbooks";
import { api } from "../lib/api";

vi.mock("../lib/api", async original => ({ ...await original<typeof import("../lib/api")>(), api: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
const permissions = ["playbooks.read", "playbooks.write", "playbooks.execute", "playbooks.approve", "incidents.update"];
function mount(perms = permissions) {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <Playbooks user={{ id: "manager", username: "manager", role: "SOC_MANAGER", permissions: perms }} />
  </QueryClientProvider>);
}
function mock(status = "WAITING_FOR_APPROVAL", requester = "analyst") {
  const run = { id: "run-1", status, dry_run: true, source_type: "incident", source_id: "incident-1",
    requested_by: requester, version: 1, attempts: 1, deadline: Date.now() / 1000 + 300,
    history: [{ step: "enrich", status: "FAILED", error: "action_failed", completed_at: 100 }] };
  vi.mocked(api).mockImplementation(async (path, method) => {
    if (path === "soar/executions/run-1") return run as never;
    if (path.startsWith("soar/executions?")) return { items: [run] } as never;
    if (method === "POST") return {} as never;
    return { items: [] } as never;
  });
}
it("shows persisted timeline, dry run and independent approval controls", async () => {
  mock(); mount();
  fireEvent.click(await screen.findByText("run-1"));
  expect(await screen.findByText("action_failed")).toBeInTheDocument();
  expect(screen.getAllByText(/DRY RUN/).length).toBeGreaterThan(0);
  fireEvent.click(screen.getByText("Approve pending action"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("soar/executions/run-1/decision", "POST", { decision: "approve" }));
});
it("hides self-approval and unauthorized mutation controls", async () => {
  mock("WAITING_FOR_APPROVAL", "manager"); mount(["playbooks.read"]);
  fireEvent.click(await screen.findByText("run-1"));
  await screen.findByText("Execution timeline");
  expect(screen.queryByText("Approve pending action")).not.toBeInTheDocument();
  expect(screen.queryByText("Save version")).not.toBeInTheDocument();
  expect(screen.queryByText("Cancel execution")).not.toBeInTheDocument();
});
it("sends approval filter and reports validation errors", async () => {
  mock(); mount();
  fireEvent.click(screen.getByLabelText("Pending approval queue"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("soar/executions?offset=0&status=WAITING_FOR_APPROVAL"));
  vi.mocked(api).mockRejectedValueOnce(new Error("Invalid forward branch"));
  fireEvent.click(screen.getByText("Validate"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Invalid forward branch");
});
it("offers bounded retry for a failed step and never shows success prematurely", async () => {
  mock("FAILED"); mount();
  fireEvent.click(await screen.findByText("run-1"));
  fireEvent.click(await screen.findByText("Retry failed step"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("soar/executions/run-1/decision", "POST", { decision: "retry" }));
  expect(screen.queryByText("SUCCEEDED")).not.toBeInTheDocument();
});
it("keeps cancellation unavailable for terminal executions", async () => {
  mock("CANCELLED"); mount();
  fireEvent.click(await screen.findByText("run-1"));
  await screen.findByText("Execution timeline");
  expect(screen.queryByText("Cancel execution")).not.toBeInTheDocument();
});
it("allows saving a new playbook version", async () => {
  mock(); mount();
  fireEvent.change(screen.getByLabelText("Playbook name"), { target: { value: "New Playbook" } });
  vi.mocked(api).mockResolvedValueOnce({ id: "pb-new", name: "New Playbook", version: 1, enabled: true });
  fireEvent.click(screen.getByText("Save version"));
  await waitFor(() => expect(api).toHaveBeenCalledWith("soar/playbooks", "POST", expect.objectContaining({ name: "New Playbook" })));
});
it("displays empty states when no playbooks or executions are returned", async () => {
  vi.mocked(api).mockResolvedValue({ items: [] });
  mount();
  expect(await screen.findByText("No playbooks yet.")).toBeInTheDocument();
  expect(await screen.findByText("No executions in this view.")).toBeInTheDocument();
});
