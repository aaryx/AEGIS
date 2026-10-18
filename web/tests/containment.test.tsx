import { render, screen, cleanup } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { DataTable } from "../components/ui";

afterEach(cleanup);

it.each(["REQUESTED", "APPROVED", "DISPATCHED", "SIMULATED", "ENFORCED", "FAILED", "UNKNOWN", "RELEASED"])(
  "renders API containment status %s without interpreting VERIFIED as enforcement", (status) => {
    render(<DataTable rows={[{ id: "legacy", status: "VERIFIED", containment_status: status }]} columns={["status"]} />);
    expect(screen.getByText(status)).toBeTruthy();
    expect(screen.queryByText("VERIFIED")).toBeNull();
  }
);
