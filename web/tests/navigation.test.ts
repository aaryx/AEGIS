import { expect, it } from "vitest";
import { pageHash, parseLocation } from "../lib/navigation";
it("round trips pages and evidence deep links", () => {
  expect(parseLocation(pageHash("Detection Rules"))).toEqual({ page: "Detection Rules", selected: null });
  expect(parseLocation("#/alerts/ALT-123")).toEqual({ page: "Alerts", selected: { resource: "alerts", id: "ALT-123" } });
});
it("rejects malformed and unrecognized resource links", () => {
  expect(parseLocation("#/alerts/%E0%A4%A").selected).toBeNull();
  expect(parseLocation("#/unknown/token").selected).toBeNull();
  expect(parseLocation("#/alerts/..%2Fsecret").selected).toBeNull();
});
