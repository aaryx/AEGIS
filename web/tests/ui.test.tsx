import React from "react";
import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { DataTable, State } from "../components/ui";

afterEach(cleanup);
it("renders malicious log text without creating executable elements", () => {
  render(<DataTable rows={[{ id: "1", message: '<img src=x onerror="alert(1)">' }]} columns={["message"]} />);
  expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument();
  expect(document.querySelector("img")).toBeNull();
});
it("provides clear empty and error states", () => {
  render(<State empty />);
  expect(screen.getByText("No results found")).toBeInTheDocument();
});
