// Smoke test for the Sidebar component. Confirms it renders all top-level
// navigation entries — protects against accidentally dropping a route.
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Sidebar from "../Sidebar";

function renderSidebar() {
  return render(
    <MemoryRouter>
      <Sidebar />
    </MemoryRouter>
  );
}

describe("Sidebar", () => {
  it("renders every top-level navigation entry", () => {
    renderSidebar();
    for (const label of [
      "Dashboard",
      "Findings",
      "Attack Paths",
      "Reports",
      "Scan History",
      "Suppressions",
      "API Explorer",
      "Settings",
    ]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });
});
