// Smoke test for the AttackPathGraph component. Confirms the SVG renders
// for both empty and populated event streams without throwing — exercising
// the layout/state-machine code that derives node colour from events.
import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import AttackPathGraph from "../AttackPathGraph";

describe("AttackPathGraph", () => {
  it("renders an SVG for an empty event list", () => {
    const { container } = render(<AttackPathGraph events={[]} />);
    const svg = container.querySelector("svg");
    expect(svg).not.toBeNull();
  });

  it("renders without crashing for a populated event stream", () => {
    const events = [
      { type: "agent_started", agent: "reconnaissance" },
      { type: "agent_completed", agent: "reconnaissance" },
      { type: "agent_started", agent: "scanning" },
    ];
    const { container } = render(<AttackPathGraph events={events} />);
    expect(container.querySelector("svg")).not.toBeNull();
  });
});
