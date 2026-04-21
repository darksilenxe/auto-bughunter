import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import AttackGraph from "./pages/AttackGraph";
import Findings from "./pages/Findings";
import Reports from "./pages/Reports";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="app-main">
        <Routes>
          <Route path="/"             element={<Dashboard />} />
          <Route path="/attack-graph" element={<AttackGraph />} />
          <Route path="/findings"     element={<Findings />} />
          <Route path="/reports"      element={<Reports />} />
          <Route path="/scans"        element={<Scans />} />
          <Route path="/settings"     element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
