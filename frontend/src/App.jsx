import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import Reports from "./pages/Reports";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";
import ApiExplorer from "./pages/ApiExplorer";
import Suppressions from "./pages/Suppressions";
import AttackPaths from "./pages/AttackPaths";

export default function App() {
  return (
    <div style={{ minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ paddingLeft: "0" }}>
        <Routes>
          <Route path="/"              element={<Dashboard />} />
          <Route path="/findings"      element={<Findings />} />
          <Route path="/attack-paths"  element={<AttackPaths />} />
          <Route path="/reports"       element={<Reports />} />
          <Route path="/scans"         element={<Scans />} />
          <Route path="/suppressions"  element={<Suppressions />} />
          <Route path="/api"           element={<ApiExplorer />} />
          <Route path="/settings"      element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
