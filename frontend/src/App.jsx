import { Routes, Route } from "react-router-dom";
import ErrorBoundary from "./components/ErrorBoundary";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import AttackGraph from "./pages/AttackGraph";
import Findings from "./pages/Findings";
import Reports from "./pages/Reports";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";
import Proxy from "./pages/Proxy";
import References from "./pages/References";

export default function App() {
  return (
    <div className="app-shell">
      <Sidebar />
      <main className="app-main">
        <ErrorBoundary>
          <Routes>
            <Route path="/"             element={<Dashboard />} />
            <Route path="/attack-graph" element={<AttackGraph />} />
            <Route path="/findings"     element={<Findings />} />
            <Route path="/reports"      element={<Reports />} />
            <Route path="/scans"        element={<Scans />} />
            <Route path="/proxy"        element={<Proxy />} />
            <Route path="/references"   element={<References />} />
            <Route path="/settings"     element={<Settings />} />
          </Routes>
        </ErrorBoundary>
      </main>
    </div>
  );
}
