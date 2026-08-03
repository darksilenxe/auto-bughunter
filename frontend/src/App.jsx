import { useEffect, useState } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import CommandPalette from "./components/CommandPalette";
import ErrorBoundary from "./components/ErrorBoundary";
import MatrixRain from "./components/MatrixRain";
import ScanProgressBar from "./components/ScanProgressBar";
import Sidebar from "./components/Sidebar";
import { ToastProvider } from "./components/Toast";
import AgentConsole from "./pages/AgentConsole";
import AgentActivity from "./pages/AgentActivity";
import AttackGraph from "./pages/AttackGraph";
import Accuracy from "./pages/Accuracy";
import Dashboard from "./pages/Dashboard";
import Findings from "./pages/Findings";
import IDE from "./pages/IDE";
import ProbeCoverage from "./pages/ProbeCoverage";
import Proxy from "./pages/Proxy";
import ProxyBrowserPopout from "./pages/ProxyBrowserPopout";
import References from "./pages/References";
import Reports from "./pages/Reports";
import ScanTimeline from "./pages/ScanTimeline";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";
import SurfaceMap from "./pages/SurfaceMap";

function AppShell({ cmdOpen, setCmdOpen }) {
  return (
    <div className="app-shell">
      <ScanProgressBar />
      <MatrixRain />
      <Sidebar />
      <main className="app-main">
        <ErrorBoundary>
          <Routes>
            <Route path="/"               element={<Dashboard />} />
            <Route path="/attack-graph"   element={<AttackGraph />} />
            <Route path="/findings"       element={<Findings />} />
            <Route path="/ide"            element={<IDE />} />
            <Route path="/reports"        element={<Reports />} />
            <Route path="/scans"          element={<Scans />} />
            <Route path="/proxy"          element={<Proxy />} />
            <Route path="/references"     element={<References />} />
            <Route path="/settings"       element={<Settings />} />
            <Route path="/agent-activity" element={<AgentActivity />} />
            <Route path="/agent-console"  element={<AgentConsole />} />
            <Route path="/probe-coverage" element={<ProbeCoverage />} />
            <Route path="/scan-timeline"  element={<ScanTimeline />} />
            <Route path="/surface-map"    element={<SurfaceMap />} />
            <Route path="/accuracy"       element={<Accuracy />} />
            <Route path="/auth/redirect"  element={<Navigate to="/" replace />} />
          </Routes>
        </ErrorBoundary>
      </main>
      {cmdOpen && <CommandPalette onClose={() => setCmdOpen(false)} />}
    </div>
  );
}

export default function App() {
  const [cmdOpen, setCmdOpen] = useState(false);
  const location = useLocation();

  // Global Ctrl+K / Cmd+K keyboard shortcut for command palette
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
      }
      if (e.key === "Escape") setCmdOpen(false);
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  // Standalone routes rendered without the app shell (no sidebar/nav)
  if (location.pathname === "/proxy-browser") {
    return (
      <ToastProvider>
        <ErrorBoundary>
          <ProxyBrowserPopout />
        </ErrorBoundary>
      </ToastProvider>
    );
  }

  return (
    <ToastProvider>
      <AppShell cmdOpen={cmdOpen} setCmdOpen={setCmdOpen} />
    </ToastProvider>
  );
}
