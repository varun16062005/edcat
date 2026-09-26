import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import AppShell from "./components/AppShell";
import HomePage from "./pages/HomePage";
import Dashboard from "./pages/Dashboard";
import RiskAnalysisPage from "./pages/RiskAnalysisPage";
import MigrationPage from "./pages/MigrationPage";
import OverviewPage from "./pages/OverviewPage";
import HistoryPage from "./pages/HistoryPage";
import AdvisorPage from "./pages/AdvisorPage";
import BlastRadiusPage from "./pages/BlastRadiusPage";
import { EcdatProvider } from "./context/EcdatContext";
import { ThemeProvider } from "./context/ThemeContext";

import "./App.css";

function RequireScan({ children }) {
  const hasScan = Boolean(
    sessionStorage.getItem("ecdatScanResult")
  );
  if (!hasScan) {
    return <Navigate to="/" replace />;
  }
  return children;
}

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <EcdatProvider>
        <Routes>
          {/* Landing / Scan Configuration in Homepage (minimal side rail) */}
          <Route path="/" element={<HomePage />} />
          <Route path="/home" element={<HomePage />} />
          <Route path="/scan-config" element={<HomePage />} />

          {/* Post-Scan Discovery & Analysis Workspace (full sidebar shell) */}
          <Route element={<AppShell />}>
            <Route
              path="/dashboard"
              element={
                <RequireScan>
                  <Dashboard discoveryOnly />
                </RequireScan>
              }
            />
            <Route
              path="/risk-analysis"
              element={
                <RequireScan>
                  <RiskAnalysisPage />
                </RequireScan>
              }
            />
            <Route
              path="/migration"
              element={
                <RequireScan>
                  <MigrationPage />
                </RequireScan>
              }
            />
            <Route
              path="/overview"
              element={
                <RequireScan>
                  <OverviewPage />
                </RequireScan>
              }
            />
            <Route
              path="/report"
              element={
                <RequireScan>
                  <OverviewPage defaultShowReport={true} />
                </RequireScan>
              }
            />
            <Route
              path="/history"
              element={
                <RequireScan>
                  <HistoryPage />
                </RequireScan>
              }
            />
            <Route
              path="/assistant"
              element={
                <RequireScan>
                  <AdvisorPage />
                </RequireScan>
              }
            />
            <Route
              path="/blast-radius"
              element={
                <RequireScan>
                  <BlastRadiusPage />
                </RequireScan>
              }
            />
            <Route
              path="/graph"
              element={
                <RequireScan>
                  <BlastRadiusPage />
                </RequireScan>
              }
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </EcdatProvider>
    </BrowserRouter>
  </ThemeProvider>
  );
}
