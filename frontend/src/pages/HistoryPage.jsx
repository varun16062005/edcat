import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  AnalysisHeader,
  EmptyAnalysisState,
} from "./analysisPageUtils";

const HISTORY_KEY = "ecdatScanHistory";
const CURRENT_SCAN_KEY = "ecdatScanResult";

function readHistory() {
  try {
    const entries = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(entries) ? entries : [];
  } catch {
    return [];
  }
}

function formatDate(value) {
  if (!value) return "Unknown date";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

export default function HistoryPage() {
  const navigate = useNavigate();
  const [history, setHistory] = useState(readHistory);
  const hasCurrentScan = useMemo(
    () => Boolean(sessionStorage.getItem(CURRENT_SCAN_KEY)),
    []
  );

  const loadScan = (entry) => {
    if (!entry?.result) return;
    sessionStorage.setItem(CURRENT_SCAN_KEY, JSON.stringify(entry.result));
    navigate("/dashboard", {
      state: { scanResult: entry.result, historyEntry: entry },
    });
  };

  return (
    <main className="analysis-page">
      <AnalysisHeader
        label="SCAN HISTORY"
        title="Previous complete reports"
        description="Browser-local history for this workstation. Load a saved report without replacing the scan engine."
      />
      <div className="history-page-actions">
        <span>{hasCurrentScan ? "Current scan available" : "No current scan loaded"}</span>
        <button
          type="button"
          onClick={() => {
            localStorage.removeItem(HISTORY_KEY);
            setHistory([]);
          }}
        >
          Clear history
        </button>
      </div>
      {!history.length ? (
        <EmptyAnalysisState />
      ) : (
        <section className="analysis-panel history-page-panel">
          <div className="analysis-table-wrap">
            <table className="analysis-table">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Date</th>
                  <th>Files</th>
                  <th>Assets</th>
                  <th>Critical</th>
                  <th>Status</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry, index) => {
                  const summary = entry.result?.summary || {};
                  return (
                    <tr key={entry.id || `${entry.name || "scan"}-${entry.timestamp || index}`}>
                      <td>{String(entry.name || "Unnamed scan")}</td>
                      <td>{formatDate(entry.timestamp)}</td>
                      <td>{summary.files_scanned || 0}</td>
                      <td>{summary.crypto_assets || 0}</td>
                      <td>{summary.critical || 0}</td>
                      <td>Complete</td>
                      <td>
                        <button type="button" onClick={() => loadScan(entry)}>
                          Load report
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </main>
  );
}
