import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Archive,
  Clock3,
  FileCode2,
  FileSearch,
  History,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";

import {
  artifactEntityId,
  fileEntityId,
  makeEntityId,
} from "../context/entityIds";
import { useEcdatContext } from "../context/useEcdatContext";

const CURRENT_SCAN_KEY = "ecdatScanResult";
const HISTORY_KEY = "ecdatScanHistory";
const RECENT_SEARCHES_KEY = "ecdatRecentSearches";
const RESULT_LIMIT = 6;

function readJson(storage, key, fallback) {
  try {
    return JSON.parse(storage.getItem(key) || JSON.stringify(fallback));
  } catch {
    return fallback;
  }
}

function getSearchData() {
  return {
    scanResult: readJson(sessionStorage, CURRENT_SCAN_KEY, null),
    history: readJson(localStorage, HISTORY_KEY, []),
  };
}

function valuesToText(values) {
  return values
    .filter((value) => value !== undefined && value !== null && value !== "")
    .map((value) => String(value))
    .join(" ")
    .toLowerCase();
}

function buildSearchIndex(scanResult, history) {
  const files = scanResult?.files || [];
  const artifacts = scanResult?.artifacts || [];
  const indexedFiles = files.map((file, index) => ({
    id: fileEntityId(file, index),
    type: "file",
    group: "Files",
    label: file.path || file.name || `File ${index + 1}`,
    detail: [file.type, file.size ? `${file.size} bytes` : ""].filter(Boolean).join(" · "),
    searchable: valuesToText([file.name, file.path, file.type, file.size]),
    context: {
      entityType: "file",
      entityId: fileEntityId(file, index),
      name: file.path || file.name,
      file: file.path || file.name,
      path: file.path || file.name,
      type: file.type || "binary/unknown",
      fileRecord: file,
    },
  }));

  const indexedArtifacts = artifacts.map((artifact, index) => ({
    id: artifactEntityId(artifact, index),
    type: "artifact",
    group: "Cryptographic Assets",
    label: artifact.algorithm || artifact.category || "Cryptographic artifact",
    detail: [artifact.file, artifact.line ? `line ${artifact.line}` : ""].filter(Boolean).join(" · "),
    status: artifact.risk || artifact.quantum_status,
    searchable: valuesToText([
      artifact.file,
      artifact.algorithm,
      artifact.algorithm_family,
      artifact.category,
      artifact.usage,
      artifact.risk,
      artifact.quantum_status,
      artifact.recommendation,
      artifact.code,
      artifact.key_size,
      artifact.mode,
      artifact.business_criticality,
      artifact.data_sensitivity,
    ]),
    context: {
      entityType: "artifact",
      entityId: artifactEntityId(artifact, index),
      name: artifact.algorithm || artifact.category || "Cryptographic artifact",
      file: artifact.file,
      line: artifact.line,
      algorithm: artifact.algorithm,
      risk: artifact.risk,
      quantumStatus: artifact.quantum_status,
      category: artifact.category,
      artifact,
    },
  }));

  const algorithmMap = new Map();
  indexedArtifacts.forEach((item) => {
    const algorithm = item.context.algorithm;
    if (!algorithm) return;

    const current = algorithmMap.get(algorithm) || {
      algorithm,
      count: 0,
      artifact: item.context.artifact,
    };
    current.count += 1;
    algorithmMap.set(algorithm, current);
  });

  const indexedAlgorithms = [...algorithmMap.values()].map((item) => ({
    id: makeEntityId("algorithm", item.algorithm),
    type: "algorithm",
    group: "Algorithms",
    label: item.algorithm,
    detail: `${item.count} detected artifact${item.count === 1 ? "" : "s"}`,
    searchable: valuesToText([item.algorithm]),
    context: {
      entityType: "algorithm",
      entityId: makeEntityId("algorithm", item.algorithm),
      name: item.algorithm,
      algorithm: item.algorithm,
    },
  }));

  const indexedHistory = history.map((entry, index) => {
    const id = entry.id || `${entry.timestamp || "unknown"}-${index}`;
    const result = entry.result || {};
    const summary = result.summary || {};

    return {
      id: makeEntityId("history", id),
      type: "history",
      group: "Scan History",
      label: entry.name || result.input?.name || "Unnamed scan",
      detail: `${summary.files_scanned || 0} files · ${summary.crypto_assets || 0} crypto assets`,
      searchable: valuesToText([
        entry.name,
        entry.timestamp,
        result.input?.name,
        summary.files_scanned,
        summary.crypto_assets,
      ]),
      context: {
        entityType: "history",
        entityId: makeEntityId("history", id),
        name: entry.name || result.input?.name || "Unnamed scan",
        timestamp: entry.timestamp,
        result,
        historyEntry: entry,
      },
    };
  });

  return [
    ...indexedFiles,
    ...indexedArtifacts,
    ...indexedAlgorithms,
    ...indexedHistory,
  ];
}

function getRecentSearches() {
  return readJson(localStorage, RECENT_SEARCHES_KEY, [])
    .filter((query) => typeof query === "string" && query.trim())
    .slice(0, 5);
}

function saveRecentSearch(query) {
  const normalized = query.trim();
  if (!normalized) return;

  const recent = [normalized, ...getRecentSearches().filter((item) => item.toLowerCase() !== normalized.toLowerCase())].slice(0, 5);
  localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
}

function ResultIcon({ type }) {
  if (type === "file") return <FileSearch size={15} />;
  if (type === "algorithm") return <ShieldAlert size={15} />;
  if (type === "history") return <History size={15} />;
  return <FileCode2 size={15} />;
}

export default function GlobalSearch({ variant = "dashboard" }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { selectContext } = useEcdatContext();
  const containerRef = useRef(null);
  const inputRef = useRef(null);
  const [query, setQuery] = useState("");
  const [isOpen, setIsOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const searchData = useMemo(
    () => getSearchData(),
    []
  );
  const [recentSearches, setRecentSearches] = useState(getRecentSearches);

  useEffect(() => {
    const onKeyDown = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        inputRef.current?.focus();
        setIsOpen(true);
        return;
      }

      if (event.key === "Escape") {
        setIsOpen(false);
        inputRef.current?.blur();
      }
    };

    const onPointerDown = (event) => {
      if (!containerRef.current?.contains(event.target)) setIsOpen(false);
    };

    window.addEventListener("keydown", onKeyDown);
    document.addEventListener("mousedown", onPointerDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("mousedown", onPointerDown);
    };
  }, []);

  const index = useMemo(
    () => buildSearchIndex(searchData.scanResult, searchData.history),
    [searchData]
  );
  const matchingResults = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    if (!normalizedQuery) return [];
    return index.filter((item) => item.searchable.includes(normalizedQuery));
  }, [index, query]);
  const groupedResults = useMemo(() => {
    const groups = [];
    ["Files", "Cryptographic Assets", "Algorithms", "Scan History"].forEach((group) => {
      const results = matchingResults.filter((item) => item.group === group).slice(0, RESULT_LIMIT);
      if (results.length) groups.push({ group, results });
    });
    return groups;
  }, [matchingResults]);
  const visibleResults = groupedResults.flatMap((group) => group.results);

  const selectResult = (result) => {
    selectContext(result.context);
    saveRecentSearch(query);
    setRecentSearches(getRecentSearches());
    setIsOpen(false);

    if (result.type === "history") {
      navigate("/dashboard", {
        state: {
          scanResult: result.context.result,
          historyEntry: result.context.historyEntry,
        },
      });
      return;
    }

    if (location.pathname !== "/dashboard") {
      navigate("/dashboard", {
        state: { scanResult: searchData.scanResult },
      });
    }
  };

  const clearRecentSearches = () => {
    localStorage.removeItem(RECENT_SEARCHES_KEY);
    setRecentSearches([]);
  };

  const selectedResultIndex = Math.min(
    activeIndex,
    Math.max(visibleResults.length - 1, 0)
  );

  const handleKeyDown = (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((current) => Math.min(current + 1, Math.max(visibleResults.length - 1, 0)));
    }

    if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((current) => Math.max(current - 1, 0));
    }

    if (event.key === "Enter" && visibleResults[selectedResultIndex]) {
      event.preventDefault();
      selectResult(visibleResults[selectedResultIndex]);
    }
  };

  const showEmptyState = !query.trim() && recentSearches.length === 0;

  return (
    <div
      className={`global-search-container ${variant}-search`}
      ref={containerRef}
    >
      <Search size={variant === "dashboard" ? 15 : 16} />
      <input
        ref={inputRef}
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        onFocus={() => setIsOpen(true)}
        onKeyDown={handleKeyDown}
        placeholder={variant === "dashboard" ? "Search ECDAT" : "Search ECDAT"}
        aria-label="Global search"
        aria-expanded={isOpen}
        aria-controls="ecdat-global-search-results"
        role="combobox"
      />
      {query && <button type="button" className="global-search-clear" onClick={() => setQuery("")} aria-label="Clear search"><X size={13} /></button>}
      <kbd>{navigator.platform?.toLowerCase().includes("mac") ? "⌘K" : "Ctrl K"}</kbd>

      {isOpen && (
        <div className="global-search-panel" id="ecdat-global-search-results" role="listbox">
          {!query.trim() && (
            <div className="global-search-recent">
              <div className="global-search-panel-heading"><span><Clock3 size={13} /> Recent searches</span><span className="global-search-panel-heading-actions"><small>Type to search current scan</small>{recentSearches.length > 0 && <button type="button" className="global-search-clear-history" onClick={clearRecentSearches}>Clear search history</button>}</span></div>
              {recentSearches.length ? recentSearches.map((recent) => <button key={recent} type="button" onClick={() => setQuery(recent)}><Clock3 size={14} />{recent}</button>) : <div className="global-search-empty"><Search size={18} /><span>Search files, algorithms, risks, findings, or scan history.</span></div>}
            </div>
          )}

          {query.trim() && groupedResults.map((group) => (
            <div className="global-search-group" key={group.group}>
              <div className="global-search-panel-heading"><span>{group.group}</span><small>{group.results.length} shown</small></div>
              {group.results.map((result) => {
                const resultIndex = visibleResults.indexOf(result);
                return <button type="button" role="option" aria-selected={selectedResultIndex === resultIndex} className={selectedResultIndex === resultIndex ? "active" : ""} key={result.id} onMouseEnter={() => setActiveIndex(resultIndex)} onClick={() => selectResult(result)}><span className="global-search-result-icon"><ResultIcon type={result.type} /></span><span className="global-search-result-copy"><strong>{result.label}</strong><small>{result.detail || result.type}</small></span>{result.status && <span className={`global-search-result-status ${String(result.status).toLowerCase()}`}>{result.status}</span>}</button>;
              })}
            </div>
          ))}

          {query.trim() && !visibleResults.length && <div className="global-search-empty"><Archive size={18} /><strong>No matching entities</strong><span>Try a filename, algorithm, risk, or recommendation from this scan.</span></div>}
          {showEmptyState && <div className="global-search-shortcut"><span>⌘K / Ctrl K</span><small>Open global search anytime</small></div>}
          {query.trim() && <div className="global-search-footer"><span>↑↓ Navigate</span><span>↵ Open</span><span>Esc Close</span></div>}
        </div>
      )}
    </div>
  );
}
