import { useMemo, useState } from "react";
import { STORAGE_KEY } from "./contextStorage";
import { EcdatContext } from "./EcdatContextValue";

function readStoredContext() {
  try {
    const stored = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || "null");
    return stored ? normalizeContext(stored) : null;
  } catch {
    return null;
  }
}

function normalizeContext(nextContext) {
  const normalized = { ...nextContext };

  if (normalized.name && typeof normalized.name === "object") {
    normalized.name = normalized.name.name || normalized.name.path || "Selected entity";
  }

  if (normalized.file && typeof normalized.file === "object") {
    normalized.fileRecord = normalized.file;
    normalized.file = normalized.file.path || normalized.file.name || "Unknown file";
  }

  if (normalized.path && typeof normalized.path === "object") {
    normalized.path = normalized.path.path || normalized.path.name || "Unknown file";
  }

  return normalized;
}

export function EcdatProvider({ children }) {
  const [selectedContext, setSelectedContext] = useState(readStoredContext);

  const value = useMemo(() => ({
    selectedContext,
    selectContext: (nextContext) => {
      if (!nextContext) return;

      const normalized = normalizeContext(nextContext);
      setSelectedContext(normalized);

      try {
        sessionStorage.setItem(
          STORAGE_KEY,
          JSON.stringify(normalized)
        );
      } catch {
        // Context persistence is best effort.
      }
    },
    clearContext: () => {
      setSelectedContext(null);

      try {
        sessionStorage.removeItem(STORAGE_KEY);
      } catch {
        // Context persistence is best effort.
      }
    },
  }), [selectedContext]);

  return (
    <EcdatContext.Provider value={value}>
      {children}
    </EcdatContext.Provider>
  );
}
