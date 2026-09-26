import { useMemo, useState } from "react";

import { useEcdatContext } from "../context/useEcdatContext";

export const CURRENT_SCAN_KEY = "ecdatScanResult";
export const PAGE_SIZE = 15;

export function useCurrentScan() {
  const { selectedContext } = useEcdatContext();

  return useMemo(() => {
    try {
      return JSON.parse(
        sessionStorage.getItem(CURRENT_SCAN_KEY) || "null"
      ) || selectedContext?.result || null;
    } catch {
      return selectedContext?.result || null;
    }
  }, [selectedContext]);
}

export function usePaginatedArtifacts(artifacts, fields) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return artifacts.filter((artifact) =>
      !query ||
      fields
        .map((field) => artifact[field])
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(query)
    );
  }, [artifacts, fields, search]);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const currentPage = totalPages ? Math.min(page, totalPages) : 1;

  return {
    search,
    setSearch: (value) => {
      setSearch(value);
      setPage(1);
    },
    currentPage,
    totalPages,
    rows: filtered.slice(
      (currentPage - 1) * PAGE_SIZE,
      currentPage * PAGE_SIZE
    ),
    previous: () => setPage((value) => Math.max(1, value - 1)),
    next: () => setPage((value) => Math.min(totalPages, value + 1)),
  };
}
