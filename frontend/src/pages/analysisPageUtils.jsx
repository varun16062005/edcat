import { Link } from "react-router-dom";

export function AnalysisHeader({ label, title, description }) {
  return (
    <header className="analysis-page-header">
      <div>
        <span className="section-kicker">{label}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
    </header>
  );
}

export function EmptyAnalysisState() {
  return (
    <section className="analysis-empty">
      <h2>No scan selected</h2>
      <p>Run a scan from Scan Configuration to populate this analysis.</p>
      <Link to="/scan-config">Open Scan Configuration</Link>
    </section>
  );
}

export function MetricGrid({ cards }) {
  return (
    <section className="analysis-metric-grid">
      {cards.map(([label, value, hint]) => (
        <article key={label} className="analysis-metric-card">
          <span>{label}</span>
          <strong>{value}</strong>
          {hint ? <small>{hint}</small> : null}
        </article>
      ))}
    </section>
  );
}

export function PaginationBar({
  currentPage,
  totalPages,
  onPageChange,
  from,
  to,
  total,
  noun = "assets",
}) {
  if (!total) return null;
  const pages = [];
  if (totalPages <= 7) {
    for (let page = 1; page <= totalPages; page += 1) pages.push(page);
  } else {
    pages.push(1);
    const start = Math.max(2, currentPage - 1);
    const end = Math.min(totalPages - 1, currentPage + 1);
    if (start > 2) pages.push("ellipsis-start");
    for (let page = start; page <= end; page += 1) pages.push(page);
    if (end < totalPages - 1) pages.push("ellipsis-end");
    pages.push(totalPages);
  }

  return (
    <div className="analysis-pagination">
      <span className="analysis-pagination-count">
        Showing {from}–{to} of {total} {noun}
      </span>
      {totalPages > 1 ? (
        <div className="analysis-pagination-controls">
          <button type="button" disabled={currentPage === 1} onClick={() => onPageChange(currentPage - 1)}>
            Previous
          </button>
          {pages.map((page) => (
            typeof page === "number" ? (
              <button
                type="button"
                key={page}
                className={page === currentPage ? "active" : ""}
                onClick={() => onPageChange(page)}
              >
                {page}
              </button>
            ) : (
              <span key={page}>…</span>
            )
          ))}
          <button type="button" disabled={currentPage === totalPages} onClick={() => onPageChange(currentPage + 1)}>
            Next
          </button>
        </div>
      ) : null}
    </div>
  );
}
