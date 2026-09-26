import { useState } from "react";
import {
  ChevronRight,
  FileSearch,
  History,
  LayoutDashboard,
  Maximize2,
  Menu,
  MessageCircle,
  Route as RouteIcon,
  ShieldAlert,
  Target,
  Upload,
  X,
} from "lucide-react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import GlobalSearch from "./GlobalSearch";

const navigation = [
  {
    label: "OVERVIEW",
    items: [
      ["Dashboard", "/dashboard", LayoutDashboard],
    ],
  },
  {
    label: "ANALYSIS",
    items: [
      ["Risk Analysis", "/risk-analysis", ShieldAlert],
      ["Blast Radius", "/blast-radius", Target],
    ],
  },
  {
    label: "SECURITY",
    items: [
      ["Migration Plan", "/migration", RouteIcon],
      ["Overview", "/overview", FileSearch],
    ],
  },
  {
    label: "INTELLIGENCE",
    items: [
      ["ECDAT Advisor", "/assistant", MessageCircle],
      ["Scan History", "/history", History],
    ],
  },
];

const PAGE_TITLES = {
  "/": "Overview",
  "/dashboard": "Dashboard",
  "/risk-analysis": "Risk Analysis",
  "/migration": "Migration Plan",
  "/overview": "Overview",
  "/report": "Executive Report",
  "/blast-radius": "Blast Radius",
  "/graph": "Blast Radius",
  "/assistant": "ECDAT Advisor",
  "/history": "Scan History",
};

export default function AppShell() {
  const location = useLocation();
  const currentTitle = PAGE_TITLES[location.pathname] || "Overview";
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [prevPathname, setPrevPathname] = useState(location.pathname);

  if (prevPathname !== location.pathname) {
    setPrevPathname(location.pathname);
    setMobileMenuOpen(false);
  }

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
    } else {
      document.exitFullscreen().catch(() => {});
    }
  };

  return (
    <div className="unified-app-shell">
      {/* Mobile Drawer Backdrop */}
      {mobileMenuOpen && (
        <div
          className="shell-mobile-backdrop"
          onClick={() => setMobileMenuOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Persistent / Mobile Slide-out Drawer */}
      <aside
        className={`shell-sidebar ${mobileMenuOpen ? "mobile-open" : ""}`}
        aria-label="Main Navigation"
      >
        <div className="sidebar-top-row">
          <NavLink
            to="/dashboard"
            className="sidebar-brand-strip"
            aria-label="ECDAT Dashboard"
            onClick={() => setMobileMenuOpen(false)}
          >
            <div className="brand-logo-icon">
              <img src="/ecdat-logo.png" alt="ECDAT" />
            </div>
            <div className="brand-title-wrap">
              <strong className="brand-title">ECDAT</strong>
            </div>
          </NavLink>
          <button
            type="button"
            className="sidebar-mobile-close"
            onClick={() => setMobileMenuOpen(false)}
            aria-label="Close navigation menu"
          >
            <X size={18} />
          </button>
        </div>

        <nav className="sidebar-nav-container" aria-label="ECDAT sections">
          {navigation.map((group) => (
            <div className="sidebar-nav-group" key={group.label}>
              <span className="nav-group-heading">{group.label}</span>
              {group.items.map(([label, path, Icon]) => (
                <NavLink
                  key={path}
                  to={path}
                  onClick={() => setMobileMenuOpen(false)}
                  className={({ isActive }) =>
                    `sidebar-nav-link${isActive ? " active" : ""}`
                  }
                  title={label}
                >
                  <Icon size={16} className="nav-item-icon" />
                  <span className="nav-item-label">{label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-bottom-action">
          <NavLink
            to="/"
            onClick={() => setMobileMenuOpen(false)}
            className="sidebar-new-scan-btn"
            title="Start a New Scan"
          >
            <Upload size={16} className="btn-icon" />
            <span>New Scan</span>
          </NavLink>
        </div>
      </aside>

      {/* Main Area: Top Bar + Content */}
      <div className="shell-main-workspace">
        {/* Unified Top Navigation Bar */}
        <header className="shell-topbar" aria-label="Workspace Header">
          <div className="shell-topbar-left">
            <button
              type="button"
              className="topbar-hamburger-btn"
              onClick={() => setMobileMenuOpen((open) => !open)}
              aria-label={mobileMenuOpen ? "Close navigation menu" : "Open navigation menu"}
              aria-expanded={mobileMenuOpen}
            >
              {mobileMenuOpen ? <X size={19} /> : <Menu size={19} />}
            </button>

            <div className="shell-topbar-breadcrumb">
              <div className="brand-crumb-icon">
                <img src="/ecdat-logo.png" alt="ECDAT" />
              </div>
              <span className="breadcrumb-brand">ECDAT</span>
              <ChevronRight size={13} className="breadcrumb-separator" />
              <span className="breadcrumb-current-page">{currentTitle}</span>
            </div>
          </div>

          <div className="shell-topbar-actions">
            <div className="topbar-search-wrapper">
              <GlobalSearch variant="dashboard" />
            </div>


            <button
              type="button"
              className="topbar-action-btn"
              title="Fullscreen Mode"
              onClick={toggleFullscreen}
              aria-label="Toggle Fullscreen"
            >
              <Maximize2 size={15} />
            </button>
          </div>
        </header>

        {/* Page Content Viewport */}
        <main className="shell-page-container">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
