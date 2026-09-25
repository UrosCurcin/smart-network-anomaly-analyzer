import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";

export default function App() {
  return (
    <div className="app-shell">
      <header className="top-bar">
        <span className="brand">Smart Network Anomaly Analyzer</span>
        <nav>
          <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
            Dashboard
          </NavLink>
          <NavLink to="/alerts" className={({ isActive }) => (isActive ? "active" : "")}>
            Alerts
          </NavLink>
        </nav>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:alertId" element={<AlertDetail />} />
        </Routes>
      </main>
    </div>
  );
}
