import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Landing } from './Landing';
import { Dashboard } from './Dashboard';
import { useState } from 'react';

/**
 * Root application component.
 *
 * Phase 0: only the landing stub route.
 * Subsequent phases add auth, wallet, pay, history, admin routes.
 */
export function App() {
  const [signedIn, setSignedIn] = useState(false);
  return (
    <>
      {/* Simulation ribbon — always visible (brain/07 requirement) */}
      <div className="simulation-ribbon" role="banner" aria-label="Simulation notice">
        Simulation — virtual points, no real money
      </div>

      <BrowserRouter>
        <Routes>
          <Route path="/" element={signedIn ? <Dashboard onLogout={() => setSignedIn(false)} /> : <Landing onLogin={() => setSignedIn(true)} />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}
