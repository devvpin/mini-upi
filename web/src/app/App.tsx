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
  const [token, setToken] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const signIn = async (collegeId: string, password: string) => {
    setAuthError(null);
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ college_id: collegeId, password }),
    });
    if (!response.ok) {
      setAuthError('Authentication failed. Check your campus ID and password.');
      return;
    }
    const data = (await response.json()) as { access_token: string };
    setToken(data.access_token);
  };
  return (
    <>
      {/* Simulation ribbon — always visible (brain/07 requirement) */}
      <div className="simulation-ribbon" role="banner" aria-label="Simulation notice">
        Simulation — virtual points, no real money
      </div>

      <BrowserRouter>
        <Routes>
          <Route path="/" element={token ? <Dashboard token={token} onLogout={() => setToken(null)} /> : <Landing onLogin={signIn} error={authError} />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}
