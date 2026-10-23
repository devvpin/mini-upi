import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Landing } from './Landing';
import { Dashboard } from './Dashboard';
import { useState } from 'react';
import type { UserProfile } from './api';

interface LoginResponse {
  access_token: string;
  user: UserProfile;
}

/**
 * Root application component for sign-in and authenticated campus wallet screens.
 */
export function App() {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [initialPassword, setInitialPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const signIn = async (collegeId: string, password: string) => {
    setAuthError(null);
    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ college_id: collegeId, password }),
      });
      if (!response.ok) {
        setAuthError('Authentication failed. Check your campus ID and password.');
        return;
      }
      const data = (await response.json()) as LoginResponse;
      setToken(data.access_token);
      setUser(data.user);
      setInitialPassword(password);
    } catch {
      setAuthError('Cannot reach the server. Check that the app is running and try again.');
    }
  };
  const signOut = () => {
    setToken(null);
    setUser(null);
    setInitialPassword('');
  };
  return (
    <>
      {/* Simulation ribbon — always visible (brain/07 requirement) */}
      <div className="simulation-ribbon" role="banner" aria-label="Simulation notice">
        Simulation — virtual points, no real money
      </div>

      <BrowserRouter>
        <Routes>
          <Route path="/" element={token && user ? <Dashboard token={token} user={user} initialPassword={initialPassword} onUserChange={setUser} onLogout={signOut} /> : <Landing onLogin={signIn} error={authError} />} />
        </Routes>
      </BrowserRouter>
    </>
  );
}
