import { useEffect, useState } from 'react';
import styles from './Landing.module.css';
import { Button, Input } from '../components/UI';

type Status = 'loading' | 'ok' | 'error';

/**
 * Landing page — Phase 0 stub.
 *
 * Shows the project title, simulation notice, and live health/ready
 * status from the backend (proves the stack is wired up).
 */
export function Landing({ onLogin }: { onLogin: () => void }) {
  const [health, setHealth] = useState<Status>('loading');
  const [ready, setReady] = useState<Status>('loading');

  useEffect(() => {
    fetch('/health')
      .then((r) => (r.ok ? setHealth('ok') : setHealth('error')))
      .catch(() => setHealth('error'));

    fetch('/ready')
      .then((r) => (r.ok ? setReady('ok') : setReady('error')))
      .catch(() => setReady('error'));
  }, []);

  const dotClass = (s: Status) =>
    s === 'ok'
      ? styles['landing__dot--ok']
      : s === 'error'
        ? styles['landing__dot--err']
        : styles['landing__dot--loading'];

  return (
    <main className={styles.landing}>
      <h1 className={styles.landing__title}>
        Mini<span className={styles.landing__accent}>-UPI</span>
      </h1>
      <p className={styles.landing__subtitle}>
        Secure campus payment simulation.
        Demonstrating real cryptographic protocols with virtual money.
      </p>
      <form className={styles.login} onSubmit={(event) => { event.preventDefault(); onLogin(); }}>
        <Input label="College ID" placeholder="e.g. 22IT002" required />
        <Input label="Password" type="password" placeholder="Your password" required />
        <Button type="submit">Enter campus wallet</Button>
      </form>
      <div className={styles.landing__status}>
        <div className={styles.landing__badge}>
          <span className={`${styles.landing__dot} ${dotClass(health)}`} />
          /health: {health}
        </div>
        <div className={styles.landing__badge}>
          <span className={`${styles.landing__dot} ${dotClass(ready)}`} />
          /ready: {ready}
        </div>
      </div>
    </main>
  );
}
