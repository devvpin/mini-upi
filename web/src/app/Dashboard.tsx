import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Copy,
  CreditCard,
  History,
  Home,
  LogOut,
  Menu,
  ScanLine,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { IScannerControls } from "@zxing/browser";
import {
  AmountPad,
  Avatar,
  Banner,
  Button,
  Card,
  Chip,
  HashBlock,
  Input,
  QRCard,
  Sheet,
  Timeline,
  Toast,
} from "../components/UI";
import {
  createRequestEnvelope,
  decryptResponseEnvelope,
  exportPublicKeyJwk,
  getOrCreateDeviceKey,
  signPayload,
} from "../crypto";
import { ApiError, apiRequest } from "./api";
import type {
  CollectRequest,
  Device,
  TransactionDetail,
  TransactionSummary,
  UserProfile,
  Wallet,
} from "./api";
import { parsePaymentQr } from "./paymentQr";
import styles from "./Dashboard.module.css";

/**
 * Authenticated wallet screens and payment workflows.
 *
 * Crypto concept: device-bound signatures and encrypted payment envelopes.
 * Threat mitigated: forged, replayed, or tampered campus-point transfers.
 */
type View = "home" | "pay" | "requests" | "history" | "profile" | "admin";

interface Props {
  token: string;
  user: UserProfile;
  initialPassword: string;
  onUserChange: (user: UserProfile) => void;
  onLogout: () => void;
}

interface LoginSetupProps {
  token: string;
  user: UserProfile;
  initialPassword: string;
  onComplete: (user: UserProfile) => void;
}

interface ServerKeyResponse {
  public_key: JsonWebKey;
}

interface VpaResolution {
  handle: string;
  masked_name: string;
}

interface VpaResponse {
  primary_vpa: string;
  all_vpas: string[];
  qr_payload: string;
}

interface BankReceiptEnvelope {
  envelope: Parameters<typeof decryptResponseEnvelope>[1];
}

interface AdminStats {
  total_users: number;
  total_transactions: number;
  total_volume_rupees: number;
}

const navItems: [View, LucideIcon, string][] = [
  ["home", Home, "Home"],
  ["pay", ArrowUpRight, "Pay"],
  ["requests", ArrowDownLeft, "Requests"],
  ["history", History, "History"],
  ["profile", UserRound, "Profile"],
  ["admin", ShieldCheck, "Admin"],
];

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Something went wrong. Please try again.";
}

function getPaymentError(error: unknown): string {
  if (error instanceof ApiError && error.status === 400 && error.message.includes("MPIN not configured")) {
    return "Set your six-digit MPIN in Profile before making a payment.";
  }
  if (error instanceof Error && error.message.includes("This browser is not bound")) {
    return "Bind this browser in Profile before making a payment.";
  }
  return getErrorMessage(error);
}

function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

function formatRupees(paise: number): string {
  return (paise / 100).toLocaleString("en-IN", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function dateLabel(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

async function bindBrowserDevice(token: string, password: string): Promise<void> {
  const keyPair = await getOrCreateDeviceKey();
  const publicKey = await exportPublicKeyJwk(keyPair.publicKey);
  const devices = await apiRequest<Device[]>("/devices", token);
  const alreadyBound = devices.some(
    (device) =>
      device.status === "active" &&
      device.public_key_jwk.x === publicKey.x &&
      device.public_key_jwk.y === publicKey.y,
  );
  if (alreadyBound) return;

  await apiRequest<Device>("/devices/register", token, {
    method: "POST",
    body: JSON.stringify({
      public_key_jwk: publicKey,
      label: "This browser",
      password,
    }),
  });
}

export function Dashboard({
  token,
  user,
  initialPassword,
  onUserChange,
  onLogout,
}: Props) {
  if (user.must_change_password) {
    return (
      <LoginSetup
        token={token}
        user={user}
        initialPassword={initialPassword}
        onComplete={(updatedUser) => onUserChange(updatedUser)}
      />
    );
  }

  return (
    <WalletDashboard
      token={token}
      user={user}
      onLogout={onLogout}
    />
  );
}

function LoginSetup({ token, user, initialPassword, onComplete }: LoginSetupProps) {
  const [step, setStep] = useState<"password" | "security">("password");
  const [currentPassword, setCurrentPassword] = useState(initialPassword);
  const [newPassword, setNewPassword] = useState("");
  const [mpin, setMpin] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const changePassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiRequest<{ status: string }>("/auth/change-password", token, {
        method: "POST",
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });
      setCurrentPassword(newPassword);
      setStep("security");
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const setSecurity = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiRequest<{ status: string }>("/mpin/set", token, {
        method: "POST",
        body: JSON.stringify({ mpin, password: currentPassword }),
      });
      await bindBrowserDevice(token, currentPassword);
      onComplete({ ...user, must_change_password: false });
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className={styles.setup}>
      <p className={styles.eyebrow}>First-time account setup</p>
      <h1>{step === "password" ? "Choose a new password." : "Secure this browser."}</h1>
      <p className={styles.muted}>
        {step === "password"
          ? "Your temporary password must be replaced before using your campus wallet."
          : "Create a six-digit MPIN and bind a device key. Your MPIN is chosen by you and is never shown again."}
      </p>
      {error && <Banner tone="danger">{error}</Banner>}
      {step === "password" ? (
        <form className={styles.payCard} onSubmit={(event) => void changePassword(event)}>
          <Input
            label="New password (at least 8 characters)"
            type="password"
            autoComplete="new-password"
            minLength={8}
            required
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
          <Button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Change password"}
          </Button>
        </form>
      ) : (
        <form className={styles.payCard} onSubmit={(event) => void setSecurity(event)}>
          <Input
            label="Choose a six-digit MPIN"
            type="password"
            inputMode="numeric"
            autoComplete="new-password"
            pattern="[0-9]{6}"
            maxLength={6}
            minLength={6}
            required
            value={mpin}
            onChange={(event) => setMpin(event.target.value.replace(/\D/g, "").slice(0, 6))}
          />
          <Button type="submit" disabled={busy || mpin.length !== 6}>
            {busy ? "Securing account…" : "Set MPIN and bind browser"}
          </Button>
        </form>
      )}
      <p className={styles.muted}>Simulation only — virtual points, no real money.</p>
    </main>
  );
}

function WalletDashboard({
  token,
  user,
  onLogout,
}: {
  token: string;
  user: UserProfile;
  onLogout: () => void;
}) {
  const [view, setView] = useState<View>("home");
  const [menu, setMenu] = useState(false);
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [walletError, setWalletError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [selectedTransaction, setSelectedTransaction] = useState<TransactionDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const isAdmin = user.role === "admin";
  const visibleNav = navItems.filter(([key]) => key !== "admin" || isAdmin);

  const reloadWallet = async () => {
    setWalletError(null);
    try {
      setWallet(await apiRequest<Wallet>("/wallet", token));
    } catch (failure) {
      setWalletError(getErrorMessage(failure));
    }
  };

  useEffect(() => {
    void reloadWallet();
  }, [token]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 5000);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const openTransaction = async (id: string) => {
    setSelectedTransaction(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      setSelectedTransaction(
        await apiRequest<TransactionDetail>(`/transactions/${encodeURIComponent(id)}`, token),
      );
    } catch (failure) {
      setDetailError(getErrorMessage(failure));
    } finally {
      setDetailLoading(false);
    }
  };

  const navigate = (next: View) => {
    setView(next);
    setMenu(false);
  };

  const onPaymentComplete = async (message: string) => {
    setToast(message);
    setView("home");
    await reloadWallet();
  };

  return (
    <div className={styles.shell}>
      <header className={styles.topbar}>
        <button
          className={styles.menu}
          onClick={() => setMenu((open) => !open)}
          aria-label={menu ? "Close navigation" : "Open navigation"}
          aria-expanded={menu}
        >
          {menu ? <X /> : <Menu />}
        </button>
        <span className={styles.brand}>Mini<span>-UPI</span></span>
        <span className={styles.connection}>session active</span>
      </header>
      <aside className={`${styles.sidebar} ${menu ? styles["sidebar--open"] : ""}`}>
        <div className={styles.sidebarBrand}>Mini<span>-UPI</span></div>
        <nav aria-label="Main navigation">
          {visibleNav.map(([key, Icon, label]) => (
            <button
              className={view === key ? styles.active : ""}
              key={key}
              onClick={() => navigate(key)}
              aria-current={view === key ? "page" : undefined}
            >
              <Icon size={18} />{label}
            </button>
          ))}
        </nav>
        <button className={styles.logout} onClick={onLogout}>
          <LogOut size={17} />Log out
        </button>
      </aside>

      <main className={styles.main}>
        {view === "home" && (
          <HomeView
            user={user}
            wallet={wallet}
            error={walletError}
            onReload={() => void reloadWallet()}
            onNavigate={navigate}
            onTransaction={(tx) => void openTransaction(tx.id)}
          />
        )}
        {view === "pay" && wallet && (
          <PayView
            token={token}
            wallet={wallet}
            onComplete={onPaymentComplete}
          />
        )}
        {view === "pay" && !wallet && (
          <PageMessage title="Wallet unavailable" message={walletError ?? "Loading wallet…"} />
        )}
        {view === "requests" && wallet && (
          <RequestsView
            token={token}
            wallet={wallet}
            onComplete={onPaymentComplete}
          />
        )}
        {view === "requests" && !wallet && (
          <PageMessage title="Requests unavailable" message={walletError ?? "Loading wallet…"} />
        )}
        {view === "history" && (
          <HistoryView token={token} onTransaction={(tx) => void openTransaction(tx.id)} />
        )}
        {view === "profile" && (
          <ProfileView
            token={token}
            user={user}
            onToast={setToast}
          />
        )}
        {view === "admin" && isAdmin && (
          <AdminView token={token} onToast={setToast} />
        )}
      </main>

      {detailLoading && <Sheet title="Transaction detail" onClose={() => setDetailLoading(false)}>Loading transaction…</Sheet>}
      {detailError && (
        <Sheet title="Transaction detail" onClose={() => setDetailError(null)}>
          <Banner tone="danger">{detailError}</Banner>
        </Sheet>
      )}
      {selectedTransaction && (
        <TransactionSheet
          transaction={selectedTransaction}
          onClose={() => setSelectedTransaction(null)}
        />
      )}
      {toast && (
        <Toast>{toast}</Toast>
      )}
    </div>
  );
}

function PageTitle({
  eyebrow,
  title,
  action,
}: {
  eyebrow: string;
  title: string;
  action?: ReactNode;
}) {
  return (
    <div className={styles.pageTitle}>
      <div><p className={styles.eyebrow}>{eyebrow}</p><h1>{title}</h1></div>
      {action}
    </div>
  );
}

function PageMessage({ title, message }: { title: string; message: string }) {
  return <><PageTitle eyebrow="Campus wallet" title={title} /><Banner tone="danger">{message}</Banner></>;
}

function TransactionRow({
  transaction,
  onClick,
}: {
  transaction: TransactionSummary;
  onClick: () => void;
}) {
  const outgoing = transaction.direction === "DEBIT";
  return (
    <button className={styles.transaction} onClick={onClick}>
      <span className={outgoing ? styles.outIcon : styles.inIcon}>
        {outgoing ? <ArrowUpRight size={17} /> : <ArrowDownLeft size={17} />}
      </span>
      <span>
        <b>{transaction.counterparty_name}</b>
        <small>{transaction.counterparty_handle} · {dateLabel(transaction.created_at)}</small>
      </span>
      <strong className={outgoing ? "" : styles.in}>
        {outgoing ? "−" : "+"}₹{formatRupees(transaction.amount_paise)}
      </strong>
    </button>
  );
}

function HomeView({
  user,
  wallet,
  error,
  onReload,
  onNavigate,
  onTransaction,
}: {
  user: UserProfile;
  wallet: Wallet | null;
  error: string | null;
  onReload: () => void;
  onNavigate: (view: View) => void;
  onTransaction: (transaction: TransactionSummary) => void;
}) {
  return (
    <>
      <PageTitle
        eyebrow={user.college_id}
        title={`Welcome, ${user.full_name.split(" ")[0]}.`}
        action={<Avatar initials={initials(user.full_name)} />}
      />
      {error && <Banner tone="danger">{error} <button onClick={onReload}>Retry</button></Banner>}
      <Card className={styles.balance}>
        <div>
          <span>Available campus points</span>
          <strong>{wallet ? `₹${formatRupees(wallet.balance_paise)}` : "—"}</strong>
          {wallet && <small>{wallet.primary_vpa}</small>}
          <Chip>simulation balance</Chip>
        </div>
        <div className={styles.walletIcon}><CreditCard size={28} /></div>
      </Card>
      <div className={styles.quick}>
        {([
          ["Pay", ArrowUpRight, "pay"],
          ["Request", ArrowDownLeft, "requests"],
          ["History", History, "history"],
          ["Profile", UserRound, "profile"],
        ] as [string, LucideIcon, View][]).map(([label, Icon, target]) => (
          <button key={label} onClick={() => onNavigate(target)}>
            <span><Icon size={21} /></span>{label}
          </button>
        ))}
      </div>
      <div className={styles.sectionHeading}>
        <h2>Recent activity</h2>
        <button onClick={() => onNavigate("history")}>See all</button>
      </div>
      <Card>
        {wallet?.recent_transactions.length ? (
          <Timeline>
            {wallet.recent_transactions.map((transaction) => (
              <TransactionRow
                key={transaction.id}
                transaction={transaction}
                onClick={() => onTransaction(transaction)}
              />
            ))}
          </Timeline>
        ) : (
          <p className={styles.muted}>No payments yet. Send or request virtual points to get started.</p>
        )}
      </Card>
      <Banner>Every payment is signed by your device and recorded in a tamper-evident audit chain.</Banner>
    </>
  );
}

async function executeSignedPayment({
  token,
  wallet,
  payeeVpa,
  amountPaise,
  mpin,
  note,
  collectId,
  tamper = false,
}: {
  token: string;
  wallet: Wallet;
  payeeVpa: string;
  amountPaise: number;
  mpin: string;
  note: string;
  collectId?: string;
  tamper?: boolean;
}): Promise<TransactionDetail> {
  const devices = await apiRequest<Device[]>("/devices", token);
  const keyPair = await getOrCreateDeviceKey();
  const publicKey = await exportPublicKeyJwk(keyPair.publicKey);
  const keyIsBound = devices.some(
    (device) =>
      device.status === "active" &&
      device.public_key_jwk.x === publicKey.x &&
      device.public_key_jwk.y === publicKey.y,
  );
  if (!keyIsBound) {
    throw new Error("This browser is not bound yet. Bind it in Profile before paying.");
  }

  const keyResponse = await apiRequest<ServerKeyResponse>("/crypto/server-key", token);
  const txnId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = {
    amount_paise: amountPaise,
    nonce: crypto.randomUUID(),
    note,
    payee_vpa: payeeVpa,
    payer_vpa: wallet.primary_vpa,
    ts: timestamp,
    txn_id: txnId,
  };
  const signature = await signPayload(keyPair.privateKey, payload);
  const { envelope, derivedKey } = await createRequestEnvelope(
    keyResponse.public_key,
    JSON.stringify({
      device_sig: signature.signatureB64,
      mpin,
      payload,
    }),
    txnId,
    timestamp,
  );
  if (tamper && envelope.ct.length > 0) {
    envelope.ct = `${envelope.ct.slice(0, -1)}${envelope.ct.endsWith("A") ? "B" : "A"}`;
  }

  const endpoint = collectId
    ? `/payments/collect/${encodeURIComponent(collectId)}/approve`
    : "/payments/pay";
  const response = await apiRequest<BankReceiptEnvelope>(endpoint, token, {
    method: "POST",
    body: JSON.stringify(envelope),
  });
  await decryptResponseEnvelope(derivedKey, response.envelope, txnId);
  const detail = await apiRequest<TransactionDetail>(
    `/transactions/${encodeURIComponent(txnId)}`,
    token,
  );
  if (!detail.security_lens.bank_signature_verified) {
    throw new Error("The bank receipt signature could not be verified.");
  }
  return detail;
}

function PayView({
  token,
  wallet,
  onComplete,
}: {
  token: string;
  wallet: Wallet;
  onComplete: (message: string) => Promise<void>;
}) {
  const [payee, setPayee] = useState("");
  const [amount, setAmount] = useState("");
  const [mpin, setMpin] = useState("");
  const [resolution, setResolution] = useState<VpaResolution | null>(null);
  const [step, setStep] = useState<"form" | "confirm">("form");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tamper, setTamper] = useState(false);
  const [scannerOpen, setScannerOpen] = useState(false);
  const demoTamperEnabled = import.meta.env.VITE_DEMO_MODE === "true";

  const handleQrResult = useCallback((value: string) => {
    try {
      const scanned = parsePaymentQr(value);
      setPayee(scanned.vpa);
      if (scanned.amount !== undefined) setAmount(scanned.amount);
      setError(null);
      setScannerOpen(false);
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  }, []);

  const reviewPayment = async () => {
    const rupees = Number(amount);
    if (!payee.trim() || !Number.isSafeInteger(rupees) || rupees < 1) {
      setError("Enter a valid campus VPA and an amount of at least ₹1.");
      return;
    }
    if (payee.trim().toLowerCase() === wallet.primary_vpa.toLowerCase()) {
      setError("You cannot send a payment to your own VPA.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const query = new URLSearchParams({ handle: payee.trim() });
      setResolution(await apiRequest<VpaResolution>(`/vpa/resolve?${query}`, token));
      setStep("confirm");
    } catch (failure) {
      setError(getPaymentError(failure));
    } finally {
      setBusy(false);
    }
  };

  const sendPayment = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (mpin.length !== 6 || !resolution) return;
    setError(null);
    setBusy(true);
    try {
      const detail = await executeSignedPayment({
        token,
        wallet,
        payeeVpa: resolution.handle,
        amountPaise: Number(amount) * 100,
        mpin,
        note: "Campus payment",
        tamper: demoTamperEnabled && tamper,
      });
      if (detail.status !== "success") throw new Error("The payment did not complete successfully.");
      await onComplete("Payment complete — bank receipt verified.");
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageTitle
        eyebrow="Virtual campus points"
        title="Send points."
        action={<button className={styles.scan} onClick={() => setScannerOpen(true)}><ScanLine size={18} /> Scan QR</button>}
      />
      {error && <Banner tone="danger">{error}</Banner>}
      <Card className={styles.payCard}>
        {step === "form" ? (
          <>
            <Input
              label="Pay to VPA"
              placeholder="name@gcet"
              autoComplete="off"
              value={payee}
              onChange={(event) => setPayee(event.target.value)}
            />
            <div className={styles.amountDisplay}>
              <span>Amount (whole rupees)</span><strong>₹{amount || "0"}</strong>
            </div>
            <AmountPad value={amount} onChange={setAmount} />
            <Button onClick={() => void reviewPayment()} disabled={busy || !payee || !amount}>
              {busy ? "Checking VPA…" : "Review payment"}
            </Button>
          </>
        ) : (
          <form className={styles.payCard} onSubmit={(event) => void sendPayment(event)}>
            <div className={styles.confirm}>
              <Avatar initials={initials(resolution?.masked_name ?? "")} />
              <div>
                <h2>{resolution?.masked_name}</h2>
                <p>{resolution?.handle}</p>
              </div>
              <Chip>VPA verified</Chip>
            </div>
            <div className={styles.amountDisplay}>
              <span>You are sending</span><strong>₹{Number(amount).toLocaleString("en-IN")}</strong>
            </div>
            <Input
              label="Six-digit MPIN"
              type="password"
              inputMode="numeric"
              autoComplete="current-password"
              pattern="[0-9]{6}"
              maxLength={6}
              value={mpin}
              onChange={(event) => setMpin(event.target.value.replace(/\D/g, "").slice(0, 6))}
            />
            {demoTamperEnabled && (
              <label className={styles.tamper}>
                <input type="checkbox" checked={tamper} onChange={(event) => setTamper(event.target.checked)} />
                Demo tamper test
              </label>
            )}
            <Button type="submit" disabled={busy || mpin.length !== 6}>
              {busy ? "Sending securely…" : "Confirm & send"}
            </Button>
            <Button type="button" variant="ghost" onClick={() => { setStep("form"); setMpin(""); }}>
              Change recipient or amount
            </Button>
          </form>
        )}
      </Card>
      {scannerOpen && (
        <QrScanner onScan={handleQrResult} onClose={() => setScannerOpen(false)} />
      )}
    </>
  );
}

function QrScanner({ onScan, onClose }: { onScan: (value: string) => void; onClose: () => void }) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    let controls: IScannerControls | undefined;
    let complete = false;
    let disposed = false;
    void import("@zxing/browser").then(({ BrowserMultiFormatReader }) => {
      if (disposed) return;
      const reader = new BrowserMultiFormatReader();
      return reader.decodeFromVideoDevice(undefined, video, (result, _error, scannerControls) => {
        controls = scannerControls;
        if (result && !complete) {
          complete = true;
          controls.stop();
          onScan(result.getText());
        }
      });
    }).catch(() => {
      setError("Camera access is unavailable. Allow camera permission and try again.");
    });
    return () => {
      disposed = true;
      controls?.stop();
    };
  }, [onScan]);

  return (
    <Sheet title="Scan a Mini-UPI QR" onClose={onClose}>
      <p className={styles.muted}>Point your camera at a campus payment QR. Review the VPA and amount before sending.</p>
      <video ref={videoRef} className={styles.scannerVideo} aria-label="Camera QR preview" muted playsInline />
      {error && <Banner tone="danger">{error}</Banner>}
    </Sheet>
  );
}

function RequestsView({
  token,
  wallet,
  onComplete,
}: {
  token: string;
  wallet: Wallet;
  onComplete: (message: string) => Promise<void>;
}) {
  const [requests, setRequests] = useState<CollectRequest[]>([]);
  const [payerVpa, setPayerVpa] = useState("");
  const [amount, setAmount] = useState("");
  const [note, setNote] = useState("");
  const [pins, setPins] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadRequests = async () => {
    setError(null);
    try {
      setRequests(await apiRequest<CollectRequest[]>("/payments/collect/incoming", token));
    } catch (failure) {
      setError(getPaymentError(failure));
    }
  };
  useEffect(() => { void loadRequests(); }, [token]);

  const createRequest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setNotice(null);
    try {
      const rupees = Number(amount);
      if (!Number.isSafeInteger(rupees) || rupees < 1) throw new Error("Enter an amount of at least ₹1.");
      const query = new URLSearchParams({ handle: payerVpa.trim() });
      const resolved = await apiRequest<VpaResolution>(`/vpa/resolve?${query}`, token);
      await apiRequest<CollectRequest>("/payments/collect", token, {
        method: "POST",
        body: JSON.stringify({
          payee_vpa: wallet.primary_vpa,
          payer_vpa: resolved.handle,
          amount_paise: rupees * 100,
          note: note.trim() || null,
        }),
      });
      setNotice(`Request sent to ${resolved.masked_name}.`);
      setPayerVpa("");
      setAmount("");
      setNote("");
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  };

  const decline = async (request: CollectRequest) => {
    setBusyId(request.id);
    setError(null);
    try {
      await apiRequest(`/payments/collect/${encodeURIComponent(request.id)}/decline`, token, {
        method: "POST",
      });
      setRequests((current) => current.filter((item) => item.id !== request.id));
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusyId(null);
    }
  };

  const approve = async (request: CollectRequest) => {
    const pin = pins[request.id] ?? "";
    if (pin.length !== 6) return;
    setBusyId(request.id);
    setError(null);
    try {
      const detail = await executeSignedPayment({
        token,
        wallet,
        payeeVpa: request.requester_vpa,
        amountPaise: request.amount_paise,
        mpin: pin,
        note: request.note ?? "Collect request",
        collectId: request.id,
      });
      if (detail.status !== "success") throw new Error("The payment did not complete successfully.");
      await onComplete("Request paid — bank receipt verified.");
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <>
      <PageTitle eyebrow="Ask another campus account" title="Request points." />
      {error && <Banner tone="danger">{error}</Banner>}
      {notice && <Banner>{notice}</Banner>}
      <Card>
        <h2>Create a request</h2>
        <form className={styles.payCard} onSubmit={(event) => void createRequest(event)}>
          <Input label="Request from VPA" placeholder="name@gcet" required value={payerVpa} onChange={(event) => setPayerVpa(event.target.value)} />
          <Input label="Amount (whole rupees)" inputMode="numeric" min="1" step="1" type="number" required value={amount} onChange={(event) => setAmount(event.target.value)} />
          <Input label="Note (optional)" maxLength={200} value={note} onChange={(event) => setNote(event.target.value)} />
          <Button type="submit">Send request</Button>
        </form>
      </Card>
      <Card>
        <div className={styles.sectionHeading}>
          <h2>Incoming requests</h2>
          <button onClick={() => void loadRequests()}>Refresh</button>
        </div>
        {requests.length === 0 ? (
          <p className={styles.muted}>No pending requests addressed to you.</p>
        ) : requests.map((request) => (
          <div className={styles.request} key={request.id}>
            <div>
              <strong>{request.requester_name}</strong>
              <small>{request.requester_vpa} · {request.note || "Payment request"}</small>
              <b>₹{formatRupees(request.amount_paise)}</b>
            </div>
            <Input
              label="MPIN"
              type="password"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              value={pins[request.id] ?? ""}
              onChange={(event) => setPins((current) => ({
                ...current,
                [request.id]: event.target.value.replace(/\D/g, "").slice(0, 6),
              }))}
            />
            <div className={styles.requestActions}>
              <Button
                onClick={() => void approve(request)}
                disabled={busyId === request.id || (pins[request.id] ?? "").length !== 6}
              >
                Pay request
              </Button>
              <Button variant="ghost" onClick={() => void decline(request)} disabled={busyId === request.id}>
                Decline
              </Button>
            </div>
          </div>
        ))}
      </Card>
    </>
  );
}

function HistoryView({
  token,
  onTransaction,
}: {
  token: string;
  onTransaction: (transaction: TransactionSummary) => void;
}) {
  const [transactions, setTransactions] = useState<TransactionSummary[]>([]);
  const [filter, setFilter] = useState<"ALL" | "DEBIT" | "CREDIT">("ALL");
  const [error, setError] = useState<string | null>(null);
  const loadHistory = async () => {
    setError(null);
    try {
      setTransactions(await apiRequest<TransactionSummary[]>("/transactions?limit=100", token));
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  };
  useEffect(() => { void loadHistory(); }, [token]);

  const filtered = transactions.filter((transaction) => filter === "ALL" || transaction.direction === filter);
  return (
    <>
      <PageTitle eyebrow="Your money trail" title="History." action={<Button variant="ghost" onClick={() => void loadHistory()}>Refresh</Button>} />
      {error && <Banner tone="danger">{error}</Banner>}
      <div className={styles.filters}>
        {([
          ["ALL", "All"],
          ["CREDIT", "Received"],
          ["DEBIT", "Sent"],
        ] as const).map(([value, label]) => (
          <button
            className={filter === value ? styles.filterActive : ""}
            key={value}
            onClick={() => setFilter(value)}
            aria-pressed={filter === value}
          >
            {label}
          </button>
        ))}
      </div>
      <Card>
        {filtered.length ? (
          <Timeline>
            {filtered.map((transaction) => (
              <TransactionRow key={transaction.id} transaction={transaction} onClick={() => onTransaction(transaction)} />
            ))}
          </Timeline>
        ) : (
          <p className={styles.muted}>No matching transactions yet.</p>
        )}
      </Card>
    </>
  );
}

function ProfileView({
  token,
  user,
  onToast,
}: {
  token: string;
  user: UserProfile;
  onToast: (message: string) => void;
}) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [vpa, setVpa] = useState<VpaResponse | null>(null);
  const [mpin, setMpin] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadProfileData = async () => {
    setError(null);
    try {
      const [deviceList, address] = await Promise.all([
        apiRequest<Device[]>("/devices", token),
        apiRequest<VpaResponse>("/vpa/me", token),
      ]);
      setDevices(deviceList);
      setVpa(address);
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  };
  useEffect(() => { void loadProfileData(); }, [token]);

  const saveMpin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiRequest("/mpin/set", token, {
        method: "POST",
        body: JSON.stringify({ mpin, password }),
      });
      setMpin("");
      setPassword("");
      onToast("MPIN saved. Remember it; it cannot be retrieved later.");
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const bindThisBrowser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await bindBrowserDevice(token, password);
      setPassword("");
      await loadProfileData();
      onToast("This browser is bound to your account.");
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (device: Device) => {
    setError(null);
    try {
      await apiRequest(`/devices/${encodeURIComponent(device.id)}`, token, { method: "DELETE" });
      await loadProfileData();
      onToast("Device revoked.");
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  };

  const copyVpa = async () => {
    if (!vpa) return;
    try {
      await navigator.clipboard.writeText(vpa.primary_vpa);
      onToast("VPA copied.");
    } catch {
      setError("Clipboard access is unavailable in this browser.");
    }
  };

  return (
    <>
      <PageTitle eyebrow="Account & security" title="Your profile." />
      {error && <Banner tone="danger">{error}</Banner>}
      <Card className={styles.profile}>
        <Avatar initials={initials(user.full_name)} />
        <div>
          <h2>{user.full_name}</h2>
          <p>{user.college_id} · {user.email}</p>
          <Chip>{user.role} · {user.status}</Chip>
        </div>
      </Card>
      <Card>
        <h2>Your payment address</h2>
        <p className={styles.vpa}>{vpa?.primary_vpa ?? "Loading VPA…"}</p>
        <Button variant="ghost" onClick={() => void copyVpa()} disabled={!vpa}>
          <Copy size={16} /> Copy VPA
        </Button>
        {vpa && <QRCard value={vpa.qr_payload} />}
      </Card>
      <Card>
        <h2>Set or change MPIN</h2>
        <p className={styles.muted}>Choose a six-digit number. It is stored as a one-way Argon2id hash and cannot be recovered.</p>
        <form className={styles.payCard} onSubmit={(event) => void saveMpin(event)}>
          <Input label="New six-digit MPIN" type="password" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} minLength={6} required value={mpin} onChange={(event) => setMpin(event.target.value.replace(/\D/g, "").slice(0, 6))} />
          <Input label="Confirm account password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
          <Button type="submit" disabled={busy || mpin.length !== 6}>Save MPIN</Button>
        </form>
      </Card>
      <Card>
        <h2>Bound devices</h2>
        {devices.length === 0 ? (
          <p className={styles.muted}>No browser devices are bound yet.</p>
        ) : devices.map((device) => (
          <div className={styles.device} key={device.id}>
            <ShieldCheck />
            <span>
              <b>{device.label || "Browser"}</b>
              <small>{dateLabel(device.created_at)} · {device.status}</small>
            </span>
            {device.status === "active" ? (
              <Button variant="danger" onClick={() => void revoke(device)}>Revoke</Button>
            ) : <Chip tone="danger">revoked</Chip>}
          </div>
        ))}
        <form className={styles.bindForm} onSubmit={(event) => void bindThisBrowser(event)}>
          <Input label="Password to bind this browser" type="password" required value={password} onChange={(event) => setPassword(event.target.value)} />
          <Button type="submit" variant="ghost" disabled={busy}>Bind this browser</Button>
        </form>
      </Card>
    </>
  );
}

function AdminView({
  token,
  onToast,
}: {
  token: string;
  onToast: (message: string) => void;
}) {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [collegeId, setCollegeId] = useState("");
  const [amount, setAmount] = useState("");
  const [reason, setReason] = useState("");
  const [files, setFiles] = useState<{ departments?: string; classes?: string; users?: string }>({});
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const loadStats = async () => {
    setError(null);
    try {
      setStats(await apiRequest<AdminStats>("/admin/stats", token));
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  };
  useEffect(() => { void loadStats(); }, [token]);

  const topUp = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await apiRequest<{ recipient_vpa: string; amount_paise: number }>("/admin/topup", token, {
        method: "POST",
        body: JSON.stringify({
          college_id: collegeId.trim(),
          amount_paise: Number(amount) * 100,
          reason: reason.trim(),
        }),
      });
      onToast(`Added ₹${formatRupees(response.amount_paise)} to ${response.recipient_vpa}.`);
      setCollegeId("");
      setAmount("");
      setReason("");
      await loadStats();
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const importUsers = async (dryRun: boolean) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await apiRequest("/admin/import", token, {
        method: "POST",
        body: JSON.stringify({
          departments_csv: files.departments ?? null,
          classes_csv: files.classes ?? null,
          users_csv: files.users ?? null,
          dry_run: dryRun,
        }),
      }));
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const verifyAudit = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await apiRequest("/admin/audit/verify", token, { method: "POST" }));
    } catch (failure) {
      setError(getErrorMessage(failure));
    } finally {
      setBusy(false);
    }
  };

  const readCsv = async (field: "departments" | "classes" | "users", file?: File) => {
    if (!file) return;
    try {
      const text = await file.text();
      setFiles((current) => ({ ...current, [field]: text }));
    } catch (failure) {
      setError(getErrorMessage(failure));
    }
  };

  return (
    <>
      <PageTitle eyebrow="Campus controls" title="Admin console." action={<Button variant="ghost" onClick={() => void loadStats()}>Refresh</Button>} />
      {error && <Banner tone="danger">{error}</Banner>}
      {stats && (
        <div className={styles.statGrid}>
          <Card><span>Accounts</span><strong>{stats.total_users.toLocaleString()}</strong></Card>
          <Card><span>Completed payments</span><strong>{stats.total_transactions.toLocaleString()}</strong></Card>
          <Card><span>Virtual volume</span><strong>₹{stats.total_volume_rupees.toLocaleString("en-IN")}</strong></Card>
        </div>
      )}
      <Card>
        <h2>Treasury top-up</h2>
        <form className={styles.payCard} onSubmit={(event) => void topUp(event)}>
          <Input label="Recipient college ID" required value={collegeId} onChange={(event) => setCollegeId(event.target.value)} />
          <Input label="Amount (whole rupees)" type="number" inputMode="numeric" min="1" step="1" required value={amount} onChange={(event) => setAmount(event.target.value)} />
          <Input label="Reason" minLength={3} maxLength={256} required value={reason} onChange={(event) => setReason(event.target.value)} />
          <Button type="submit" disabled={busy}>Top up virtual wallet</Button>
        </form>
      </Card>
      <Card>
        <h2>Verify ledger and audit chain</h2>
        <p className={styles.muted}>Checks zero-sum balances, double-entry history, and the audit hash chain.</p>
        <Button onClick={() => void verifyAudit()} disabled={busy}><ShieldCheck size={17} /> Verify now</Button>
      </Card>
      <Card>
        <h2>Import campus CSV</h2>
        {([
          ["departments", "Departments CSV"],
          ["classes", "Classes CSV"],
          ["users", "Users CSV"],
        ] as const).map(([field, label]) => (
          <Input
            key={field}
            label={`${label}${files[field] ? " · loaded" : ""}`}
            type="file"
            accept=".csv,text/csv"
            onChange={(event) => void readCsv(field, event.target.files?.[0])}
          />
        ))}
        <div className={styles.requestActions}>
          <Button variant="ghost" onClick={() => void importUsers(true)} disabled={busy || !Object.keys(files).length}>Dry-run preview</Button>
          <Button onClick={() => void importUsers(false)} disabled={busy || !Object.keys(files).length}>Import CSV</Button>
        </div>
      </Card>
      {result !== null && <Card><h2>Operation result</h2><pre className={styles.result}>{JSON.stringify(result, null, 2)}</pre></Card>}
    </>
  );
}

function TransactionSheet({
  transaction,
  onClose,
}: {
  transaction: TransactionDetail;
  onClose: () => void;
}) {
  const checks = transaction.security_lens;
  return (
    <Sheet title="Transaction Security Lens" onClose={onClose}>
      <div className={styles.lensHeader}>
        <ShieldCheck />
        <div>
          <strong>{transaction.status === "success" ? "Payment complete" : transaction.status}</strong>
          <span>₹{formatRupees(transaction.amount_paise)} · {dateLabel(transaction.created_at)}</span>
        </div>
      </div>
      <p className={styles.muted}>{transaction.payer_vpa} → {transaction.payee_vpa}</p>
      <HashBlock label="Transaction ID" value={transaction.id} />
      <HashBlock label="Device signature" value={checks.device_signature_verified ? "Verified" : "Not verified"} />
      <HashBlock label="PSP signature" value={checks.psp_signature_verified ? "Verified" : "Not verified"} />
      <HashBlock label="Switch HMAC" value={checks.switch_mac_verified ? "Verified" : "Not verified"} />
      <HashBlock label="Bank receipt" value={checks.bank_signature_verified ? "Signature verified" : "Signature not verified"} />
      {checks.bank_cert_subject && <HashBlock label="Bank certificate" value={checks.bank_cert_subject} />}
      <HashBlock label="Audit chain" value={checks.audit_chain_verified ? "Verified" : "Verification failed"} />
      {checks.audit_chain_seq !== null && <HashBlock label="Audit sequence" value={String(checks.audit_chain_seq)} />}
      {checks.audit_entry_hash && <HashBlock label="Audit entry hash" value={checks.audit_entry_hash} />}
      {transaction.receipt && <details><summary>Signed receipt data</summary><pre className={styles.result}>{JSON.stringify(transaction.receipt, null, 2)}</pre></details>}
    </Sheet>
  );
}
