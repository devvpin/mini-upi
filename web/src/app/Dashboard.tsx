import { useState } from "react";
import type { ReactNode } from "react";
import { ArrowDownLeft, ArrowUpRight, Copy, CreditCard, History, Home, LogOut, Menu, QrCode, ScanLine, ShieldCheck, UserRound, X } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { AmountPad, Avatar, Banner, Button, Card, Chip, HashBlock, Input, QRCard, Sheet, Timeline, Toast } from "../components/UI";
import { createRequestEnvelope, decryptResponseEnvelope, exportPublicKeyJwk, getOrCreateDeviceKey, signPayload } from "../crypto";
import styles from "./Dashboard.module.css";

type View = "home" | "pay" | "history" | "profile" | "admin";

const transactions = [
  { name: "Cafeteria", handle: "canteen@gcet", amount: "-₹250", time: "Today, 12:42", type: "out" },
  { name: "Aarav Sharma", handle: "22it001@gcet", amount: "+₹500", time: "Yesterday, 16:08", type: "in" },
  { name: "Library deposit", handle: "library@gcet", amount: "-₹100", time: "Mon, 09:15", type: "out" },
];
const navItems: [View, LucideIcon, string][] = [["home", Home, "Home"], ["pay", ArrowUpRight, "Pay"], ["history", History, "History"], ["profile", UserRound, "Profile"], ["admin", ShieldCheck, "Admin"]];
const quickActions: [string, LucideIcon, View][] = [["Pay", ArrowUpRight, "pay"], ["Request", ArrowDownLeft, "pay"], ["Scan", ScanLine, "pay"], ["History", History, "history"]];

export function Dashboard({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [view, setView] = useState<View>("home");
  const [menu, setMenu] = useState(false);
  const [lens, setLens] = useState(false);
  const [payee, setPayee] = useState("");
  const [amount, setAmount] = useState("");
  const [mpin, setMpin] = useState("");
  const [payStep, setPayStep] = useState<"form" | "confirm" | "done">("form");
  const [toast, setToast] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);
  const [paymentError, setPaymentError] = useState<string | null>(null);
  const [tamper, setTamper] = useState(false);

  const doPay = async () => {
    if (payStep === "form" && payee && Number(amount) > 0) setPayStep("confirm");
    else if (payStep === "confirm" && mpin.length === 6) {
      setPaymentError(null);
      try {
        const passwordForSetup = window.prompt("Confirm your password to set the MPIN and bind this browser.") ?? "";
        if (!passwordForSetup) throw new Error("Password confirmation is required for device binding.");
        const device = await getOrCreateDeviceKey();
        const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
        const mpinSetup = await fetch("/api/v1/mpin/set", { method: "POST", headers, body: JSON.stringify({ mpin, password: passwordForSetup }) });
        if (!mpinSetup.ok) throw new Error("Could not configure the six-digit MPIN.");
        const registration = await fetch("/api/v1/devices/register", { method: "POST", headers, body: JSON.stringify({ public_key_jwk: await exportPublicKeyJwk(device.publicKey), label: "browser", password: passwordForSetup }) });
        if (!registration.ok && registration.status !== 409) throw new Error("Could not bind this browser device.");
        const serverResponse = await fetch("/api/v1/crypto/server-key");
        if (!serverResponse.ok) throw new Error("Could not load the server encryption key.");
        const serverKey = (await serverResponse.json()) as { public_key: JsonWebKey };
        const myVpaResponse = await fetch("/api/v1/vpa/me", { headers });
        if (!myVpaResponse.ok) throw new Error("Could not load your payment address.");
        const { primary_vpa } = (await myVpaResponse.json()) as { primary_vpa: string };
        const txnId = crypto.randomUUID();
        const payload = { amount_paise: Math.round(Number(amount) * 100), nonce: crypto.randomUUID(), note: "Browser payment", payee_vpa: payee, payer_vpa: primary_vpa, ts: Math.floor(Date.now() / 1000), txn_id: txnId };
        const signed = await signPayload(device.privateKey, payload);
        const { envelope, derivedKey } = await createRequestEnvelope(serverKey.public_key, JSON.stringify({ device_sig: signed.signatureB64, mpin, payload }), txnId, payload.ts);
        if (tamper) envelope.ct = `${envelope.ct.slice(0, -1)}${envelope.ct.endsWith("A") ? "B" : "A"}`;
        const payment = await fetch("/api/v1/payments/pay", { method: "POST", headers, body: JSON.stringify(envelope) });
        if (!payment.ok) throw new Error("Payment rejected. The encrypted request was not accepted.");
        const body = (await payment.json()) as { envelope: Parameters<typeof decryptResponseEnvelope>[1] };
        await decryptResponseEnvelope(derivedKey, body.envelope, txnId);
        const detail = await fetch(`/api/v1/transactions/${txnId}`, { headers });
        if (!detail.ok) throw new Error("Receipt verification could not be completed.");
        const detailData = (await detail.json()) as { security_lens?: { bank_signature_verified?: boolean } };
        if (!detailData.security_lens?.bank_signature_verified) throw new Error("Bank receipt signature verification failed.");
        setPayStep("done"); setToast("Payment receipt verified by Bank"); setMpin("");
      } catch (error) {
        setPaymentError(error instanceof Error ? error.message : "Payment failed.");
      }
    }
  };
  const nav = (next: View) => { setView(next); setMenu(false); setPayStep("form"); };
  return <div className={styles.shell}>
    {offline && <Banner tone="danger">You are offline. Payments are paused until the connection returns. <button onClick={() => setOffline(false)}>Dismiss</button></Banner>}
    <header className={styles.topbar}><button className={styles.menu} onClick={() => setMenu(!menu)} aria-label="Open navigation">{menu ? <X /> : <Menu />}</button><span className={styles.brand}>Mini<span>-UPI</span></span><button className={styles.connection} onClick={() => setOffline(!offline)} aria-label="Toggle connection"><i /> secure</button></header>
    <aside className={`${styles.sidebar} ${menu ? styles["sidebar--open"] : ""}`}><div className={styles.sidebarBrand}>Mini<span>-UPI</span></div><nav>{navItems.map(([key, Icon, label]) => <button className={view === key ? styles.active : ""} key={key} onClick={() => nav(key)}><Icon size={18} />{label}</button>)}</nav><button className={styles.logout} onClick={onLogout}><LogOut size={17} />Log out</button></aside>
    <main className={styles.main}>
      {view === "home" && <HomeView onNavigate={nav} onLens={() => setLens(true)} />}
      {view === "pay" && <PayView payee={payee} setPayee={setPayee} amount={amount} setAmount={setAmount} mpin={mpin} setMpin={setMpin} step={payStep} error={paymentError} tamper={tamper} setTamper={setTamper} onPay={() => void doPay()} onLens={() => setLens(true)} />}
      {view === "history" && <HistoryView onLens={() => setLens(true)} />}
      {view === "profile" && <ProfileView />}
      {view === "admin" && <AdminView />}
    </main>
    {lens && <Lens onClose={() => setLens(false)} />}
    {toast && <Toast>{toast} <button onClick={() => setToast(null)}>×</button></Toast>}
  </div>;
}

function PageTitle({ eyebrow, title, action }: { eyebrow: string; title: string; action?: ReactNode }) { return <div className={styles.pageTitle}><div><p className={styles.eyebrow}>{eyebrow}</p><h1>{title}</h1></div>{action}</div>; }
function HomeView({ onNavigate, onLens }: { onNavigate: (v: View) => void; onLens: () => void }) { return <><PageTitle eyebrow="Tuesday · 21 October" title="Good morning, Diya." action={<Avatar initials="DP" />} /><Card className={styles.balance}><div><span>Available campus points</span><strong>₹2,450<small>.00</small></strong><Chip>live balance</Chip></div><div className={styles.walletIcon}><CreditCard size={28} /></div></Card><div className={styles.quick}>{quickActions.map(([label, Icon, target]) => <button key={label} onClick={() => onNavigate(target)}><span><Icon size={21} /></span>{label}</button>)}</div><div className={styles.sectionHeading}><h2>Recent activity</h2><button onClick={() => onNavigate("history")}>See all</button></div><Card><Timeline>{transactions.slice(0, 2).map((tx) => <button className={styles.transaction} key={tx.name} onClick={onLens}><span className={tx.type === "in" ? styles.inIcon : styles.outIcon}>{tx.type === "in" ? <ArrowDownLeft size={17} /> : <ArrowUpRight size={17} />}</span><span><b>{tx.name}</b><small>{tx.handle} · {tx.time}</small></span><strong className={tx.type === "in" ? styles.in : ""}>{tx.amount}</strong></button>)}</Timeline></Card><Banner>Every payment is signed by your device and recorded in a tamper-evident audit chain.</Banner></>; }
function PayView({ payee, setPayee, amount, setAmount, mpin, setMpin, step, error, tamper, setTamper, onPay, onLens }: { payee: string; setPayee: (v: string) => void; amount: string; setAmount: (v: string) => void; mpin: string; setMpin: (v: string) => void; step: "form" | "confirm" | "done"; error: string | null; tamper: boolean; setTamper: (v: boolean) => void; onPay: () => void; onLens: () => void }) {
  if (step === "done") return <><PageTitle eyebrow="Payment complete" title="Sent safely." /><Card className={styles.success}><ShieldCheck size={52} /><h2>Receipt verified</h2><p>Your bank-signed receipt is valid and the ledger was updated atomically.</p><Button onClick={onLens}>Open Security Lens</Button></Card></>;
  return <><PageTitle eyebrow="New payment" title="Send points." action={<button className={styles.scan}><QrCode /> Scan QR</button>} />{error && <Banner tone="danger">{error}</Banner>}<Card className={styles.payCard}>{step === "form" ? <><Input label="Pay to VPA" placeholder="name@gcet" value={payee} onChange={(e) => setPayee(e.target.value)} /><div className={styles.amountDisplay}><span>Amount</span><strong>₹{amount || "0"}</strong></div><AmountPad value={amount} onChange={setAmount} /></> : <><div className={styles.confirm}><Avatar initials={payee.slice(0, 2).toUpperCase() || "??"} /><div><h2>{payee}</h2><p>Campus account · available</p></div><Chip>verified VPA</Chip></div><div className={styles.amountDisplay}><span>You are sending</span><strong>₹{amount}</strong></div><Input label="MPIN" value={mpin} onChange={(e) => setMpin(e.target.value.replace(/\D/g, ""))} maxLength={6} inputMode="numeric" type="password" /><label className={styles.tamper}><input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} /> Demo tamper test</label></>}<Button onClick={onPay} disabled={step === "form" ? !payee || !amount : mpin.length !== 6}>{step === "form" ? "Review payment" : "Confirm & send"}</Button></Card>{step === "confirm" && <button className={styles.lensLink} onClick={onLens}><ShieldCheck size={17} /> See what gets protected</button>}</>;
}
function HistoryView({ onLens }: { onLens: () => void }) { return <><PageTitle eyebrow="Your money trail" title="History" action={<Chip>All activity</Chip>} /><div className={styles.filters}><button className={styles.filterActive}>All</button><button>Received</button><button>Sent</button></div><Card><p className={styles.day}>OCTOBER 2026</p>{transactions.map((tx) => <button className={styles.transaction} key={tx.name} onClick={onLens}><span className={tx.type === "in" ? styles.inIcon : styles.outIcon}>{tx.type === "in" ? <ArrowDownLeft size={17} /> : <ArrowUpRight size={17} />}</span><span><b>{tx.name}</b><small>{tx.handle} · {tx.time}</small></span><strong className={tx.type === "in" ? styles.in : ""}>{tx.amount}</strong></button>)}</Card></>; }
function ProfileView() { return <><PageTitle eyebrow="Account & security" title="Your profile" /><Card className={styles.profile}><Avatar initials="DP" /><div><h2>Diya Patel</h2><p>22IT002 · 22it002@gcet</p><Chip>student · active</Chip></div></Card><Card><h2>Bound devices</h2><div className={styles.device}><ShieldCheck /><span><b>This browser</b><small>Registered today · ECDSA P-256</small></span><Chip>trusted</Chip></div><Button variant="ghost">Revoke other devices</Button></Card><Card><h2>Your payment QR</h2><QRCard value="miniupi://pay?vpa=22it002@gcet" /></Card></>; }
function AdminView() { return <><PageTitle eyebrow="Campus controls" title="Admin console" /><div className={styles.statGrid}><Card><span>Active users</span><strong>2,741</strong></Card><Card><span>Today volume</span><strong>₹84,250</strong></Card><Card><span>Audit chain</span><strong className={styles.in}>✓ OK</strong></Card></div><Card><h2>Audit verification</h2><p className={styles.muted}>The chain is checked from genesis to the latest ledger event.</p><Button><ShieldCheck size={17} /> Verify chain</Button></Card><Card><h2>Import campus users</h2><Input label="CSV file" type="file" accept=".csv" /><Button variant="ghost">Dry-run preview</Button></Card></>; }
function Lens({ onClose }: { onClose: () => void }) { return <Sheet title="Transaction Security Lens" onClose={onClose}><div className={styles.lensHeader}><ShieldCheck /><div><strong>All checks passed</strong><span>Bank receipt verified</span></div></div><HashBlock label="txn_id" value="91e1b722…bba7062" /><HashBlock label="device signature" value="3045022100…verified" /><HashBlock label="envelope" value="ECDH P-256 · AES-256-GCM · 1,248 bytes" /><HashBlock label="PSP / Switch" value="PSP cert ✓ · HMAC-SHA256 ✓" /><HashBlock label="audit chain" value="seq 204 · prev → entry hash ✓" /><Button variant="ghost" onClick={() => { navigator.clipboard?.writeText("91e1b722"); }}> <Copy size={16} /> Copy details</Button></Sheet>; }
