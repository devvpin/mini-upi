import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import styles from "./UI.module.css";

export function Button({ children, variant = "primary", ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" | "danger" }) {
  return <button className={`${styles.button} ${styles[`button--${variant}`]}`} {...props}>{children}</button>;
}

export function IconButton(props: ButtonHTMLAttributes<HTMLButtonElement>) {
  return <button className={styles.iconButton} {...props} />;
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`${styles.card} ${className}`}>{children}</section>;
}

export function Chip({ children, tone = "ok" }: { children: ReactNode; tone?: "ok" | "warn" | "danger" | "info" }) {
  return <span className={`${styles.chip} ${styles[`chip--${tone}`]}`}><i />{children}</span>;
}

export function Input({ label, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  return <label className={styles.field}><span>{label}</span><input {...props} /></label>;
}

export function OtpInput({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  return <input className={styles.otp} aria-label="Six digit MPIN" inputMode="numeric" maxLength={6} type="password" value={value} onChange={(event) => onChange(event.target.value.replace(/\D/g, ""))} />;
}

export function AmountPad({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const keys = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫", "0", "Clear"];
  return <div className={styles.amountPad} aria-label="Amount keypad">{keys.map((key) => <button key={key} type="button" onClick={() => key === "Clear" ? onChange("") : key === "⌫" ? onChange(value.slice(0, -1)) : onChange(`${value}${key}`)}>{key}</button>)}</div>;
}

export function Sheet({ children, title, onClose }: { children: ReactNode; title: string; onClose: () => void }) {
  return <div className={styles.sheetBackdrop} role="presentation" onClick={onClose}><section className={styles.sheet} role="dialog" aria-modal="true" aria-label={title} onClick={(event) => event.stopPropagation()}><button className={styles.close} onClick={onClose} aria-label="Close">×</button><h2>{title}</h2>{children}</section></div>;
}

export function Toast({ children, tone = "ok" }: { children: ReactNode; tone?: "ok" | "danger" }) {
  return <div className={`${styles.toast} ${tone === "danger" ? styles["toast--danger"] : ""}`} role="status">{children}</div>;
}

export function Skeleton() { return <div className={styles.skeleton} aria-hidden="true" />; }
export function Avatar({ initials }: { initials: string }) { return <span className={styles.avatar}>{initials}</span>; }
export function QRCard({ value }: { value: string }) { return <div className={styles.qr}><div className={styles.qrPattern} aria-hidden="true" /><span>{value}</span></div>; }
export function Timeline({ children }: { children: ReactNode }) { return <div className={styles.timeline}>{children}</div>; }
export function HashBlock({ label, value }: { label: string; value: string }) { return <div className={styles.hash}><span>{label}</span><code>{value}</code></div>; }
export function Banner({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "danger" }) { return <div className={`${styles.banner} ${tone === "danger" ? styles["banner--danger"] : ""}`} role="alert">{children}</div>; }
export function EmptyState({ title, children }: { title: string; children: ReactNode }) { return <div className={styles.empty}><strong>{title}</strong><span>{children}</span></div>; }
