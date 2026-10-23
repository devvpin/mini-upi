/**
 * Typed API client for the authenticated campus simulation.
 *
 * Crypto concept: bearer-token session authentication.
 * Threat mitigated: unauthenticated access to private wallet and payment data.
 */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function apiRequest<T>(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, { ...options, headers });
  } catch {
    throw new ApiError("Cannot reach the server. Check that the app is running and try again.", 0);
  }

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const payload = body as {
      error?: { message?: string; code?: string };
      detail?: string;
    } | null;
    throw new ApiError(
      payload?.error?.message ?? payload?.detail ?? `Request failed (${response.status}).`,
      response.status,
      payload?.error?.code,
    );
  }
  return body as T;
}

export interface UserProfile {
  id: string;
  college_id: string;
  full_name: string;
  email: string;
  role: "student" | "faculty" | "admin" | "auditor";
  status: string;
  department_code: string | null;
  class_name: string | null;
  must_change_password: boolean;
}

export interface TransactionSummary {
  id: string;
  amount_paise: number;
  direction: "DEBIT" | "CREDIT";
  counterparty_handle: string;
  counterparty_name: string;
  note: string | null;
  status: string;
  created_at: string;
}

export interface Wallet {
  account_id: string;
  balance_paise: number;
  balance_rupees: number;
  primary_vpa: string;
  recent_transactions: TransactionSummary[];
}

export interface CollectRequest {
  id: string;
  requester_vpa: string;
  payer_vpa: string;
  requester_name: string;
  amount_paise: number;
  amount_rupees: number;
  note: string | null;
  status: string;
  created_at: string;
  expires_at: string;
}

export interface Device {
  id: string;
  label: string | null;
  status: string;
  public_key_jwk: JsonWebKey;
  created_at: string;
  revoked_at: string | null;
}

export interface TransactionDetail {
  id: string;
  amount_paise: number;
  amount_rupees: number;
  payer_vpa: string;
  payee_vpa: string;
  payer_name: string;
  payee_name: string;
  direction: "DEBIT" | "CREDIT";
  note: string | null;
  status: string;
  created_at: string;
  completed_at: string | null;
  receipt: Record<string, unknown> | null;
  security_lens: {
    device_signature_verified: boolean;
    psp_signature_verified: boolean;
    switch_mac_verified: boolean;
    bank_signature_verified: boolean;
    bank_cert_subject: string | null;
    bank_cert_issuer: string | null;
    audit_chain_seq: number | null;
    audit_entry_hash: string | null;
    audit_chain_verified: boolean;
  };
}
