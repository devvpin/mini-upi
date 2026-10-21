"""
bank.schemas — Request and response models for wallet, VPA, and transactions.

Crypto concept: Privacy preservation via display-name masking in directory lookup.
Threat mitigated: Full-directory harvesting and enumeration of campus users.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class TransactionSummary(BaseModel):
    id: uuid.UUID
    amount_paise: int
    direction: str  # DEBIT or CREDIT
    counterparty_handle: str
    counterparty_name: str
    note: str | None = None
    status: str
    created_at: datetime


class WalletResponse(BaseModel):
    account_id: uuid.UUID
    balance_paise: int
    balance_rupees: float
    primary_vpa: str
    recent_transactions: list[TransactionSummary]


class VpaResolveResponse(BaseModel):
    handle: str
    masked_name: str


class VpaMeResponse(BaseModel):
    primary_vpa: str
    all_vpas: list[str]
    qr_payload: str


class TopupRequest(BaseModel):
    college_id: str | None = None
    vpa: str | None = None
    amount_paise: int = Field(..., gt=0, le=50_000_000)  # Max ₹500,000 topup per action
    reason: str = Field(..., min_length=3, max_length=256)


class TopupResponse(BaseModel):
    txn_id: uuid.UUID
    recipient_college_id: str
    recipient_vpa: str
    amount_paise: int
    new_balance_paise: int
    reason: str
