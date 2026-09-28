"""Rating engine: turns metered usage into invoice line items.

All money is integer kobo. VAT is computed with Decimal and ROUND_HALF_UP
so kobo arithmetic is exact and decimal-safe; floats are never used.

Rating order per operation:
  1. Units up to the plan's included volume are free (covered by the
     subscription base fee).
  2. Units beyond inclusion are billed at the plan's per-operation overage
     rate (kobo per unit). Operations with no overage rate configured are
     hard-capped at the included volume (overage treated as 0 and flagged in
     the line item description).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

VAT_RATE = Decimal("0.075")  # 7.5% Nigerian VAT on services


def parse_json_map(raw: Any) -> dict[str, int]:
    if isinstance(raw, dict):
        return {str(k): int(v) for k, v in raw.items()}
    try:
        return {str(k): int(v) for k, v in json.loads(raw or "{}").items()}
    except (TypeError, ValueError, AttributeError):
        return {}


def vat_kobo(subtotal_kobo: int) -> int:
    """7.5% VAT rounded half-up to whole kobo (Decimal, never float)."""
    return int(
        (Decimal(subtotal_kobo) * VAT_RATE).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    )


@dataclass(frozen=True)
class RatedOperation:
    operation: str
    units: int
    included_units: int
    billable_units: int
    unit_price_kobo: int
    amount_kobo: int


@dataclass
class InvoiceDraft:
    tenant_id: str
    period: str
    line_items: list[dict[str, Any]] = field(default_factory=list)
    subtotal_kobo: int = 0
    vat_kobo: int = 0
    total_kobo: int = 0


def rate_operation(operation: str, units: int, included: dict[str, int],
                   overage_rates: dict[str, int]) -> RatedOperation:
    """Split usage into included vs billable units and rate the overage."""
    included_units = max(0, min(units, included.get(operation, 0)))
    billable = units - included_units
    unit_price = overage_rates.get(operation, 0)
    return RatedOperation(
        operation=operation,
        units=units,
        included_units=included_units,
        billable_units=billable,
        unit_price_kobo=unit_price,
        amount_kobo=billable * unit_price,
    )


def build_invoice_draft(tenant_id: str, period: str, plan: dict[str, Any],
                        overrides: dict[str, Any] | None,
                        rollups: dict[str, int]) -> InvoiceDraft:
    """Build an invoice draft from monthly rollups + plan (tenant overrides
    take precedence over plan defaults — enterprise negotiated pricing)."""
    overrides = overrides or {}
    monthly_fee = int(overrides.get("monthly_fee_kobo", plan.get("monthly_fee_kobo", 0)))
    included = parse_json_map(plan.get("included_units"))
    included.update({k: int(v) for k, v in parse_json_map(overrides.get("included_units")).items()})
    overage = parse_json_map(plan.get("overage_rates_kobo"))
    overage.update({k: int(v) for k, v in parse_json_map(overrides.get("overage_rates_kobo")).items()})

    draft = InvoiceDraft(tenant_id=tenant_id, period=period)
    if monthly_fee > 0:
        draft.line_items.append({
            "kind": "subscription",
            "operation": "subscription",
            "units": 1,
            "unit_price_kobo": monthly_fee,
            "amount_kobo": monthly_fee,
            "description": f"{plan.get('display_name', plan.get('id'))} plan — monthly base fee ({period})",
        })

    for operation in sorted(rollups):
        rated = rate_operation(operation, rollups[operation], included, overage)
        if rated.billable_units == 0:
            continue
        description = (
            f"{operation}: {rated.billable_units} units over inclusion "
            f"({rated.included_units} included of {rated.units} used) "
            f"x {rated.unit_price_kobo} kobo"
        )
        if rated.unit_price_kobo == 0:
            description += " [no overage rate configured — not billed]"
        draft.line_items.append({
            "kind": "overage",
            "operation": operation,
            "units": rated.billable_units,
            "unit_price_kobo": rated.unit_price_kobo,
            "amount_kobo": rated.amount_kobo,
            "description": description,
        })

    draft.subtotal_kobo = sum(item["amount_kobo"] for item in draft.line_items)
    draft.vat_kobo = vat_kobo(draft.subtotal_kobo)
    draft.total_kobo = draft.subtotal_kobo + draft.vat_kobo
    return draft
