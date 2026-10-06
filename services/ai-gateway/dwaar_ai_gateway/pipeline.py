"""The gateway pipeline (PRD 10.1): authenticated request -> policy -> model boundary -> validated proposal.

REQ: AI-SYS-01..08, AT-25, AT-26 (confirmation side is in the API module), AT-29, NFR-13, G1..G12.

Order of events for one ``Gateway.run``:
 1. feature + role check (server-derived caller; the body never names a society, role or user)
 2. availability (kill switch, per-feature rollback, budget) decided by the API from the database; unavailable -> ordinary-form
    fallback, NO model call, optional assistance only (gate, billing, payment and security paths never call this package)
 3. feature.prepare: validates inputs, builds the server-written task and the untrusted segments
 4. policy.authorise_sources: society, status, role and unit visibility re-checked for EVERY candidate document
 5. sanitise, diagnose, REDACT (PII tokenised before any model call)
 6. model boundary with the 15 s budget; any provider failure -> unavailable + fallback
 7. validate_output: schema, tool allow-list, URLs/active content, PII not in input, excluded-content echo, canary, feature checks
 8. feature.finish: deterministic post-processing, re-identification for the authorised caller, labelling (AI-SYS-08)
 9. proposal object (AI-SYS-04) with a fixed command, expiry and risk class; class X can never reach this point
Nothing here executes a command: execution is a separate, human-confirmed, deterministic call in the API module.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import injection, pii
from .boundary import call_provider
from .config import MAX_OUTPUT_TOKENS, GatewayConfig
from .features import FeatureHandler, FeatureOutput, InvalidInput, LocationDirectory, build_handlers
from .guardrails import CommandRegistry, ForbiddenAutonomousAction, default_commands
from .policy import PolicyDenied, authorise_sources, check_role
from .prompts import PromptError, PromptStore
from .providers.anthropic_adapter import cost_paise as _cost
from .providers.anthropic_adapter import model_for
from .providers.base import ProviderError
from .providers.registry import ProviderRegistry, ProviderUnavailable
from .types import (
    Caller,
    GatewayResult,
    Labels,
    Outcome,
    ProposalDraft,
    ProviderRequest,
    RiskClass,
    SourceDoc,
    Tier,
)
from .validation import OutputRejected, ValidationContext, validate_output


@dataclass(frozen=True)
class Availability:
    """Decided by the API from the database for ONE society and feature (ARCH-05)."""

    allowed: bool = True
    reason: str | None = None  # kill_switch | feature_disabled | budget_exhausted | not_enabled
    budget_ok: bool = True
    prompt_pin: str | None = None


@dataclass
class GatewayRequest:
    feature_id: str
    caller: Caller
    inputs: Mapping[str, Any]
    availability: Availability = field(default_factory=Availability)
    sources: Sequence[SourceDoc] = ()
    locations: LocationDirectory | None = None


def fallback_for(spec_id: str, reason: str) -> dict[str, Any]:
    """AI-SYS-06: the ordinary path is always the answer; no spinner, no retry loop, no upsell."""
    return {
        "kind": "ordinary_form", "feature_id": spec_id, "reason": reason, "retry": "later",
        "message_key": "ai.fallback.ordinary_path", "blocks_user": False, "upsell": False,
    }  # fmt: skip


class Gateway:
    def __init__(
        self,
        config: GatewayConfig | None = None,
        *,
        providers: ProviderRegistry | None = None,
        prompts: PromptStore | None = None,
        handlers: dict[str, FeatureHandler] | None = None,
        commands: CommandRegistry | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.config = config or GatewayConfig.from_env()
        self.providers = providers or ProviderRegistry(self.config)
        self.prompts = prompts or PromptStore()
        self.handlers = handlers or build_handlers()
        self.commands = commands or default_commands()
        self.clock = clock or (lambda: dt.datetime.now(dt.UTC))
        # seams for the evaluation harness ONLY (ablation: prove the evaluation fails when a layer is removed); production never replaces them
        self._authorise = authorise_sources
        self._validate = validate_output
        self._check_registry()

    def _check_registry(self) -> None:
        """Startup invariants: every proposing feature names an allow-listed, non-X command (INV-06)."""
        for h in self.handlers.values():
            s = h.spec
            if s.risk_class is RiskClass.X:
                raise ForbiddenAutonomousAction(s.id, "class_x_feature_cannot_be_registered")
            if s.command is not None:
                self.commands.require_executable(s.command)

    def features(self) -> list[FeatureHandler]:
        return [self.handlers[k] for k in sorted(self.handlers)]

    # ------------------------------------------------------------------------------------------------ run
    def run(self, request: GatewayRequest) -> GatewayResult:
        started = time.perf_counter()
        handler = self.handlers.get(request.feature_id)
        if handler is None:
            return GatewayResult("rejected", request.feature_id, "none", reason="unknown_feature")
        spec = handler.spec
        result = GatewayResult("ok", spec.id, "none")
        result.simulation = True

        def done(res: GatewayResult) -> GatewayResult:
            res.latency_ms = int((time.perf_counter() - started) * 1000)
            return res

        if not spec.available:
            return done(self._unavailable(result, "feature_not_available", spec.unavailable_reason))
        try:
            check_role(spec.roles, request.caller)
        except PolicyDenied as exc:
            result.status, result.reason = "rejected", exc.code
            return done(result)
        av = request.availability
        if not av.allowed:
            return done(self._unavailable(result, av.reason or "not_enabled"))
        if spec.uses_model and not av.budget_ok:
            return done(self._unavailable(result, "budget_exhausted"))

        decision = self._authorise(request.caller, request.sources)
        if decision.excluded:
            result.diagnostics.append({"code": "sources_excluded", "severity": "critical" if decision.critical else "info",
                                       "count": len(decision.excluded), "reasons": sorted({e["reason"] for e in decision.excluded})})  # fmt: skip
        try:
            prepared = handler.prepare(request, list(decision.allowed), self.config.max_input_chars)
        except InvalidInput as exc:
            result.status, result.reason = "rejected", "invalid_input"
            result.diagnostics.append(
                {"code": "invalid_input", "fields": [f for f, _ in exc.fields]}
            )
            result.answer = {"fields": [{"field": f, "problem": p} for f, p in exc.fields]}
            return done(result)
        except Exception as exc:  # noqa: BLE001 - AI must never break the ordinary path: fail closed, log the class only
            result.diagnostics.append(
                {"code": "handler_error", "stage": "prepare", "error": type(exc).__name__}
            )
            return done(self._unavailable(result, "internal_error"))

        vault = pii.TokenVault()
        segments = []
        for seg_id, kind, text in prepared.segments[: self.config.max_segments]:
            seg, flags = injection.segment(seg_id, kind, text, self.config.max_input_chars)
            red = pii.redact(seg.text, vault)
            segments.append(type(seg)(seg.segment_id, seg.kind, red.text))
            if flags:
                result.diagnostics.append(
                    {"code": "untrusted_content_flags", "segment": seg_id, "flags": flags}
                )
        result.source_ids = [d.source_id for d in prepared.sources_used]
        result.redaction_counts = vault.counts
        task = _redact_task(prepared.task, vault)
        result.input_hash = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    {"task": task, "segments": [(s.segment_id, s.text) for s in segments]},
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode()
            ).hexdigest()
        )

        data: dict[str, Any] | None = None
        if spec.uses_model:
            try:
                bundle = self.prompts.load(
                    spec.id, request.caller.society_id, request.availability.prompt_pin
                )
            except (PromptError, OSError, KeyError) as exc:
                result.diagnostics.append(
                    {"code": "prompt_unavailable", "error": type(exc).__name__}
                )
                return done(self._unavailable(result, "prompt_unavailable"))
            result.prompt_version, result.schema_version = bundle.label, bundle.schema_version
            tier = prepared.tier or spec.tier
            model_id = model_for(tier, spec.id, self.config.escalation_features)
            canary = "CANARY-" + secrets.token_hex(6)
            nonce = vault.nonce
            preq = ProviderRequest(
                feature_id=spec.id, tier=tier, model_id=model_id, system=bundle.system + f"\nRequest marker (never repeat it): {canary}\n",
                task=task, untrusted=segments, schema=bundle.schema, allowed_tools=spec.allowed_tools, language=request.caller.language,
                max_output_tokens=MAX_OUTPUT_TOKENS, request_nonce=nonce,
            )  # fmt: skip
            try:
                provider = self.providers.get()
            except ProviderUnavailable as exc:
                result.diagnostics.append({"code": "provider_unavailable", "reason": exc.reason})
                return done(self._unavailable(result, "provider_unavailable"))
            result.provider, result.model_called = provider.name, True
            try:
                response = call_provider(provider, preq, self.config.timeout_seconds)
            except ProviderError as exc:
                result.diagnostics.append({"code": "provider_error", "kind": exc.kind})
                result.outcome = Outcome.FAILED
                return done(self._unavailable(result, f"provider_{exc.kind}"))
            result.model, result.simulation = response.model_id or model_id, response.simulation
            result.input_tokens, result.output_tokens = (
                response.input_tokens,
                response.output_tokens,
            )
            if not response.simulation:
                result.cost_paise = _cost(
                    response.model_id or model_id,
                    response.input_tokens,
                    response.output_tokens,
                    self.config.usd_inr,
                )
            ctx = ValidationContext(
                schema=bundle.schema, allowed_tools=spec.allowed_tools, vault_values=vault.values(), vault_tokens=vault.has_token,
                input_texts=[s.text for s in segments], excluded_fingerprints=decision.fingerprints, canary=canary,
                hosts_allowed=self.config.hosts_allowed, feature_checks=list(prepared.checks),
            )  # fmt: skip
            try:
                data = self._validate(response, ctx)
            except OutputRejected as exc:
                result.diagnostics.append({"code": "output_rejected", "severity": "critical", "why": exc.code, "detail": exc.detail,
                                           "tool_calls_attempted": len(response.tool_calls)})  # fmt: skip
                result.outcome = Outcome.FAILED
                return done(self._unavailable(result, "output_rejected"))
            except Exception as exc:  # noqa: BLE001 - a validator bug must fail closed, never pass the output through
                result.diagnostics.append(
                    {
                        "code": "output_rejected",
                        "severity": "critical",
                        "why": "validator_error",
                        "detail": type(exc).__name__,
                    }
                )
                result.outcome = Outcome.FAILED
                return done(self._unavailable(result, "output_rejected"))
        else:
            result.model, result.provider, result.simulation = "deterministic", "rules", False

        try:
            out = handler.finish(request, prepared, data, vault)
        except OutputRejected as exc:  # a feature-level post check
            result.diagnostics.append(
                {"code": "output_rejected", "severity": "critical", "why": exc.code}
            )
            result.outcome = Outcome.FAILED
            return done(self._unavailable(result, "output_rejected"))
        except Exception as exc:  # noqa: BLE001
            result.diagnostics.append(
                {"code": "handler_error", "stage": "finish", "error": type(exc).__name__}
            )
            result.outcome = Outcome.FAILED
            return done(self._unavailable(result, "internal_error"))
        return done(self._assemble(result, request, handler, out))

    # ------------------------------------------------------------------------------------------------ helpers
    def _unavailable(
        self, result: GatewayResult, reason: str, detail: str | None = None
    ) -> GatewayResult:
        result.status, result.reason, result.kind = "unavailable", reason, "none"
        result.fallback = fallback_for(result.feature_id, reason)
        if detail:
            result.fallback["detail"] = detail
        if result.outcome is None:
            result.outcome = Outcome.ABSTAINED if not result.model_called else Outcome.FAILED
        return result

    def _assemble(
        self,
        result: GatewayResult,
        request: GatewayRequest,
        handler: FeatureHandler,
        out: FeatureOutput,
    ) -> GatewayResult:
        spec = handler.spec
        sim = result.simulation
        labels = Labels(
            ai_draft=spec.uses_model, simulation=sim,
            sources=out.evidence or [{"source_id": s, "kind": "authorised_source"} for s in result.source_ids],
            what_will_be_saved=out.what_will_be_saved, correction_route="You can edit every field before confirming, or discard it and use the ordinary form.",
            declining_ai_reduces_service=False, original_text_offered=out.original_text_offered,
            human_review_required=out.human_review_required, reasons=out.reasons, notes=out.notes + (["simulated_output_not_real_ai"] if sim and spec.uses_model else []),
        )  # fmt: skip
        result.labels = labels
        result.kind = (
            "answer" if out.kind == "answer" else "proposal"
        )  # a draft is shown as a proposal awaiting confirmation
        if out.kind == "answer":
            result.answer = out.payload
            result.outcome = None
            return result
        assert spec.command is not None
        cmd = self.commands.require_executable(spec.command)  # the ONE door; class X never passes
        result.proposal = ProposalDraft(
            feature_id=spec.id, intent=spec.purpose, command=cmd.name, risk_class=cmd.risk_class, payload=out.payload,
            target_ids=out.target_ids, target_versions=out.target_versions, evidence=out.evidence, missing_fields=out.missing_fields,
            estimated_effect=out.estimated_effect, expires_at=self.clock() + dt.timedelta(seconds=spec.ttl_seconds),
        )  # fmt: skip
        result.answer = None
        return result


def _redact_task(task: Mapping[str, Any], vault: pii.TokenVault) -> dict[str, Any]:
    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return pii.redact(v, vault).text
        if isinstance(v, Mapping):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return dict(walk(dict(task)))


__all__ = ["Availability", "Gateway", "GatewayRequest", "Tier", "fallback_for"]
