// REQ: GATE-03 (409 already_decided / request_expired never resurrect a request), GATE-02, INV-07, UX-04, UX-05 (scope,
// effect and an outcome receipt), PRD 12.3. All state shown here comes from the backend; "approved" is never "entered".
import React, { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { View } from "react-native";
import { ApiError, errorMessage, errorRequestId } from "../api/errors";
import { belongsToContext } from "../domain/household";
import { entryLine, requestStatus } from "../domain/status";
import { useApp } from "../state/AppProvider";
import { createDecisionCommand, flowReducer, initialFlow, submitDecision, type FlowState } from "../state/approvalFlow";
import { useCountdown } from "../hooks/useCountdown";
import { useNav } from "../hooks/useNav";
import { formatDateTime } from "../i18n";
import { POLL_INTERVAL_MS } from "../config";
import { AppText, Banner, Button, Card, Heading, Row, Screen, StatusPill } from "../ui/components";
import { ExpiredNote, LoadingState, OfflineBanner } from "../ui/states";
import { BackBar } from "../ui/chrome";
import { space } from "../ui/tokens";
import type { ApprovalRequest, CanonicalDecision } from "../domain/types";

export function ApprovalScreen({ requestId }: { requestId: string }) {
  const { t, locale, active, services, labels } = useApp();
  const nav = useNav();
  const [flow, dispatch] = useReducer(flowReducer, initialFlow as FlowState);
  const [offline, setOffline] = useState(false);
  const [fetchedAt, setFetchedAt] = useState<number | null>(null);
  const flowRef = useRef(flow);
  flowRef.current = flow;
  const activeRef = useRef(active);
  activeRef.current = active;

  const load = useCallback(async () => {
    const ctx = activeRef.current;
    if (!ctx) return;
    try {
      const r = await services.api.getApprovalRequest(ctx.societyId, requestId);
      setOffline(false);
      if (!belongsToContext(ctx, r)) {
        // an id that is not this home's (e.g. from another society or a stale link) fails closed as "not found"
        dispatch({ type: "load_failed", error: new ApiError(404, { code: "not_found" }) });
        return;
      }
      setFetchedAt(Date.now());
      dispatch({ type: "loaded", request: r });
    } catch (e) {
      setOffline(e instanceof Error && e.name === "NetworkError");
      dispatch({ type: "load_failed", error: e });
    }
  }, [services.api, requestId]);

  useEffect(() => {
    void load();
  }, [load]);

  // poll while pending (pull-to-refresh is the other path; push arrives in slice 4)
  useEffect(() => {
    if (flow.phase !== "ready") return;
    const id = setInterval(() => void load(), POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [flow.phase, load]);

  // after a stale_version answer the fresh request is fetched; the screen never lets the person act on stale data
  useEffect(() => {
    if (flow.phase === "ready" && flow.notice === "stale") void load();
  }, [flow, load]);

  const send = useCallback(
    async (command: Parameters<typeof submitDecision>[1]) => {
      const action = await submitDecision(services.api, command);
      dispatch(action);
      if (action.type === "failed") void load(); // learn the canonical state after any failure (offline reload will just fail again)
    },
    [services.api, load],
  );

  const decide = (decision: "approve" | "deny") => {
    if (flow.phase !== "ready" || !active) return;
    const command = createDecisionCommand(flow.request, active.societyId, decision);
    dispatch({ type: "submit", command });
    void send(command);
  };
  const retry = () => {
    if (flow.phase !== "send_failed") return;
    // SAME command: same Idempotency-Key and client_action_id, so the server cannot apply it twice
    dispatch({ type: "submit", command: flow.command });
    void send(flow.command);
  };

  const countdown = useCountdown(flow.request?.status === "pending" ? flow.request.expires_in_seconds : null, fetchedAt);
  const unitLabel = flow.request?.unit_label ?? "";
  const req = flow.request;

  return (
    <Screen testID="screen-approval" refreshing={false} onRefresh={() => void load()} refreshLabel={t("app.state.refresh")}>
      <BackBar onBack={nav.back} />
      <Heading>{t("app.approval.title")}</Heading>
      {offline && req ? <OfflineBanner /> : null}
      {flow.phase === "loading" ? <LoadingState /> : null}

      {flow.phase === "not_available" ? (
        <View testID="approval-not-available">
          <Banner tone="danger" alert>{t("app.approval.not_found")}</Banner>
        </View>
      ) : null}

      {flow.phase === "error" ? (
        <View testID="approval-error">
          <Banner tone="danger" alert>{errorMessage(flow.error, t)}</Banner>
          {errorRequestId(flow.error) ? <AppText variant="small" muted>{t("errors.request_id.label", { request_id: errorRequestId(flow.error) ?? "-" })}</AppText> : null}
          <Button label={t("app.state.retry")} variant="secondary" onPress={() => void load()} />
        </View>
      ) : null}

      {req ? <RequestDetails r={req} unitLabel={unitLabel} societyName={active ? labels[`${active.societyId}:${active.unitId}:${active.role}`]?.society : undefined} /> : null}

      {(flow.phase === "ready" || flow.phase === "submitting" || flow.phase === "send_failed") && req ? (
        <View>
          {flow.phase === "ready" && flow.notice === "stale" ? <Banner tone="warning" alert testID="approval-stale">{t("app.approval.stale")}</Banner> : null}
          <View style={{ marginVertical: space.sm }}>
            <StatusPill testID="approval-status" label={t(requestStatus(req).key)} glyph={requestStatus(req).glyph} tone={requestStatus(req).tone} />
          </View>
          {countdown !== null ? <AppText testID="approval-countdown" style={{ marginBottom: space.sm }}>{t("app.approval.expires_in", { seconds: countdown })}</AppText> : null}
          <Row label={t("app.approval.entry")} value={t(entryLine(req.entry_observed))} />
          <Card>
            <AppText>{t("app.approval.effect_unknown_minutes")}</AppText>
            <AppText style={{ marginTop: space.sm }}>{t("app.approval.effect_deny")}</AppText>
            <AppText variant="small" muted style={{ marginTop: space.sm }}>{t("app.approval.auto_allow_note")}</AppText>
          </Card>
          {flow.phase === "submitting" ? <Banner tone="info" testID="approval-sending">{t("app.approval.sending")}</Banner> : null}
          {flow.phase === "send_failed" ? (
            <View testID="approval-send-failed">
              <Banner tone="warning" alert>{t("app.approval.not_sent")}</Banner>
              <AppText variant="small" muted style={{ marginBottom: space.sm }}>{errorMessage(flow.error, t)}</AppText>
              <Button testID="btn-retry" label={t("app.state.retry")} onPress={retry} />
            </View>
          ) : (
            <View style={{ gap: space.md }}>
              <Button testID="btn-approve" glyph="✓" label={t("resident.approval.approve")} onPress={() => decide("approve")} busy={flow.phase === "submitting"} />
              <Button testID="btn-deny" glyph="✕" variant="danger" label={t("resident.approval.deny")} onPress={() => decide("deny")} disabled={flow.phase === "submitting"} />
            </View>
          )}
          <AppText variant="small" muted style={{ marginTop: space.lg }}>{t("resident.fallback.call_note")}</AppText>
        </View>
      ) : null}

      {flow.phase === "closed" ? <ClosedView state={flow} locale={locale} /> : null}
    </Screen>
  );
}

function RequestDetails({ r, unitLabel, societyName }: { r: ApprovalRequest; unitLabel: string; societyName?: string }) {
  const { t } = useApp();
  return (
    <Card testID="approval-details">
      <Row label={t("app.approval.visitor")} value={r.visitor.alias ?? t("app.visitors.visitor_unnamed")} />
      <Row label={t("app.approval.kind")} value={r.visitor.kind} />
      <Row label={t("app.approval.people")} value={String(r.visitor.people_count)} />
      {r.visitor.vehicle_plate ? <Row label={t("app.approval.vehicle")} value={r.visitor.vehicle_plate} /> : null}
      <Row label={t("app.approval.destination")} value={`${societyName ? `${societyName} · ` : ""}${t("common.unit.label", { unit: unitLabel })}`} />
    </Card>
  );
}

function ClosedView({ state, locale }: { state: Extract<FlowState, { phase: "closed" }>; locale: ReturnType<typeof useApp>["locale"] }) {
  const { t } = useApp();
  const { result, how, request } = state;
  const status = requestStatus({ status: result.status, entry_observed: result.entry_observed });
  const approved = result.status === "approved";
  return (
    <View testID="approval-closed">
      {result.status === "expired" ? (
        <ExpiredNote message={request ? t("app.approval.expired_at", { time: formatDateTime(request.expires_at, locale) }) : t("errors.request_expired")} />
      ) : null}
      {how === "decided_elsewhere" ? (
        <Banner tone="info" alert testID="approval-decided-elsewhere" title={t("app.approval.other_decided")}>
          {state.decidedByRole ? t("app.approval.other_decided_by", { role: roleLabel(state.decidedByRole, t) }) : t("errors.already_decided")}
        </Banner>
      ) : null}
      {how === "decided_here" && result.status !== "pending" ? (
        <Banner tone={approved ? "success" : "info"} testID="approval-decided-here">
          {approved ? t("app.approval.decided_approved") : t("app.approval.decided_denied")}
        </Banner>
      ) : null}
      {result.status === "cancelled" ? <Banner tone="neutral">{t("app.approval.cancelled")}</Banner> : null}
      <View style={{ marginVertical: space.sm }}>
        <StatusPill testID="approval-status" label={t(status.key)} glyph={status.glyph} tone={status.tone} />
      </View>
      <Row testID="approval-entry" label={t("app.approval.entry")} value={t(entryLine(result.entry_observed))} />
      {approved ? (
        <View>
          {result.permission_expires_at ? <AppText testID="approval-permission">{t("app.approval.permission_until", { time: formatDateTime(result.permission_expires_at, locale) })}</AppText> : null}
          <AppText variant="small" muted style={{ marginTop: space.xs }}>{t("resident.approval.not_entered_note")}</AppText>
        </View>
      ) : null}
      {result.status === "expired" ? <AppText variant="small" muted style={{ marginTop: space.sm }}>{t("app.approval.guard_options")}</AppText> : null}
      {result.decision_id ? <Receipt result={result} /> : null}
      <View style={{ height: space.lg }} />
      <BackHome />
    </View>
  );
}

function Receipt({ result }: { result: CanonicalDecision }) {
  const { t } = useApp();
  return (
    <Card testID="approval-receipt" style={{ marginTop: space.md }}>
      <AppText variant="label" accessibilityRole="header">{t("app.approval.receipt")}</AppText>
      <AppText variant="small">{t("app.approval.receipt_id", { id: (result.decision_id ?? "").slice(-12) })}</AppText>
      <AppText variant="small">{t("app.approval.receipt_version", { version: result.version })}</AppText>
    </Card>
  );
}

function BackHome() {
  const { t } = useApp();
  const nav = useNav();
  return <Button testID="btn-back-home" label={t("resident.home.title")} variant="secondary" onPress={() => nav.go("/")} />;
}

function roleLabel(role: string, t: ReturnType<typeof useApp>["t"]): string {
  if (role === "owner_occ" || role === "tenant" || role === "family") return t(`app.role.${role}` as const);
  return role;
}

