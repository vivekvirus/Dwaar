// REQ: GATE-01 (signed QR rendered from the API payload, revoke), UX-05 (scope + effect before revoke, receipt after),
// INV-01 (a pass of another unit/society fails closed). The QR text comes from the API verbatim; nothing is encoded here.
import React, { useState } from "react";
import { View } from "react-native";
import QRCode from "react-native-qrcode-svg";
import { contextKey, useApp } from "../state/AppProvider";
import { useResource } from "../state/resource";
import { ApiError, errorMessage } from "../api/errors";
import { belongsToContext } from "../domain/household";
import { invitationStatus } from "../domain/status";
import { createdCodes } from "../state/created";
import { formatDateTime } from "../i18n";
import { useNav } from "../hooks/useNav";
import { BackBar } from "../ui/chrome";
import { AppText, Banner, Button, Card, Heading, Row, Screen, StatusPill } from "../ui/components";
import { ErrorState, LoadingState, OfflineBanner } from "../ui/states";
import { colors, space } from "../ui/tokens";
import type { Invitation } from "../domain/types";

export function QrBlock({ payload, label }: { payload: string; label: string }) {
  return (
    <View testID="invite-qr" accessible accessibilityRole="image" accessibilityLabel={label} style={{ alignSelf: "center", padding: space.lg, backgroundColor: "#FFFFFF", borderWidth: 2, borderColor: colors.navy }}>
      <QRCode value={payload} size={240} color="#000000" backgroundColor="#FFFFFF" ecl="M" quietZone={8} />
    </View>
  );
}

export function InviteDetailScreen({ invitationId }: { invitationId: string }) {
  const { t, locale, active, services, cache, labels } = useApp();
  const nav = useNav();
  const key = active ? contextKey(active) : null;
  const inv = useResource<Invitation>(cache, key ? `invite:${key}:${invitationId}` : null, async () => {
    const i = await services.api.getInvitation(active!.societyId, invitationId);
    if (!belongsToContext(active!, i)) throw new ApiError(404, { code: "not_found" }); // fail closed
    return i;
  });
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [receipt, setReceipt] = useState<number | null>(null);
  const unit = active ? labels[key!]?.unit ?? "" : "";
  const code = createdCodes.get(invitationId);
  const i = inv.data;

  const revoke = async () => {
    if (!active) return;
    setBusy(true);
    setError(null);
    try {
      const r = await services.api.revokeInvitation(active.societyId, invitationId);
      setReceipt(r.revoked_version ?? r.version);
      setConfirming(false);
      createdCodes.clear();
      await inv.refresh();
    } catch (e) {
      setError(errorMessage(e, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen testID="screen-invite-detail" refreshing={inv.refreshing} onRefresh={() => void inv.refresh()} refreshLabel={t("app.state.refresh")}>
      <BackBar onBack={nav.back} />
      {inv.offline && i ? <OfflineBanner /> : null}
      {inv.loading ? <LoadingState /> : null}
      {!inv.loading && inv.error && !i ? <ErrorState error={inv.error} onRetry={inv.refresh} /> : null}
      {i ? (
        <View>
          <Heading>{code ? t("app.invite.created") : t("app.invite.title")}</Heading>
          {(() => {
            const s = invitationStatus(i);
            return <StatusPill testID="invite-status" label={t(s.key)} glyph={s.glyph} tone={s.tone} />;
          })()}
          <View style={{ height: space.md }} />
          {i.state === "active" && i.qr ? (
            <View>
              <QrBlock payload={i.qr} label={t("app.invite.qr_label")} />
              <AppText variant="small" muted style={{ textAlign: "center", marginVertical: space.sm }}>{t("app.invite.qr_note")}</AppText>
            </View>
          ) : (
            <Banner tone="warning" testID="invite-not-active">{t("app.invite.not_active")}</Banner>
          )}
          {i.state === "active" && i.has_code ? (
            <Card testID="invite-code-card">
              <AppText variant="small" muted>{t("app.invite.code")}</AppText>
              {code ? (
                <View>
                  <AppText testID="invite-code" variant="title" accessibilityLabel={`${t("app.invite.code")}: ${code.split("").join(" ")}`} style={{ letterSpacing: 4 }}>{code}</AppText>
                  <AppText variant="small" muted>{t("app.invite.code_once")}</AppText>
                </View>
              ) : (
                <AppText variant="small" muted>{t("app.invite.code_gone")}</AppText>
              )}
            </Card>
          ) : null}
          <Card>
            <Row label={t("app.invite.purpose")} value={i.purpose} />
            <Row label={t("app.invite.people")} value={String(i.people_count)} />
            <Row label={t("app.invite.starts")} value={`${formatDateTime(i.window_start, locale)} → ${formatDateTime(i.window_end, locale)}`} />
            <Row label={t("app.invite.uses", { uses: i.uses, max: i.max_uses })} value={t(invitationStatus(i).key)} />
            {i.vehicle_plate ? <Row label={t("app.invite.vehicle")} value={i.vehicle_plate} /> : null}
          </Card>

          {receipt !== null ? <Banner tone="success" testID="invite-revoked-receipt">{t("app.invite.revoked_receipt", { version: receipt })}</Banner> : null}
          {error ? <Banner tone="danger" alert>{error}</Banner> : null}
          {i.state === "active" ? (
            confirming ? (
              <Card testID="revoke-confirm">
                <AppText>{t("app.invite.revoke_scope", { unit })}</AppText>
                <View style={{ height: space.md }} />
                <Button testID="btn-revoke-confirm" variant="danger" label={t("app.invite.revoke_confirm")} onPress={revoke} busy={busy} />
                <View style={{ height: space.sm }} />
                <Button label={t("common.action.cancel")} variant="secondary" onPress={() => setConfirming(false)} disabled={busy} />
              </Card>
            ) : (
              <Button testID="btn-revoke" variant="danger" label={t("app.invite.revoke")} onPress={() => setConfirming(true)} />
            )
          ) : null}
          <View style={{ height: space.md }} />
          <Button testID="btn-to-visitors" label={t("app.nav.visitors")} variant="secondary" onPress={() => nav.go("/visitors")} />
        </View>
      ) : null}
    </Screen>
  );
}
