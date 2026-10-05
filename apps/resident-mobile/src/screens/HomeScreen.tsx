// REQ: UX-01 (pending approval pinned at the top; quick actions invite / approve / view visitors; operational messages
// separate from community content), PRD 6 states, INV-07. "Pay dues", "Report an issue" and "Community" are NOT built yet
// and are therefore not shown at all (no empty navigation). Community content has no API yet: the section is absent.
import React, { useEffect, useRef } from "react";
import { View } from "react-native";
import { contextKey, useApp } from "../state/AppProvider";
import { useResource } from "../state/resource";
import { belongsToContext } from "../domain/household";
import { requestStatus, visitStatus } from "../domain/status";
import { useCountdown } from "../hooks/useCountdown";
import { useNav } from "../hooks/useNav";
import { formatDateTime } from "../i18n";
import { POLL_INTERVAL_MS } from "../config";
import { AppText, Banner, Button, Card, Heading, Screen, StatusPill } from "../ui/components";
import { ErrorState, LoadingState, OfflineBanner } from "../ui/states";
import { space } from "../ui/tokens";
import type { ApprovalRequest } from "../domain/types";

function PendingCard({ r, anchor, onOpen, onExpiredLocally }: { r: ApprovalRequest; anchor: number | null; onOpen: () => void; onExpiredLocally: () => void }) {
  const { t } = useApp();
  const left = useCountdown(r.expires_in_seconds, anchor);
  const fired = useRef(false);
  useEffect(() => {
    if (left === 0 && !fired.current) {
      fired.current = true;
      onExpiredLocally();
    }
  }, [left, onExpiredLocally]);
  const who = r.visitor.alias ?? t("app.visitors.visitor_unnamed");
  const s = requestStatus(r);
  return (
    <Card testID={`pending-${r.id}`} style={{ borderWidth: 3, borderColor: "#0B2545" }}>
      <AppText variant="heading" accessibilityRole="header">{t("resident.approval.visitor_at_gate", { visitor: who })}</AppText>
      <View style={{ marginVertical: space.sm }}>
        <StatusPill label={t(s.key)} glyph={s.glyph} tone={s.tone} />
      </View>
      <AppText muted>{t("app.visitors.people", { count: r.visitor.people_count })}</AppText>
      {left !== null ? <AppText style={{ marginTop: space.xs }}>{t("app.home.expires_in", { seconds: left })}</AppText> : null}
      <View style={{ height: space.md }} />
      <Button testID={`open-${r.id}`} label={t("app.home.open")} onPress={onOpen} />
    </Card>
  );
}

export function HomeScreen() {
  const { t, locale, active, services, cache } = useApp();
  const nav = useNav();
  const key = active ? contextKey(active) : null;
  const pending = useResource(
    cache,
    key ? `pending:${key}` : null,
    async () => {
      const res = await services.api.listApprovalRequests(active!.societyId, active!.unitId, "pending");
      return res.items.filter((r) => belongsToContext(active!, r)); // fail closed on foreign ids
    },
    { pollMs: POLL_INTERVAL_MS },
  );
  const recent = useResource(
    cache,
    key ? `recent:${key}` : null,
    async () => (await services.api.unitVisits(active!.societyId, active!.unitId)).items.slice(0, 5),
    { pollMs: POLL_INTERVAL_MS * 2 },
  );

  // register for wake-ups; an event only triggers a refresh (slice 4 provides a real adapter, default is a no-op)
  const refreshPending = pending.refresh;
  const refreshRecent = recent.refresh;
  useEffect(
    () =>
      services.notifications.subscribe(() => {
        void refreshPending();
        void refreshRecent();
      }),
    [services.notifications, refreshPending, refreshRecent],
  );

  const refreshAll = async () => {
    await Promise.all([pending.refresh(), recent.refresh()]);
  };
  const first = pending.data?.[0];
  const offline = pending.offline || recent.offline;

  return (
    <Screen testID="screen-home" refreshing={pending.refreshing || recent.refreshing} onRefresh={refreshAll} refreshLabel={t("app.state.refresh")}>
      <Heading>{t("resident.home.title")}</Heading>
      {offline && (pending.data || recent.data) ? <OfflineBanner /> : null}

      <Heading level={2}>{t("resident.home.pending_approval")}</Heading>
      {pending.loading ? <LoadingState /> : null}
      {!pending.loading && pending.error && !pending.data ? <ErrorState error={pending.error} onRetry={pending.refresh} /> : null}
      {pending.data && pending.data.length === 0 ? (
        <Card testID="pending-none"><AppText muted>{t("app.home.pending_none")}</AppText></Card>
      ) : null}
      {pending.data?.map((r) => (
        <PendingCard key={r.id} r={r} anchor={pending.updatedAt} onOpen={() => nav.push(`/approval/${r.id}`)} onExpiredLocally={() => void pending.refresh()} />
      ))}

      <Heading level={2}>{t("app.home.quick_actions")}</Heading>
      <View style={{ gap: space.md, marginBottom: space.lg }}>
        <Button testID="qa-invite" glyph="＋" label={t("resident.home.action.invite")} onPress={() => nav.push("/invite/new")} />
        <Button
          testID="qa-approve"
          glyph="✓"
          label={first ? t("resident.home.action.approve") : t("app.home.action.approve_none")}
          variant="secondary"
          disabled={!first}
          onPress={() => first && nav.push(`/approval/${first.id}`)}
        />
        <Button testID="qa-visitors" glyph="☰" label={t("app.home.action.visitors")} variant="secondary" onPress={() => nav.push("/visitors")} />
      </View>

      <Heading level={2}>{t("app.home.updates")}</Heading>
      {recent.loading ? <LoadingState /> : null}
      {!recent.loading && recent.error && !recent.data ? <ErrorState error={recent.error} onRetry={recent.refresh} /> : null}
      {recent.data && recent.data.length === 0 ? <Card><AppText muted>{t("app.home.updates_empty")}</AppText></Card> : null}
      {recent.data?.map((v) => {
        const s = visitStatus(v);
        return (
          <Card key={v.id} testID={`update-${v.id}`}>
            <AppText variant="label">{v.visitor_alias ?? t("app.visitors.visitor_unnamed")}</AppText>
            <View style={{ marginVertical: space.xs }}>
              <StatusPill label={t(s.key)} glyph={s.glyph} tone={s.tone} />
            </View>
            <AppText variant="small" muted>{formatDateTime(v.created_at, locale)}</AppText>
          </Card>
        );
      })}
      {pending.error && pending.data && !pending.offline ? <Banner tone="warning" alert>{t("app.errors.network")}</Banner> : null}
    </Screen>
  );
}
