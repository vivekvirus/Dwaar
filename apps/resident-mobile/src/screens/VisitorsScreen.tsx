// REQ: GATE-01 (own passes), GATE-13 / AT-02 (history of the OWN household only; server-enforced), INV-07, UX-06 (no
// infinite feed: explicit "Load more").
import React, { useEffect, useState } from "react";
import { View } from "react-native";
import { contextKey, useApp } from "../state/AppProvider";
import { useResource } from "../state/resource";
import { invitationStatus, visitStatus } from "../domain/status";
import { useNav } from "../hooks/useNav";
import { formatDateTime } from "../i18n";
import { AppText, Button, Card, Heading, Screen, StatusPill } from "../ui/components";
import { ErrorState, LoadingState, OfflineBanner } from "../ui/states";
import { space } from "../ui/tokens";
import { errorMessage } from "../api/errors";
import type { Visit } from "../domain/types";

export function VisitorsScreen() {
  const { t, locale, active, services, cache } = useApp();
  const nav = useNav();
  const key = active ? contextKey(active) : null;
  const passes = useResource(cache, key ? `passes:${key}` : null, async () => (await services.api.listInvitations(active!.societyId, active!.unitId)).items);
  const history = useResource(cache, key ? `history:${key}` : null, () => services.api.unitVisits(active!.societyId, active!.unitId));
  const [more, setMore] = useState<Visit[]>([]);
  const [cursor, setCursor] = useState<string | null | undefined>(undefined);
  const [moreBusy, setMoreBusy] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);

  // a refreshed first page replaces anything appended after it
  useEffect(() => {
    setMore([]);
    setCursor(history.data?.next_cursor);
    setMoreError(null);
  }, [history.data]);

  const loadMore = async () => {
    if (!active || !cursor) return;
    setMoreBusy(true);
    setMoreError(null);
    try {
      const page = await services.api.unitVisits(active.societyId, active.unitId, cursor);
      setMore((m) => [...m, ...page.items]);
      setCursor(page.next_cursor ?? null);
    } catch (e) {
      setMoreError(errorMessage(e, t));
    } finally {
      setMoreBusy(false);
    }
  };

  const items = [...(history.data?.items ?? []), ...more];
  const refreshAll = async () => {
    await Promise.all([passes.refresh(), history.refresh()]);
  };

  return (
    <Screen testID="screen-visitors" refreshing={passes.refreshing || history.refreshing} onRefresh={refreshAll} refreshLabel={t("app.state.refresh")}>
      <Heading>{t("app.visitors.title")}</Heading>
      {(passes.offline || history.offline) && (passes.data || history.data) ? <OfflineBanner /> : null}
      <Button testID="btn-new-invite" glyph="＋" label={t("app.visitors.new_invite")} onPress={() => nav.push("/invite/new")} />

      <View style={{ height: space.lg }} />
      <Heading level={2}>{t("app.visitors.passes")}</Heading>
      {passes.loading ? <LoadingState /> : null}
      {!passes.loading && passes.error && !passes.data ? <ErrorState error={passes.error} onRetry={passes.refresh} /> : null}
      {passes.data && passes.data.length === 0 ? <Card testID="passes-empty"><AppText muted>{t("app.visitors.passes_empty")}</AppText></Card> : null}
      {passes.data?.map((p) => {
        const s = invitationStatus(p);
        return (
          <Card key={p.id} testID={`pass-${p.id}`}>
            <AppText variant="label">{p.purpose}</AppText>
            <View style={{ marginVertical: space.xs }}><StatusPill label={t(s.key)} glyph={s.glyph} tone={s.tone} /></View>
            <AppText variant="small" muted>{t("app.visitors.people", { count: p.people_count })}</AppText>
            <AppText variant="small" muted>{t("app.visitors.valid", { from: formatDateTime(p.window_start, locale), to: formatDateTime(p.window_end, locale) })}</AppText>
            <View style={{ height: space.sm }} />
            <Button label={t("app.home.open")} variant="secondary" onPress={() => nav.push(`/invite/${p.id}`)} />
          </Card>
        );
      })}

      <View style={{ height: space.lg }} />
      <Heading level={2}>{t("app.visitors.history")}</Heading>
      {history.loading ? <LoadingState /> : null}
      {!history.loading && history.error && !history.data ? <ErrorState error={history.error} onRetry={history.refresh} /> : null}
      {history.data && items.length === 0 ? <Card testID="history-empty"><AppText muted>{t("app.visitors.history_empty")}</AppText></Card> : null}
      {items.map((v) => {
        const s = visitStatus(v);
        return (
          <Card key={v.id} testID={`visit-${v.id}`}>
            <AppText variant="label">{v.visitor_alias ?? t("app.visitors.visitor_unnamed")}</AppText>
            <View style={{ marginVertical: space.xs }}><StatusPill label={t(s.key)} glyph={s.glyph} tone={s.tone} /></View>
            <AppText variant="small" muted>{formatDateTime(v.created_at, locale)} · {t("app.visitors.people", { count: v.people_count })}</AppText>
            <AppText variant="small">{v.entry_observed && v.entered_at ? t("app.visitors.entered_at", { time: formatDateTime(v.entered_at, locale) }) : t("app.visitors.entry_not_observed")}</AppText>
          </Card>
        );
      })}
      {moreError ? <AppText accessibilityRole="alert" style={{ marginBottom: space.sm }}>{moreError}</AppText> : null}
      {cursor ? <Button testID="btn-load-more" label={t("app.visitors.load_more")} variant="secondary" busy={moreBusy} onPress={loadMore} /> : null}
    </Screen>
  );
}
