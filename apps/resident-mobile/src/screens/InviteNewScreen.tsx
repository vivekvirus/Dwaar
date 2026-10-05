// REQ: GATE-01 (purpose, host/unit, people count, validity window, optional vehicle), UX-05 (scope and effect before the
// action), PRD 12 (Idempotency-Key on command creation; a retry re-sends the SAME frozen request).
import React, { useRef, useState } from "react";
import { View } from "react-native";
import { contextKey, useApp } from "../state/AppProvider";
import { errorMessage } from "../api/errors";
import type { InvitationBody } from "../api/endpoints";
import { newIdempotencyKey } from "../api/ids";
import { createdCodes } from "../state/created";
import { useNav } from "../hooks/useNav";
import { BackBar } from "../ui/chrome";
import { AppText, Banner, Button, Card, Choice, Field, Heading, Screen } from "../ui/components";
import { space } from "../ui/tokens";

const STARTS = [
  { id: "now", minutes: 0, key: "app.invite.starts_now" },
  { id: "1h", minutes: 60, key: "app.invite.starts_1h" },
  { id: "3h", minutes: 180, key: "app.invite.starts_3h" },
] as const;
const DURATIONS = [
  { id: "1h", minutes: 60, key: "app.invite.duration_1h" },
  { id: "3h", minutes: 180, key: "app.invite.duration_3h" },
  { id: "6h", minutes: 360, key: "app.invite.duration_6h" },
  { id: "12h", minutes: 720, key: "app.invite.duration_12h" },
] as const;

export function buildInvitationBody(input: {
  unitId: string;
  purpose: string;
  alias: string;
  people: number;
  startOffsetMin: number;
  durationMin: number;
  plate: string;
  now: Date;
}): InvitationBody {
  const start = new Date(Math.floor(input.now.getTime() / 1000) * 1000 + input.startOffsetMin * 60_000);
  const end = new Date(start.getTime() + input.durationMin * 60_000);
  return {
    unit_id: input.unitId,
    kind: "guest",
    purpose: input.purpose.trim(),
    visitor_alias: input.alias.trim() || null,
    people_count: input.people,
    windows: [{ start: start.toISOString(), end: end.toISOString() }],
    vehicle_plate: input.plate.trim().toUpperCase() || null,
    max_uses: 1,
    with_code: true,
  };
}

export function InviteNewScreen() {
  const { t, active, services, labels } = useApp();
  const nav = useNav();
  const [purpose, setPurpose] = useState("");
  const [alias, setAlias] = useState("");
  const [people, setPeople] = useState(1);
  const [start, setStart] = useState<(typeof STARTS)[number]["id"]>("now");
  const [duration, setDuration] = useState<(typeof DURATIONS)[number]["id"]>("3h");
  const [plate, setPlate] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [purposeError, setPurposeError] = useState<string | null>(null);
  // the request built on the first attempt is frozen with its key, so a retry after a network failure is the same command
  const frozen = useRef<{ body: InvitationBody; key: string } | null>(null);
  const edit = <T,>(setter: (v: T) => void) => (v: T) => {
    frozen.current = null;
    setter(v);
  };
  const unit = active ? labels[contextKey(active)]?.unit ?? "" : "";

  const submit = async () => {
    if (!active) return;
    if (!purpose.trim()) {
      setPurposeError(t("app.invite.purpose_required"));
      return;
    }
    setPurposeError(null);
    setError(null);
    if (!frozen.current) {
      frozen.current = {
        key: newIdempotencyKey(),
        body: buildInvitationBody({
          unitId: active.unitId,
          purpose,
          alias,
          people,
          startOffsetMin: STARTS.find((s) => s.id === start)!.minutes,
          durationMin: DURATIONS.find((d) => d.id === duration)!.minutes,
          plate,
          now: new Date(),
        }),
      };
    }
    setBusy(true);
    try {
      const inv = await services.api.createInvitation(active.societyId, frozen.current.body, frozen.current.key);
      if (inv.code) createdCodes.set(inv.id, inv.code);
      frozen.current = null;
      nav.replace(`/invite/${inv.id}`);
    } catch (e) {
      setError(errorMessage(e, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Screen testID="screen-invite-new">
      <BackBar onBack={nav.back} />
      <Heading>{t("app.invite.title")}</Heading>
      <Field testID="input-purpose" label={t("app.invite.purpose")} hint={t("app.invite.purpose_hint")} value={purpose} onChangeText={edit(setPurpose)} error={purposeError} maxLength={200} />
      <Field testID="input-alias" label={t("app.invite.name")} value={alias} onChangeText={edit(setAlias)} maxLength={100} />

      <AppText variant="label" accessibilityRole="header" style={{ marginBottom: space.sm }}>{t("app.invite.people")}</AppText>
      <View style={{ flexDirection: "row", alignItems: "center", gap: space.md, marginBottom: space.lg, flexWrap: "wrap" }}>
        <Button testID="people-less" label="−" accessibilityLabel={t("app.invite.people_less")} onPress={() => edit(setPeople)(Math.max(1, people - 1))} disabled={people <= 1} />
        <AppText testID="people-count" variant="title" accessibilityLabel={`${t("app.invite.people")}: ${people}`}>{people}</AppText>
        <Button testID="people-more" label="+" accessibilityLabel={t("app.invite.people_more")} onPress={() => edit(setPeople)(Math.min(50, people + 1))} disabled={people >= 50} />
      </View>

      <AppText variant="label" accessibilityRole="header" style={{ marginBottom: space.sm }}>{t("app.invite.starts")}</AppText>
      <View accessibilityRole="radiogroup" style={{ gap: space.sm, marginBottom: space.lg }}>
        {STARTS.map((s) => <Choice key={s.id} testID={`start-${s.id}`} label={t(s.key)} selected={start === s.id} onPress={() => edit(setStart)(s.id)} />)}
      </View>

      <AppText variant="label" accessibilityRole="header" style={{ marginBottom: space.sm }}>{t("app.invite.duration")}</AppText>
      <View accessibilityRole="radiogroup" style={{ gap: space.sm, marginBottom: space.lg }}>
        {DURATIONS.map((d) => <Choice key={d.id} testID={`duration-${d.id}`} label={t(d.key)} selected={duration === d.id} onPress={() => edit(setDuration)(d.id)} />)}
      </View>

      <Field testID="input-plate" label={t("app.invite.vehicle")} value={plate} onChangeText={edit(setPlate)} autoCapitalize="characters" maxLength={20} />

      <Card><AppText>{t("app.invite.summary", { unit })}</AppText></Card>
      {error ? <Banner tone="danger" alert testID="invite-error">{error}</Banner> : null}
      <Button testID="btn-create-invite" label={busy ? t("app.invite.creating") : t("app.invite.create")} onPress={submit} busy={busy} />
    </Screen>
  );
}
