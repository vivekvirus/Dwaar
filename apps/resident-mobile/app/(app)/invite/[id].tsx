import React from "react";
import { useLocalSearchParams } from "expo-router";
import { InviteDetailScreen } from "../../../src/screens/InviteDetailScreen";

export default function InviteRoute() {
  const { id } = useLocalSearchParams<{ id: string }>();
  return <InviteDetailScreen key={String(id)} invitationId={String(id)} />;
}
