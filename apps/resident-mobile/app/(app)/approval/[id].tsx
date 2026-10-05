import React from "react";
import { useLocalSearchParams } from "expo-router";
import { ApprovalScreen } from "../../../src/screens/ApprovalScreen";

export default function ApprovalRoute() {
  const { id } = useLocalSearchParams<{ id: string }>();
  return <ApprovalScreen key={String(id)} requestId={String(id)} />;
}
