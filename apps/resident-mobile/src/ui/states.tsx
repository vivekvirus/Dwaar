// REQ: PRD 6 states: loading, empty, offline, expired request, permission denied. Each one says what it is in words.
import React from "react";
import { View } from "react-native";
import { errorMessage, errorRequestId, ApiError, NetworkError } from "../api/errors";
import { useApp } from "../state/AppProvider";
import { AppText, Banner, Button, Card, Loading } from "./components";
import { space } from "./tokens";

export function LoadingState() {
  const { t } = useApp();
  return <Loading label={t("resident.state.loading")} />;
}

export function EmptyState({ message }: { message?: string }) {
  const { t } = useApp();
  return (
    <Card testID="state-empty">
      <AppText muted>{message ?? t("resident.state.empty")}</AppText>
    </Card>
  );
}

/** Shown above saved data when the last refresh could not reach the server. */
export function OfflineBanner() {
  const { t } = useApp();
  return (
    <Banner tone="warning" alert testID="state-offline">
      {t("resident.state.offline")}
    </Banner>
  );
}

export function PermissionDenied({ message }: { message?: string }) {
  const { t } = useApp();
  return (
    <Banner tone="danger" alert testID="state-permission-denied">
      {message ?? t("resident.state.permission_denied")}
    </Banner>
  );
}

export function ExpiredNote({ message }: { message?: string }) {
  const { t } = useApp();
  return (
    <Banner tone="danger" alert testID="state-expired">
      {message ?? t("resident.state.expired")}
    </Banner>
  );
}

/** Error with retry. Offline with nothing saved says so honestly. 403/404 are shown as permission denied / not found only. */
export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const { t } = useApp();
  if (error instanceof NetworkError) {
    return (
      <View testID="state-offline-nodata">
        <Banner tone="warning" alert>
          {t("app.state.offline_nodata")}
        </Banner>
        {onRetry ? <Button label={t("app.state.retry")} onPress={onRetry} variant="secondary" /> : null}
      </View>
    );
  }
  if (error instanceof ApiError && error.status === 403) return <PermissionDenied />;
  const id = errorRequestId(error);
  return (
    <View testID="state-error" style={{ marginBottom: space.md }}>
      <Banner tone="danger" alert>
        {errorMessage(error, t)}
      </Banner>
      {id ? (
        <AppText variant="small" muted style={{ marginBottom: space.sm }}>
          {t("errors.request_id.label", { request_id: id })}
        </AppText>
      ) : null}
      {onRetry ? <Button label={t("app.state.retry")} onPress={onRetry} variant="secondary" /> : null}
    </View>
  );
}
