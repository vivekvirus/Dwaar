// REQ: PRD 6 (push arrives in slice 4). The app only knows this interface; the default adapter does nothing and the UI never
// claims that push works. Slice 4 supplies a real adapter (device token registration + data-only wake-ups; INV-05: no
// commercial push). A received event only triggers a REFRESH from the API; the payload is never trusted as state.
export interface NotificationEvent {
  kind: "approval_requested" | "approval_decided" | "unknown";
  /** Opaque id of the object to refetch; never used to display state. */
  objectId?: string;
}

export interface NotificationAdapter {
  /** True only when a real push channel is registered for this device. */
  readonly available: boolean;
  /** Ask for permission and register the device with the API. Resolves false when unavailable or declined. */
  register(): Promise<boolean>;
  subscribe(handler: (event: NotificationEvent) => void): () => void;
}

export class NoopNotificationAdapter implements NotificationAdapter {
  readonly available = false;
  async register(): Promise<boolean> {
    return false;
  }
  subscribe(): () => void {
    return () => undefined;
  }
}
