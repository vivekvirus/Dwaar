// The 6-digit pass code is shown ONCE (only its hash exists on the server). It is kept in memory just long enough to show it
// on the detail screen right after creation; it is never persisted and never put in a URL.
const codes = new Map<string, string>();
export const createdCodes = {
  set(invitationId: string, code: string) {
    codes.set(invitationId, code);
  },
  get(invitationId: string): string | undefined {
    return codes.get(invitationId);
  },
  clear() {
    codes.clear();
  },
};
