// REQ: GATE-01: the QR is drawn by a maintained library (react-native-qrcode-svg -> qrcode) from the API payload. No mock here.
import React from "react";
import { render, screen } from "@testing-library/react-native";
import QRCodeLib from "qrcode";
import { QrBlock } from "../src/screens/InviteDetailScreen";
import { InvitationSchema } from "../src/domain/types";
import { recorded } from "./fixtures";

const payload = InvitationSchema.parse(recorded("invitation-created").body).qr!;

describe("QR rendering with the real library", () => {
  test("renders an SVG with modules for the real API payload and exposes an accessible name", () => {
    render(<QrBlock payload={payload} label="QR code for the guard to scan" />);
    expect(screen.getByLabelText("QR code for the guard to scan")).toBeTruthy();
    const dump = JSON.stringify(screen.toJSON(), (k, v) => (typeof v === "function" ? undefined : v));
    expect(dump).toMatch(/RNSVG|svg/i);
    expect(dump.length).toBeGreaterThan(2000); // a drawn matrix, not an empty box
  });

  test("the payload is encodable at the error-correction level used (it fits a QR code) and is not altered", () => {
    const qr = QRCodeLib.create(payload, { errorCorrectionLevel: "M" });
    expect(qr.version).toBeLessThanOrEqual(40);
    expect(payload).toMatch(/^[A-Za-z0-9_-]+\.ed25519:/); // untouched API text: b64url body + '.' + signature
    const body = JSON.parse(Buffer.from(payload.split(".")[0]!, "base64url").toString("utf8"));
    expect(Object.keys(body).sort()).toEqual(["exp", "iid", "kid", "n", "nbf", "sid", "typ", "v"]);
    expect(JSON.stringify(body)).not.toMatch(/phone|address|name/i); // GATE-01: no raw phone or address in the QR
  });
});
