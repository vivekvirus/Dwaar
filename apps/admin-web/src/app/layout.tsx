import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Providers } from "@/components/providers";
import { message } from "@/i18n";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: message("en", "console.app.title"), template: `%s | ${message("en", "console.app.title")}` },
  description: message("en", "console.app.description"),
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
