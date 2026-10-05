import type { Metadata } from "next";
import { SignInFlow } from "@/features/auth/sign-in";
import { message } from "@/i18n";

export const metadata: Metadata = { title: message("en", "console.signin.title") };

export default function SignInPage() {
  return <SignInFlow />;
}
