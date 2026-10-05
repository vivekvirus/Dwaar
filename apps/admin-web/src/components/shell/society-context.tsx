"use client";
import { createContext, useContext } from "react";
import type { Capability } from "@/lib/access";
import type { SessionSociety } from "@/server/session";

export type SocietyCtx = {
  societyId: string;
  society: SessionSociety;
  roles: string[];
  capabilities: Capability[];
  can: (c: Capability) => boolean;
};

export const SocietyContext = createContext<SocietyCtx | null>(null);

export function useSociety(): SocietyCtx {
  const v = useContext(SocietyContext);
  if (!v) throw new Error("useSociety outside the console shell");
  return v;
}
