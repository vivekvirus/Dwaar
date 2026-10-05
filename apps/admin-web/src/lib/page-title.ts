import { message, type ConsoleKey } from "@/i18n";

export const titleOf = (key: ConsoleKey) => ({ title: message("en", key) });
