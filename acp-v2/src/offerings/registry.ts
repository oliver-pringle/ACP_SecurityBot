import type { Offering } from "./types.js";

export const OFFERINGS: Record<string, Offering> = {
  // populated in Task 11 (security_scan) and Task 12 (security_watch)
};

export function getOffering(name: string): Offering | undefined {
  return OFFERINGS[name];
}

export function listOfferings(): string[] {
  return Object.keys(OFFERINGS);
}
