import type { Offering } from "./types.js";
import { securityScan } from "./security_scan.js";
import { securityWatch } from "./security_watch.js";

export const OFFERINGS: Record<string, Offering> = {
  security_scan: securityScan,
  security_watch: securityWatch,
};

export function getOffering(name: string): Offering | undefined {
  return OFFERINGS[name];
}

export function listOfferings(): string[] {
  return Object.keys(OFFERINGS);
}
