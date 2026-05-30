import type { Offering } from "./types.js";
import { echo } from "./echo.js";
import { tickEcho } from "./tick_echo.js";
import { tickStreamEcho } from "./tick_stream_echo.js";

export const OFFERINGS: Record<string, Offering> = {
  echo,
  tick_echo: tickEcho,
  tick_stream_echo: tickStreamEcho
};

export function getOffering(name: string): Offering | undefined {
  return OFFERINGS[name];
}

export function listOfferings(): string[] {
  return Object.keys(OFFERINGS);
}
