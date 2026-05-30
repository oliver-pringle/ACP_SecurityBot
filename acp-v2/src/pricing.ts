import type { AssetToken } from "@virtuals-protocol/acp-node-v2";
import { OFFERINGS } from "./offerings/registry.js";

const DEFAULT_PRICE_USDC = 0.1;

export interface Price {
  amountUsdc: number;
}

export function priceFor(offeringName: string, requirement: Record<string, unknown>): Price {
  const off = OFFERINGS[offeringName];
  if (!off) return { amountUsdc: DEFAULT_PRICE_USDC };

  if (off.subscription) {
    const ticks = typeof requirement.ticks === "number" ? requirement.ticks : 0;
    return { amountUsdc: off.subscription.pricePerTickUsdc * ticks };
  }

  // One-shot: per-name fixed price table; default if absent.
  const fixed: Record<string, number> = { echo: 0.1 };
  return { amountUsdc: fixed[offeringName] ?? DEFAULT_PRICE_USDC };
}

export async function priceForAssetToken(
  offeringName: string,
  requirement: Record<string, unknown>,
  chainId: number
): Promise<AssetToken> {
  const price = priceFor(offeringName, requirement);
  const { AssetToken } = await import("@virtuals-protocol/acp-node-v2");
  return AssetToken.usdc(price.amountUsdc, chainId);
}
