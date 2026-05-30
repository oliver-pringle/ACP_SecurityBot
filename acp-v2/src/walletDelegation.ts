import { createPublicClient, createWalletClient, http, getAddress, type Chain } from "viem";
import { privateKeyToAccount } from "viem/accounts";

// EIP-7702 ensure-on-boot helper for ACP v2 Privy-WaaS bots.
//
// Origin: lifted from ACP_ChainlinkBot/acp-v2/src/walletDelegation.ts after
// the 2026-05-11 Base mainnet cutover hit `Expected bigint, got: 0` on the
// first hire. The same drift will hit any bot whose Privy WaaS rotates the
// delegation to a non-allowlisted impl  -  every Privy-WaaS bot must guard
// against it on boot. Round 7 PART 5 item B1 lifted this into both
// boilerplates so future bots inherit the guard.
//
// Background: the ACP v2 SDK (acp-node-v2 ^0.0.6) only recognises wallets
// delegated to Alchemy ModularAccountV2 (the sole entry in
// SUPPORTED_DELEGATION_ADDRESSES at @alchemy/wallet-api-types
// dist/esm/capabilities/eip7702Auth.js). Any other delegation makes the SDK
// take a code path that feeds the wallet's raw integer nonce to a HexBigInt
// typebox encoder which throws "Expected bigint, got: N" (N = the EOA nonce
// fed as a JS number).
//
// Pattern: call `ensureDelegation(...)` AFTER `AcpAgent.create({ provider })`
// in seller.ts. If `DEPLOYER_PRIVATE_KEY` is set in env, the helper
// auto-recovers by sending a sponsored type-4 tx from the deployer EOA with
// the wallet's signed authorization in the list. If not set, throws with a
// clear recovery message pointing at scripts/provision-7702.ts.
//
// See: user-memory reference_acp_wallet_provisioning.md.

// Alchemy ModularAccountV2 implementation address. The only delegation the
// ACP v2 SDK recognises. Don't change this constant unless the SDK's
// SUPPORTED_DELEGATION_ADDRESSES allowlist changes upstream.
export const MODULAR_ACCOUNT_V2 =
  "0x69007702764179f14F51cdce752f4f775d74E139" as const;

export interface DelegationStatus {
  walletAddress: string;
  chainId: number;
  bytecode: string;
  delegatedTo: string | null;
  isModularAccountV2: boolean;
}

export interface DelegationLogger {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
}

export async function getDelegationStatus(
  walletAddress: string,
  chain: Chain,
  rpcUrl: string
): Promise<DelegationStatus> {
  const pub = createPublicClient({ chain, transport: http(rpcUrl) });
  const bytecode =
    (await pub.getBytecode({ address: walletAddress as `0x${string}` })) ?? "0x";
  // EIP-7702 delegated EOAs have code = 0xef0100 + 20-byte impl address (48 hex chars total).
  let delegatedTo: string | null = null;
  if (bytecode.length === 48 && bytecode.toLowerCase().startsWith("0xef0100")) {
    delegatedTo = getAddress("0x" + bytecode.slice(8));
  }
  const isModularAccountV2 =
    delegatedTo?.toLowerCase() === MODULAR_ACCOUNT_V2.toLowerCase();
  return { walletAddress, chainId: chain.id, bytecode, delegatedTo, isModularAccountV2 };
}

export interface EnsureDelegationOpts {
  adapter: unknown;
  walletAddress: string;
  chain: Chain;
  rpcUrl: string;
  deployerPrivateKey?: string;
  logger?: DelegationLogger;
}

// Confirm the wallet is delegated to ModularAccountV2. If not, either
// auto-provision (when deployerPrivateKey is set) or throw with a clear
// recovery message.
export async function ensureDelegation(
  opts: EnsureDelegationOpts
): Promise<DelegationStatus> {
  const { adapter, walletAddress, chain, rpcUrl, deployerPrivateKey } = opts;
  const logger = opts.logger ?? consoleLogger();

  const status = await getDelegationStatus(walletAddress, chain, rpcUrl);

  if (status.isModularAccountV2) {
    logger.info(
      `[delegation] wallet ${walletAddress} chain ${chain.id} OK (ModularAccountV2)`
    );
    return status;
  }

  const currentLabel = status.delegatedTo ?? "0x (undelegated)";
  logger.warn(
    `[delegation] wallet ${walletAddress} chain ${chain.id} delegated to ${currentLabel}; need ${MODULAR_ACCOUNT_V2}`
  );

  if (!deployerPrivateKey) {
    throw new Error(
      `Wallet ${walletAddress} on chain ${chain.id} is delegated to ${currentLabel}, ` +
        `which the SDK does not recognise. Set DEPLOYER_PRIVATE_KEY in env to auto-recover ` +
        `on boot, or run scripts/provision-7702.ts manually. See ` +
        `memory/reference_acp_wallet_provisioning.md.`
    );
  }

  await provisionViaRelay({
    adapter,
    walletAddress,
    chain,
    rpcUrl,
    deployerPrivateKey,
    logger,
  });

  const finalStatus = await getDelegationStatus(walletAddress, chain, rpcUrl);
  if (!finalStatus.isModularAccountV2) {
    throw new Error(
      `Auto-provision tx mined but wallet is still delegated to ${finalStatus.delegatedTo ?? "0x"}`
    );
  }
  logger.info(
    `[delegation] auto-provisioned ${walletAddress} -> ModularAccountV2`
  );
  return finalStatus;
}

interface ProvisionOpts {
  adapter: unknown;
  walletAddress: string;
  chain: Chain;
  rpcUrl: string;
  deployerPrivateKey: string;
  logger: DelegationLogger;
}

// Sign a fresh 7702 authorization via Privy's signer.signAuthorization, then
// broadcast a type-4 tx from the deployer EOA as a sponsored relay.
async function provisionViaRelay(opts: ProvisionOpts): Promise<void> {
  const { adapter, walletAddress, chain, rpcUrl, deployerPrivateKey, logger } = opts;

  // The signer is marked private on the public adapter type but is set as a
  // public field in the constructor. Access defensively.
  const signer = (adapter as { signer?: { signAuthorization?: SignAuthFn } }).signer;
  if (!signer || typeof signer.signAuthorization !== "function") {
    throw new Error(
      "adapter.signer.signAuthorization not available - SDK shape changed?"
    );
  }

  const pub = createPublicClient({ chain, transport: http(rpcUrl) });
  const walletNonce = await pub.getTransactionCount({
    address: walletAddress as `0x${string}`,
  });
  logger.info(
    `[delegation] requesting Privy authorization (wallet nonce ${walletNonce})`
  );

  const signedAuth = await signer.signAuthorization({
    contractAddress: MODULAR_ACCOUNT_V2,
    chainId: chain.id,
    nonce: walletNonce,
  });
  const auth = normaliseAuth(signedAuth, MODULAR_ACCOUNT_V2, chain.id, walletNonce);

  const deployer = privateKeyToAccount(deployerPrivateKey as `0x${string}`);
  const wc = createWalletClient({
    account: deployer,
    chain,
    transport: http(rpcUrl),
  });
  const txHash = await wc.sendTransaction({
    to: deployer.address,
    value: 0n,
    data: "0x",
    authorizationList: [auth],
  });
  logger.info(`[delegation] type-4 tx ${txHash}; waiting for receipt`);

  const receipt = await pub.waitForTransactionReceipt({ hash: txHash });
  if (receipt.status !== "success") {
    throw new Error(`provision tx reverted in block ${receipt.blockNumber}`);
  }
  logger.info(
    `[delegation] confirmed in block ${receipt.blockNumber}, gasUsed ${receipt.gasUsed}`
  );
}

type SignAuthFn = (input: {
  contractAddress: string;
  chainId: number;
  nonce: number;
}) => Promise<RawSignedAuth>;

interface RawSignedAuth {
  address?: string;
  contractAddress?: string;
  chainId?: number | string;
  chain_id?: number | string;
  nonce?: number | string;
  r: `0x${string}`;
  s: `0x${string}`;
  yParity?: number | string;
  y_parity?: number | string;
  v?: number | string | bigint;
}

// Privy can return either { r, s, yParity } or { r, s, v }, with chainId as
// hex string or number. Normalise to viem's SignedAuthorization shape.
function normaliseAuth(
  raw: RawSignedAuth,
  implAddress: string,
  chainId: number,
  nonce: number
) {
  const toNum = (v: number | string): number =>
    typeof v === "string" && v.startsWith("0x") ? parseInt(v, 16) : Number(v);
  const out: {
    address: `0x${string}`;
    chainId: number;
    nonce: number;
    r: `0x${string}`;
    s: `0x${string}`;
    yParity?: number;
  } = {
    address: (raw.address ?? raw.contractAddress ?? implAddress) as `0x${string}`,
    chainId:
      raw.chainId != null
        ? toNum(raw.chainId)
        : raw.chain_id != null
          ? toNum(raw.chain_id)
          : chainId,
    nonce: raw.nonce != null ? toNum(raw.nonce) : nonce,
    r: raw.r,
    s: raw.s,
  };
  if (raw.yParity != null) {
    out.yParity = typeof raw.yParity === "string" ? toNum(raw.yParity) : raw.yParity;
  } else if (raw.y_parity != null) {
    out.yParity =
      typeof raw.y_parity === "string" ? toNum(raw.y_parity) : raw.y_parity;
  } else if (raw.v != null) {
    out.yParity = raw.v === 27 || raw.v === "0x1b" || raw.v === 0n ? 0 : 1;
  }
  return out;
}

function consoleLogger(): DelegationLogger {
  return {
    info: (m) => console.log(m),
    warn: (m) => console.warn(m),
    error: (m) => console.error(m),
  };
}
