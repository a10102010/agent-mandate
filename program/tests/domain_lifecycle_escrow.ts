import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { AgentMandate } from "../target/types/agent_mandate";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Ed25519Program,
  Transaction,
  TransactionInstruction,
  SYSVAR_INSTRUCTIONS_PUBKEY,
} from "@solana/web3.js";
import { expect } from "chai";
import { createHash } from "crypto";
import BN from "bn.js";
import * as nacl from "tweetnacl";

// ── Domain separation prefixes (must match on-chain constants) ──
const ATTESTATION_PREFIX = Buffer.from("mandate-clearing/attestation/v1");
const CART_PREFIX = Buffer.from("mandate-clearing/cart/v1");

function sha256(input: string): number[] {
  const hash = createHash("sha256").update(input).digest();
  return Array.from(hash);
}

/**
 * Build the message payload (without prefix):
 * mandate_hash (32) || order_hash (32) || content_hash (32) || trace_hash (32) || timestamp_le (8)
 */
function buildRawPayload(
  mandateHash: number[],
  orderHash: number[],
  contentHash: number[],
  traceHash: number[],
  timestamp: number
): Buffer {
  const buf = Buffer.alloc(136);
  Buffer.from(mandateHash).copy(buf, 0);
  Buffer.from(orderHash).copy(buf, 32);
  Buffer.from(contentHash).copy(buf, 64);
  Buffer.from(traceHash).copy(buf, 96);
  buf.writeBigInt64LE(BigInt(timestamp), 128);
  return buf;
}

/**
 * Build the domain-prefixed message:
 * prefix || mandate_hash || order_hash || content_hash || trace_hash || timestamp_le
 */
function buildPrefixedMessage(
  prefix: Buffer,
  mandateHash: number[],
  orderHash: number[],
  contentHash: number[],
  traceHash: number[],
  timestamp: number
): Buffer {
  const payload = buildRawPayload(mandateHash, orderHash, contentHash, traceHash, timestamp);
  return Buffer.concat([prefix, payload]);
}

/**
 * Build an Ed25519 precompile instruction with TWO signatures.
 * Messages can be variable length (for domain prefixes).
 */
function buildDualEd25519Ix(
  keypair0: Keypair,
  message0: Buffer,
  keypair1: Keypair,
  message1: Buffer
): TransactionInstruction {
  const headerSize = 2;
  const offsetsSize = 14 * 2;
  const dataStart = headerSize + offsetsSize;

  const sig0Offset = dataStart;
  const pk0Offset = sig0Offset + 64;
  const msg0Offset = pk0Offset + 32;
  const msg0Size = message0.length;

  const sig1Offset = msg0Offset + msg0Size;
  const pk1Offset = sig1Offset + 64;
  const msg1Offset = pk1Offset + 32;
  const msg1Size = message1.length;

  const totalLen = msg1Offset + msg1Size;
  const data = Buffer.alloc(totalLen);

  data[0] = 2;
  data[1] = 0;

  let off = 2;
  data.writeUInt16LE(sig0Offset, off);     off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;
  data.writeUInt16LE(pk0Offset, off);      off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;
  data.writeUInt16LE(msg0Offset, off);     off += 2;
  data.writeUInt16LE(msg0Size, off);       off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;

  data.writeUInt16LE(sig1Offset, off);     off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;
  data.writeUInt16LE(pk1Offset, off);      off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;
  data.writeUInt16LE(msg1Offset, off);     off += 2;
  data.writeUInt16LE(msg1Size, off);       off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;

  const sig0 = nacl.sign.detached(message0, keypair0.secretKey);
  const sig1 = nacl.sign.detached(message1, keypair1.secretKey);

  Buffer.from(sig0).copy(data, sig0Offset);
  keypair0.publicKey.toBuffer().copy(data, pk0Offset);
  message0.copy(data, msg0Offset);

  Buffer.from(sig1).copy(data, sig1Offset);
  keypair1.publicKey.toBuffer().copy(data, pk1Offset);
  message1.copy(data, msg1Offset);

  return new TransactionInstruction({
    keys: [],
    programId: Ed25519Program.programId,
    data,
  });
}

// ═══════════════════════════════════════════════════════════════
// Part 1: Domain Separation Tests
// ═══════════════════════════════════════════════════════════════

describe("Part 1: Domain Separation", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AgentMandate as Program<AgentMandate>;

  const principal = Keypair.generate();
  const agent = Keypair.generate();
  const merchant = Keypair.generate();

  const mandateId = "domain-sep-test";
  const currency = "USD";
  const maxTotal = new BN(10_000_000);
  const validFrom = new BN(0);
  const validUntil = new BN(Math.floor(Date.now() / 1000) + 86400 * 365);
  const disputeWindowSec = new BN(3600);
  const merchantHash = sha256("merchant-acme");

  const orderTotal = new BN(100);
  const itemPrices = [new BN(50)];
  const itemQuantities = [2];
  const itemCategories: number[][] = [];
  const itemSkus: number[][] = [];

  const cartHash = sha256("cart-data");
  const traceHash = sha256("trace-data");
  const mandateHashArr = sha256("mandate-hash-data");
  const sigTimestamp = Math.floor(Date.now() / 1000);

  let mandatePda: PublicKey;

  function orderHashFor(name: string): number[] {
    return Array.from(createHash("sha256").update(name).digest());
  }

  async function buildClearIx(
    orderHash: number[],
    agentKp: Keypair,
    attestationHash: number[],
    opts?: { merchantPk?: PublicKey }
  ): Promise<TransactionInstruction> {
    const merchPk = opts?.merchantPk ?? merchant.publicKey;
    return await program.methods
      .clear(
        orderHash,
        attestationHash,
        orderTotal,
        itemPrices,
        itemQuantities,
        itemCategories,
        itemSkus,
        merchantHash,
        currency,
        cartHash,
        traceHash,
        mandateHashArr,
        new BN(sigTimestamp)
      )
      .accountsPartial({
        agent: agentKp.publicKey,
        merchant: merchPk,
        mandate: mandatePda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();
  }

  before(async () => {
    const airdropSigs = await Promise.all([
      provider.connection.requestAirdrop(principal.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(agent.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(merchant.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
    ]);
    for (const sig of airdropSigs) {
      await provider.connection.confirmTransaction(sig, "confirmed");
    }

    [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, maxTotal, null, null, null, null,
        [], [merchantHash], [],
        validFrom, validUntil, disputeWindowSec, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();
  });

  it("1.1 sanity: domain-prefixed clear succeeds", async () => {
    const orderHash = orderHashFor("domain-sanity");
    const attestationHash = sha256("att-domain-sanity");

    // Build domain-prefixed messages
    const agentMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildPrefixedMessage(CART_PREFIX, mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);

    const ed25519Ix = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);
    const clearIx = await buildClearIx(orderHash, agent, attestationHash);

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);
    tx.feePayer = agent.publicKey;
    tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx.sign(agent);

    const sig = await provider.connection.sendRawTransaction(tx.serialize());
    await provider.connection.confirmTransaction(sig, "confirmed");

    // Verify verdict was created
    const [verdictPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("verdict"), mandatePda.toBuffer(), Buffer.from(orderHash)],
      program.programId
    );
    const verdict = await program.account.verdictAccount.fetch(verdictPda);
    expect(verdict.mandate.toBase58()).to.equal(mandatePda.toBase58());
  });

  it("1.2 rejects clear with old-style unprefixed messages", async () => {
    const orderHash = orderHashFor("domain-unprefixed");
    const attestationHash = sha256("att-domain-unprefixed");

    // Build OLD unprefixed messages (136 bytes without domain prefix)
    const agentMsg = buildRawPayload(mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildRawPayload(mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);

    const ed25519Ix = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);
    const clearIx = await buildClearIx(orderHash, agent, attestationHash);

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);
    tx.feePayer = agent.publicKey;
    tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx.sign(agent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — unprefixed messages");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519MessageMismatch") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });

  it("1.3 domain separation attack: swap attestation/cart slots with same keypair", async () => {
    // Use a SINGLE keypair as both agent and merchant — create a dedicated mandate for this
    const sharedKey = Keypair.generate();
    const principalDS = Keypair.generate();
    const mandateIdDS = "domain-sep-attack";

    const airdropSigs = await Promise.all([
      provider.connection.requestAirdrop(sharedKey.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(principalDS.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
    ]);
    for (const s of airdropSigs) {
      await provider.connection.confirmTransaction(s, "confirmed");
    }

    const [mandatePdaDS] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principalDS.publicKey.toBuffer(), Buffer.from(mandateIdDS)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateIdDS, currency, maxTotal, null, null, null, null,
        [], [merchantHash], [],
        validFrom, validUntil, disputeWindowSec, null
      )
      .accountsPartial({
        principal: principalDS.publicKey,
        agent: sharedKey.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principalDS])
      .rpc();

    const orderHash = orderHashFor("domain-sep-attack-order");
    const attestationHash = sha256("att-domain-sep-attack");

    // Build correct domain-prefixed messages
    const attestationMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const cartMsg = buildPrefixedMessage(CART_PREFIX, mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);

    // ATTACK: Put the cart message in the attestation slot and vice versa
    // Slot 0 (agent) gets the cart-prefixed message, slot 1 (merchant) gets the attestation-prefixed message
    const ed25519Ix = buildDualEd25519Ix(sharedKey, cartMsg, sharedKey, attestationMsg);

    const clearIx = await program.methods
      .clear(
        orderHash,
        attestationHash,
        orderTotal,
        itemPrices,
        itemQuantities,
        itemCategories,
        itemSkus,
        merchantHash,
        currency,
        cartHash,
        traceHash,
        mandateHashArr,
        new BN(sigTimestamp)
      )
      .accountsPartial({
        agent: sharedKey.publicKey,
        merchant: sharedKey.publicKey,
        mandate: mandatePdaDS,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);
    tx.feePayer = sharedKey.publicKey;
    tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx.sign(sharedKey);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — swapped domain slots");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519MessageMismatch") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// Part 2: Replay & Lifecycle Tests
// ═══════════════════════════════════════════════════════════════

describe("Part 2: Replay & Lifecycle", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AgentMandate as Program<AgentMandate>;

  const principal = Keypair.generate();
  const agent = Keypair.generate();
  const merchant = Keypair.generate();

  const currency = "USD";
  const maxTotal = new BN(10_000_000);
  const validFrom = new BN(0);
  const disputeWindowSec = new BN(3600);
  const merchantHash = sha256("merchant-acme");

  const orderTotal = new BN(100);
  const itemPrices = [new BN(50)];
  const itemQuantities = [2];
  const itemCategories: number[][] = [];
  const itemSkus: number[][] = [];

  const cartHash = sha256("cart-data");
  const traceHash = sha256("trace-data");
  const mandateHashArr = sha256("mandate-hash-data");
  const sigTimestamp = Math.floor(Date.now() / 1000);

  function orderHashFor(name: string): number[] {
    return Array.from(createHash("sha256").update(name).digest());
  }

  before(async () => {
    const airdropSigs = await Promise.all([
      provider.connection.requestAirdrop(principal.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(agent.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(merchant.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
    ]);
    for (const sig of airdropSigs) {
      await provider.connection.confirmTransaction(sig, "confirmed");
    }
  });

  // ── 2a: Replay via Verdict PDA ──
  it("2a. replay: second clear with same order_hash fails (verdict PDA already exists)", async () => {
    const mandateId = "replay-test";
    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, maxTotal, null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        disputeWindowSec, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const orderHash = orderHashFor("replay-order");
    const attestationHash = sha256("att-replay");

    // First clear — should succeed
    const agentMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildPrefixedMessage(CART_PREFIX, mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);

    const buildClearIx = async () => {
      return await program.methods
        .clear(
          orderHash, attestationHash, orderTotal,
          itemPrices, itemQuantities, itemCategories, itemSkus,
          merchantHash, currency, cartHash, traceHash, mandateHashArr,
          new BN(sigTimestamp)
        )
        .accountsPartial({
          agent: agent.publicKey,
          merchant: merchant.publicKey,
          mandate: mandatePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .instruction();
    };

    const ed25519Ix1 = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);
    const clearIx1 = await buildClearIx();
    const tx1 = new Transaction();
    tx1.add(ed25519Ix1);
    tx1.add(clearIx1);
    tx1.feePayer = agent.publicKey;
    tx1.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx1.sign(agent);
    const sig1 = await provider.connection.sendRawTransaction(tx1.serialize());
    await provider.connection.confirmTransaction(sig1, "confirmed");

    // Second clear with SAME order hash — must fail
    const ed25519Ix2 = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);
    const clearIx2 = await buildClearIx();
    const tx2 = new Transaction();
    tx2.add(ed25519Ix2);
    tx2.add(clearIx2);
    tx2.feePayer = agent.publicKey;
    tx2.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx2.sign(agent);

    try {
      const sig2 = await provider.connection.sendRawTransaction(tx2.serialize());
      await provider.connection.confirmTransaction(sig2, "confirmed");
      expect.fail("Should have failed — replay attack");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("already in use") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });

  // ── 2b: Clear after revoke ──
  it("2b. clear after revoke fails", async () => {
    const mandateId = "revoked-clear-test";
    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, maxTotal, null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        disputeWindowSec, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    // Revoke the mandate
    await program.methods
      .revoke()
      .accountsPartial({
        principal: principal.publicKey,
        mandate: mandatePda,
      })
      .signers([principal])
      .rpc();

    // Now try to clear
    const orderHash = orderHashFor("revoked-clear-order");
    const attestationHash = sha256("att-revoked-clear");

    const agentMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildPrefixedMessage(CART_PREFIX, mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);
    const ed25519Ix = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);

    const clearIx = await program.methods
      .clear(
        orderHash, attestationHash, orderTotal,
        itemPrices, itemQuantities, itemCategories, itemSkus,
        merchantHash, currency, cartHash, traceHash, mandateHashArr,
        new BN(sigTimestamp)
      )
      .accountsPartial({
        agent: agent.publicKey,
        merchant: merchant.publicKey,
        mandate: mandatePda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);
    tx.feePayer = agent.publicKey;
    tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx.sign(agent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — mandate is revoked");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("MandateRevoked") ||
          msg.includes("mandate_revoked") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });

  // ── 2c: Clear after validUntil ──
  it("2c. clear after validUntil fails (expired mandate)", async () => {
    const mandateId = "expired-clear-test";
    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    // Create mandate that is already expired (validUntil in the past)
    // Use validFrom=0, validUntil=1 (Unix timestamp 1 = Jan 1 1970)
    await program.methods
      .createMandate(
        mandateId, currency, maxTotal, null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(1), // expired immediately
        disputeWindowSec, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const orderHash = orderHashFor("expired-clear-order");
    const attestationHash = sha256("att-expired-clear");

    const agentMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildPrefixedMessage(CART_PREFIX, mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);
    const ed25519Ix = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);

    const clearIx = await program.methods
      .clear(
        orderHash, attestationHash, orderTotal,
        itemPrices, itemQuantities, itemCategories, itemSkus,
        merchantHash, currency, cartHash, traceHash, mandateHashArr,
        new BN(sigTimestamp)
      )
      .accountsPartial({
        agent: agent.publicKey,
        merchant: merchant.publicKey,
        mandate: mandatePda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      })
      .instruction();

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);
    tx.feePayer = agent.publicKey;
    tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
    tx.sign(agent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — mandate expired");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("MandateExpired") ||
          msg.includes("mandate_expired") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });
});

// ═══════════════════════════════════════════════════════════════
// Part 3: Escrow & Business Logic Tests
// ═══════════════════════════════════════════════════════════════

describe("Part 3: Escrow & Business Logic", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AgentMandate as Program<AgentMandate>;

  const principal = Keypair.generate();
  const agent = Keypair.generate();
  const merchant = Keypair.generate();
  const arbiter = Keypair.generate();

  const currency = "USD";
  const disputeWindowSec = new BN(2); // 2 seconds for test speed
  const merchantHash = sha256("merchant-acme");

  function orderHashFor(name: string): number[] {
    return Array.from(createHash("sha256").update(name).digest());
  }

  before(async () => {
    const airdropSigs = await Promise.all([
      provider.connection.requestAirdrop(principal.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(agent.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(merchant.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
      provider.connection.requestAirdrop(arbiter.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL),
    ]);
    for (const sig of airdropSigs) {
      await provider.connection.confirmTransaction(sig, "confirmed");
    }
  });

  // ── 3a: settle → release after dispute window ──
  it("3a. settle then release after dispute window", async () => {
    const mandateId = "settle-release-test";
    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, new BN(10_000), null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        disputeWindowSec, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const orderHash = orderHashFor("settle-release-order");
    const [holdPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("hold"), mandatePda.toBuffer(), Buffer.from(orderHash)],
      program.programId
    );

    // Settle
    await program.methods
      .settle(
        orderHash,
        new Array(64).fill(0),
        sha256("att-settle"),
        new BN(500),
        [new BN(250)],
        [2],
        [],
        [],
        merchantHash,
        currency
      )
      .accountsPartial({
        agent: agent.publicKey,
        merchant: merchant.publicKey,
        mandate: mandatePda,
      })
      .signers([agent])
      .rpc();

    // Verify hold was created
    let hold = await program.account.holdAccount.fetch(holdPda);
    expect(hold.amount.toNumber()).to.equal(500);
    expect(hold.released).to.equal(false);
    expect(hold.disputed).to.equal(false);

    // Wait for dispute window to pass (2 seconds + buffer)
    await new Promise((resolve) => setTimeout(resolve, 3000));

    // Release
    await program.methods
      .release()
      .accountsPartial({
        merchant: merchant.publicKey,
        hold: holdPda,
      })
      .signers([merchant])
      .rpc();

    // Verify hold is released
    hold = await program.account.holdAccount.fetch(holdPda);
    expect(hold.released).to.equal(true);
  });

  // ── 3b: dispute within window ──
  it("3b. dispute within window succeeds", async () => {
    const mandateId = "dispute-window-test";
    const longWindow = new BN(86400); // 24h window — we're well within it

    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, new BN(10_000), null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        longWindow, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const orderHash = orderHashFor("dispute-within-order");
    const [holdPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("hold"), mandatePda.toBuffer(), Buffer.from(orderHash)],
      program.programId
    );

    // Settle
    await program.methods
      .settle(
        orderHash,
        new Array(64).fill(0),
        sha256("att-dispute"),
        new BN(300),
        [new BN(150)],
        [2],
        [],
        [],
        merchantHash,
        currency
      )
      .accountsPartial({
        agent: agent.publicKey,
        merchant: merchant.publicKey,
        mandate: mandatePda,
      })
      .signers([agent])
      .rpc();

    // Dispute within window
    await program.methods
      .dispute()
      .accountsPartial({
        principal: principal.publicKey,
        mandate: mandatePda,
        hold: holdPda,
      })
      .signers([principal])
      .rpc();

    const hold = await program.account.holdAccount.fetch(holdPda);
    expect(hold.disputed).to.equal(true);
    expect(hold.released).to.equal(false);
  });

  // ── 3c: resolve with split ──
  it("3c. resolve disputed hold with split", async () => {
    const mandateId = "resolve-split-test";
    const longWindow = new BN(86400);

    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, new BN(10_000), null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        longWindow, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const orderHash = orderHashFor("resolve-split-order");
    const [holdPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("hold"), mandatePda.toBuffer(), Buffer.from(orderHash)],
      program.programId
    );

    // Settle 1000
    await program.methods
      .settle(
        orderHash,
        new Array(64).fill(0),
        sha256("att-resolve"),
        new BN(1000),
        [new BN(500)],
        [2],
        [],
        [],
        merchantHash,
        currency
      )
      .accountsPartial({
        agent: agent.publicKey,
        merchant: merchant.publicKey,
        mandate: mandatePda,
      })
      .signers([agent])
      .rpc();

    // Dispute
    await program.methods
      .dispute()
      .accountsPartial({
        principal: principal.publicKey,
        mandate: mandatePda,
        hold: holdPda,
      })
      .signers([principal])
      .rpc();

    // Resolve with 60/40 split (600 merchant, 400 principal)
    await program.methods
      .resolve(new BN(400), new BN(600))
      .accountsPartial({
        arbiter: arbiter.publicKey,
        hold: holdPda,
      })
      .signers([arbiter])
      .rpc();

    const hold = await program.account.holdAccount.fetch(holdPda);
    expect(hold.disputed).to.equal(true);
    expect(hold.released).to.equal(true);
  });

  // ── 3d: revoke mandate ──
  it("3d. revoke sets mandate.revoked = true", async () => {
    const mandateId = "revoke-test";
    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, new BN(10_000), null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        disputeWindowSec, null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    // Verify not revoked initially
    let mandate = await program.account.mandateAccount.fetch(mandatePda);
    expect(mandate.revoked).to.equal(false);

    // Revoke
    await program.methods
      .revoke()
      .accountsPartial({
        principal: principal.publicKey,
        mandate: mandatePda,
      })
      .signers([principal])
      .rpc();

    mandate = await program.account.mandateAccount.fetch(mandatePda);
    expect(mandate.revoked).to.equal(true);

    // Double revoke should fail
    try {
      await program.methods
        .revoke()
        .accountsPartial({
          principal: principal.publicKey,
          mandate: mandatePda,
        })
        .signers([principal])
        .rpc();
      expect.fail("Should have failed — already revoked");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("MandateAlreadyRevoked") ||
          msg.includes("mandate_already_revoked") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });

  // ── 3e: Budget across three orders ──
  it("3e. budget tracking across three orders", async () => {
    const mandateId = "budget-3orders-test";
    const sigTs = Math.floor(Date.now() / 1000);

    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    // maxTotal = 3000
    await program.methods
      .createMandate(
        mandateId, currency, new BN(3000), null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        new BN(3600), null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const mhArr = sha256("mandate-hash-budget");
    const cHash = sha256("cart-hash-budget");
    const tHash = sha256("trace-hash-budget");

    // Helper to do a clear with a given order total
    async function doClear(name: string, total: number) {
      const orderHash = orderHashFor(name);
      const attestationHash = sha256(`att-${name}`);

      const agentMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mhArr, orderHash, attestationHash, tHash, sigTs);
      const merchantMsg = buildPrefixedMessage(CART_PREFIX, mhArr, orderHash, cHash, tHash, sigTs);
      const ed25519Ix = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);

      const clearIx = await program.methods
        .clear(
          orderHash,
          attestationHash,
          new BN(total),
          [new BN(total)],
          [1],
          [],
          [],
          merchantHash,
          currency,
          cHash,
          tHash,
          mhArr,
          new BN(sigTs)
        )
        .accountsPartial({
          agent: agent.publicKey,
          merchant: merchant.publicKey,
          mandate: mandatePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .instruction();

      const tx = new Transaction();
      tx.add(ed25519Ix);
      tx.add(clearIx);
      tx.feePayer = agent.publicKey;
      tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
      tx.sign(agent);

      return provider.connection.sendRawTransaction(tx.serialize());
    }

    // Order 1: 1000 → APPROVE
    const sig1 = await doClear("budget-order-1", 1000);
    await provider.connection.confirmTransaction(sig1, "confirmed");

    let mandate = await program.account.mandateAccount.fetch(mandatePda);
    expect(mandate.spent.toNumber()).to.equal(1000);
    expect(mandate.orderCount).to.equal(1);

    // Order 2: 1500 → APPROVE (remaining: 500)
    const sig2 = await doClear("budget-order-2", 1500);
    await provider.connection.confirmTransaction(sig2, "confirmed");

    mandate = await program.account.mandateAccount.fetch(mandatePda);
    expect(mandate.spent.toNumber()).to.equal(2500);
    expect(mandate.orderCount).to.equal(2);

    // Order 3: 600 → REJECT (would exceed budget of 3000)
    try {
      const sig3 = await doClear("budget-order-3", 600);
      await provider.connection.confirmTransaction(sig3, "confirmed");
      expect.fail("Should have failed — budget exceeded");
    } catch (err: any) {
      expect(err.toString()).to.satisfy(
        (msg: string) =>
          msg.includes("BudgetExceeded") ||
          msg.includes("budget_exceeded") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${err}`
      );
    }
  });

  // ── 3f: Reputation counters ──
  it("3f. reputation counters increment on approved clear", async () => {
    const mandateId = "reputation-test";
    const sigTs = Math.floor(Date.now() / 1000);

    const [mandatePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("mandate"), principal.publicKey.toBuffer(), Buffer.from(mandateId)],
      program.programId
    );

    await program.methods
      .createMandate(
        mandateId, currency, new BN(10_000_000), null, null, null, null,
        [], [merchantHash], [],
        new BN(0), new BN(Math.floor(Date.now() / 1000) + 86400 * 365),
        new BN(3600), null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: agent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();

    const [reputationPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("reputation"), agent.publicKey.toBuffer()],
      program.programId
    );

    const mhArr = sha256("mandate-hash-rep");
    const cHash = sha256("cart-hash-rep");
    const tHash = sha256("trace-hash-rep");

    // Do two clears
    for (let i = 1; i <= 2; i++) {
      const orderHash = orderHashFor(`rep-order-${i}`);
      const attestationHash = sha256(`att-rep-${i}`);

      const agentMsg = buildPrefixedMessage(ATTESTATION_PREFIX, mhArr, orderHash, attestationHash, tHash, sigTs);
      const merchantMsg = buildPrefixedMessage(CART_PREFIX, mhArr, orderHash, cHash, tHash, sigTs);
      const ed25519Ix = buildDualEd25519Ix(agent, agentMsg, merchant, merchantMsg);

      const clearIx = await program.methods
        .clear(
          orderHash,
          attestationHash,
          new BN(100),
          [new BN(100)],
          [1],
          [],
          [],
          merchantHash,
          currency,
          cHash,
          tHash,
          mhArr,
          new BN(sigTs)
        )
        .accountsPartial({
          agent: agent.publicKey,
          merchant: merchant.publicKey,
          mandate: mandatePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        })
        .instruction();

      const tx = new Transaction();
      tx.add(ed25519Ix);
      tx.add(clearIx);
      tx.feePayer = agent.publicKey;
      tx.recentBlockhash = (await provider.connection.getLatestBlockhash()).blockhash;
      tx.sign(agent);

      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
    }

    // Check reputation
    const rep = await program.account.reputationAccount.fetch(reputationPda);
    expect(rep.agent.toBase58()).to.equal(agent.publicKey.toBase58());
    // The agent may have been used in other tests in the same suite (init_if_needed),
    // so approved should be at least 2
    expect(rep.approved.toNumber()).to.be.at.least(2);
    expect(rep.rejected.toNumber()).to.equal(0);
  });
});
