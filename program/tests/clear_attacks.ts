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

function sha256(input: string): number[] {
  const hash = createHash("sha256").update(input).digest();
  return Array.from(hash);
}

function sha256Bytes(input: Buffer): number[] {
  const hash = createHash("sha256").update(input).digest();
  return Array.from(hash);
}

/**
 * Build the 136-byte message that the on-chain program reconstructs:
 * mandate_hash (32) || order_hash (32) || content_hash (32) || trace_hash (32) || timestamp_le (8)
 */
function buildMessage(
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
 * Build an Ed25519 precompile instruction with TWO signatures.
 *
 * Layout:
 *   [0]    num_signatures = 2
 *   [1]    padding = 0
 *   [2..16]  offsets for sig 0 (14 bytes = 7 x u16 LE)
 *   [16..30] offsets for sig 1
 *   [30..]   sig0 (64) | pubkey0 (32) | msg0 (136) | sig1 (64) | pubkey1 (32) | msg1 (136)
 */
function buildDualEd25519Ix(
  keypair0: Keypair,
  message0: Buffer,
  keypair1: Keypair,
  message1: Buffer
): TransactionInstruction {
  const headerSize = 2;
  const offsetsSize = 14 * 2; // 2 entries x 14 bytes each
  const dataStart = headerSize + offsetsSize;

  // Entry 0 data starts at dataStart
  const sig0Offset = dataStart;
  const pk0Offset = sig0Offset + 64;
  const msg0Offset = pk0Offset + 32;
  const msg0Size = message0.length;

  // Entry 1 data starts after entry 0
  const sig1Offset = msg0Offset + msg0Size;
  const pk1Offset = sig1Offset + 64;
  const msg1Offset = pk1Offset + 32;
  const msg1Size = message1.length;

  const totalLen = msg1Offset + msg1Size;
  const data = Buffer.alloc(totalLen);

  // Header
  data[0] = 2; // num_signatures
  data[1] = 0; // padding

  // Offsets entry 0 (at byte 2)
  let off = 2;
  data.writeUInt16LE(sig0Offset, off);     off += 2; // signature_offset
  data.writeUInt16LE(0xFFFF, off);         off += 2; // signature_instruction_index = u16::MAX
  data.writeUInt16LE(pk0Offset, off);      off += 2; // public_key_offset
  data.writeUInt16LE(0xFFFF, off);         off += 2; // public_key_instruction_index = u16::MAX
  data.writeUInt16LE(msg0Offset, off);     off += 2; // message_data_offset
  data.writeUInt16LE(msg0Size, off);       off += 2; // message_data_size
  data.writeUInt16LE(0xFFFF, off);         off += 2; // message_instruction_index = u16::MAX

  // Offsets entry 1 (at byte 16)
  data.writeUInt16LE(sig1Offset, off);     off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;
  data.writeUInt16LE(pk1Offset, off);      off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;
  data.writeUInt16LE(msg1Offset, off);     off += 2;
  data.writeUInt16LE(msg1Size, off);       off += 2;
  data.writeUInt16LE(0xFFFF, off);         off += 2;

  // Sign messages
  const sig0 = nacl.sign.detached(message0, keypair0.secretKey);
  const sig1 = nacl.sign.detached(message1, keypair1.secretKey);

  // Write data
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

/**
 * Build a SINGLE-signature Ed25519 precompile instruction (num_signatures=1).
 */
function buildSingleEd25519Ix(
  keypair: Keypair,
  message: Buffer
): TransactionInstruction {
  const headerSize = 2;
  const offsetsSize = 14; // 1 entry
  const dataStart = headerSize + offsetsSize;

  const sigOffset = dataStart;
  const pkOffset = sigOffset + 64;
  const msgOffset = pkOffset + 32;
  const msgSize = message.length;

  const totalLen = msgOffset + msgSize;
  const data = Buffer.alloc(totalLen);

  data[0] = 1; // num_signatures = 1
  data[1] = 0;

  let off = 2;
  data.writeUInt16LE(sigOffset, off);   off += 2;
  data.writeUInt16LE(0xFFFF, off);      off += 2;
  data.writeUInt16LE(pkOffset, off);    off += 2;
  data.writeUInt16LE(0xFFFF, off);      off += 2;
  data.writeUInt16LE(msgOffset, off);   off += 2;
  data.writeUInt16LE(msgSize, off);     off += 2;
  data.writeUInt16LE(0xFFFF, off);      off += 2;

  const sig = nacl.sign.detached(message, keypair.secretKey);
  Buffer.from(sig).copy(data, sigOffset);
  keypair.publicKey.toBuffer().copy(data, pkOffset);
  message.copy(data, msgOffset);

  return new TransactionInstruction({
    keys: [],
    programId: Ed25519Program.programId,
    data,
  });
}

/**
 * Build a dual Ed25519 ix where instruction_index fields are NOT u16::MAX
 * (pointing to instruction index 0 instead). The on-chain program must reject this.
 */
function buildDualEd25519IxBadIndex(
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

  // Entry 0: instruction_index = 0 (NOT u16::MAX) — ATTACK
  let off = 2;
  data.writeUInt16LE(sig0Offset, off);     off += 2;
  data.writeUInt16LE(0, off);              off += 2; // BAD: points to ix 0
  data.writeUInt16LE(pk0Offset, off);      off += 2;
  data.writeUInt16LE(0, off);              off += 2; // BAD
  data.writeUInt16LE(msg0Offset, off);     off += 2;
  data.writeUInt16LE(msg0Size, off);       off += 2;
  data.writeUInt16LE(0, off);              off += 2; // BAD

  // Entry 1: also bad indices
  data.writeUInt16LE(sig1Offset, off);     off += 2;
  data.writeUInt16LE(0, off);              off += 2;
  data.writeUInt16LE(pk1Offset, off);      off += 2;
  data.writeUInt16LE(0, off);              off += 2;
  data.writeUInt16LE(msg1Offset, off);     off += 2;
  data.writeUInt16LE(msg1Size, off);       off += 2;
  data.writeUInt16LE(0, off);              off += 2;

  // Still put valid sigs so the ed25519 precompile doesn't reject the tx
  // (precompile with ix_index != u16::MAX reads from another instruction)
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

describe("clear instruction — Ed25519 introspection attack vectors", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.AgentMandate as Program<AgentMandate>;

  // Actors
  const principal = Keypair.generate();
  const correctAgent = Keypair.generate();
  const wrongAgent = Keypair.generate();
  const merchant = Keypair.generate();

  // Mandate params
  const mandateId = "test-mandate-ed25519";
  const currency = "USD";
  const maxTotal = new BN(10_000_000);
  const validFrom = new BN(0);
  const validUntil = new BN(Math.floor(Date.now() / 1000) + 86400 * 365);
  const disputeWindowSec = new BN(3600);
  const merchantHash = sha256("merchant-acme");

  // Shared clear args
  const cartSignature = new Array(64).fill(0);
  const orderTotal = new BN(100);
  const itemPrices = [new BN(50)];
  const itemQuantities = [2];
  const itemCategories: number[][] = [];
  const itemSkus: number[][] = [];

  // Additional args for Ed25519 message
  const cartHash = sha256("cart-data");
  const traceHash = sha256("trace-data");
  const mandateHashArr = sha256("mandate-hash-data");
  const sigTimestamp = Math.floor(Date.now() / 1000);

  let mandatePda: PublicKey;

  // Helper: unique order hash from test name
  function orderHashFor(name: string): number[] {
    return Array.from(createHash("sha256").update(name).digest());
  }

  // Helper: build the clear instruction via anchor then get raw ix
  async function buildClearIx(
    orderHash: number[],
    agentKp: Keypair,
    attestationHash: number[],
    opts?: {
      merchantPk?: PublicKey;
    }
  ): Promise<TransactionInstruction> {
    const merchPk = opts?.merchantPk ?? merchant.publicKey;
    return await program.methods
      .clear(
        orderHash,
        cartSignature,
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
    // Airdrop SOL to all parties
    const airdropSigs = await Promise.all([
      provider.connection.requestAirdrop(
        principal.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL
      ),
      provider.connection.requestAirdrop(
        correctAgent.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL
      ),
      provider.connection.requestAirdrop(
        wrongAgent.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL
      ),
      provider.connection.requestAirdrop(
        merchant.publicKey,
        10 * anchor.web3.LAMPORTS_PER_SOL
      ),
    ]);
    for (const sig of airdropSigs) {
      await provider.connection.confirmTransaction(sig, "confirmed");
    }

    // Derive mandate PDA
    [mandatePda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("mandate"),
        principal.publicKey.toBuffer(),
        Buffer.from(mandateId),
      ],
      program.programId
    );

    // Create the mandate with merchant allowlist
    await program.methods
      .createMandate(
        mandateId,
        currency,
        maxTotal,
        null,
        null,
        null,
        null,
        [],
        [merchantHash],
        [],
        validFrom,
        validUntil,
        disputeWindowSec,
        null
      )
      .accountsPartial({
        principal: principal.publicKey,
        agent: correctAgent.publicKey,
        principalToken: null,
        escrowToken: null,
      })
      .signers([principal])
      .rpc();
  });

  // ────────────────────────────────────────────────────────
  // Test 1: No precompile — call clear without Ed25519 instruction
  // ────────────────────────────────────────────────────────
  it("1. rejects clear without Ed25519 precompile instruction", async () => {
    const orderHash = orderHashFor("attack-no-precompile");
    const attestationHash = sha256("att-no-precompile");

    // Build clear ix and send WITHOUT any Ed25519 precompile preceding it
    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    const tx = new Transaction();
    tx.add(clearIx); // only the clear ix, no ed25519

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — no Ed25519 precompile");
    } catch (err: any) {
      const errMsg = err.toString();
      expect(errMsg).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519Missing") ||
          msg.includes("ed25519_missing") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${errMsg}`
      );
    }
  });

  // ────────────────────────────────────────────────────────
  // Test 2: Precompile at wrong position (after clear, not before)
  // ────────────────────────────────────────────────────────
  it("2. rejects clear when precompile is at wrong position (after clear)", async () => {
    const orderHash = orderHashFor("attack-wrong-position");
    const attestationHash = sha256("att-wrong-pos");

    const agentMsg = buildMessage(mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildMessage(mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);
    const ed25519Ix = buildDualEd25519Ix(correctAgent, agentMsg, merchant, merchantMsg);

    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    // Wrong order: clear first, then ed25519
    const tx = new Transaction();
    tx.add(clearIx);
    tx.add(ed25519Ix);

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — precompile at wrong position");
    } catch (err: any) {
      const errMsg = err.toString();
      // Could be Ed25519Missing (no instruction at -1 that's ed25519)
      // or Ed25519WrongProgram if -1 resolves to something else
      expect(errMsg).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519Missing") ||
          msg.includes("Ed25519WrongProgram") ||
          msg.includes("ed25519") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${errMsg}`
      );
    }
  });

  // ────────────────────────────────────────────────────────
  // Test 3: Precompile with wrong pubkey (not mandate's agent)
  // ────────────────────────────────────────────────────────
  it("3. rejects clear when Ed25519 precompile uses wrong pubkey", async () => {
    const orderHash = orderHashFor("attack-wrong-pubkey");
    const attestationHash = sha256("att-wrong-pk");

    const agentMsg = buildMessage(mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildMessage(mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);

    // Use wrongAgent for signature 0 instead of correctAgent
    const ed25519Ix = buildDualEd25519Ix(wrongAgent, agentMsg, merchant, merchantMsg);

    // We still need correctAgent as the signer for the clear ix (account constraint)
    // but the ed25519 precompile has wrongAgent's pubkey
    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — wrong pubkey in Ed25519 precompile");
    } catch (err: any) {
      const errMsg = err.toString();
      expect(errMsg).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519PubkeyMismatch") ||
          msg.includes("ed25519_pubkey_mismatch") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${errMsg}`
      );
    }
  });

  // ────────────────────────────────────────────────────────
  // Test 4: Right pubkey but wrong message content
  // ────────────────────────────────────────────────────────
  it("4. rejects clear when Ed25519 message content differs from args", async () => {
    const orderHash = orderHashFor("attack-wrong-message");
    const attestationHash = sha256("att-wrong-msg");

    // Build message with WRONG content hash (agent signs different data)
    const wrongContentHash = sha256("wrong-attestation-content");
    const agentMsg = buildMessage(mandateHashArr, orderHash, wrongContentHash, traceHash, sigTimestamp);
    const merchantMsg = buildMessage(mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);
    const ed25519Ix = buildDualEd25519Ix(correctAgent, agentMsg, merchant, merchantMsg);

    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — message mismatch");
    } catch (err: any) {
      const errMsg = err.toString();
      expect(errMsg).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519MessageMismatch") ||
          msg.includes("ed25519_message_mismatch") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${errMsg}`
      );
    }
  });

  // ────────────────────────────────────────────────────────
  // Test 5: instruction_index points to other instruction (not u16::MAX)
  // ────────────────────────────────────────────────────────
  it("5. rejects clear when instruction_index != u16::MAX", async () => {
    const orderHash = orderHashFor("attack-bad-ix-index");
    const attestationHash = sha256("att-bad-idx");

    const agentMsg = buildMessage(mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildMessage(mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);
    const ed25519Ix = buildDualEd25519IxBadIndex(correctAgent, agentMsg, merchant, merchantMsg);

    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — instruction_index != u16::MAX");
    } catch (err: any) {
      const errMsg = err.toString();
      // The ed25519 precompile itself may reject (invalid sig if referencing
      // another ix), or our program catches Ed25519BadIndex
      expect(errMsg).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519BadIndex") ||
          msg.includes("ed25519_bad_index") ||
          msg.includes("custom program error") ||
          msg.includes("InvalidAccountIndex") ||
          msg.includes("invalid instruction") ||
          msg.includes("0x"),
        `Unexpected error: ${errMsg}`
      );
    }
  });

  // ────────────────────────────────────────────────────────
  // Test 6: Only one signature instead of two
  // ────────────────────────────────────────────────────────
  it("6. rejects clear when Ed25519 precompile has only 1 signature", async () => {
    const orderHash = orderHashFor("attack-one-sig");
    const attestationHash = sha256("att-one-sig");

    const agentMsg = buildMessage(mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const ed25519Ix = buildSingleEd25519Ix(correctAgent, agentMsg);

    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    try {
      const sig = await provider.connection.sendRawTransaction(tx.serialize());
      await provider.connection.confirmTransaction(sig, "confirmed");
      expect.fail("Should have failed — only 1 signature");
    } catch (err: any) {
      const errMsg = err.toString();
      expect(errMsg).to.satisfy(
        (msg: string) =>
          msg.includes("Ed25519SigCount") ||
          msg.includes("ed25519_sig_count") ||
          msg.includes("custom program error") ||
          msg.includes("0x"),
        `Unexpected error: ${errMsg}`
      );
    }
  });

  // ────────────────────────────────────────────────────────
  // Test 7: CPI attack — call clear through CPI from another program
  // Known limitation: testing CPI requires deploying a separate program.
  // We document the guard here and verify the CPI check exists in code.
  // The on-chain code calls get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT.
  // ────────────────────────────────────────────────────────
  it("7. CPI guard exists in code (documented limitation — needs separate program to test)", async () => {
    // We cannot easily deploy a CPI-wrapper program in this test suite.
    // The on-chain code has: get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT
    // which rejects any CPI call. We verify the error code exists.
    const errCodes = (program.idl as any).errors || [];
    const cpiErr = errCodes.find(
      (e: any) => e.name === "CpiNotAllowed" || e.name === "cpiNotAllowed"
    );
    expect(cpiErr).to.not.be.undefined;
    console.log(
      "    CPI guard: get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT " +
        "is enforced on-chain. Full CPI test requires a separate deployed program."
    );
  });

  // ────────────────────────────────────────────────────────
  // Test 8: Sanity — correct dual Ed25519 precompile SUCCEEDS
  // ────────────────────────────────────────────────────────
  it("8. sanity: correctly built dual Ed25519 precompile succeeds", async () => {
    const orderHash = orderHashFor("sanity-dual-ed25519");
    const attestationHash = sha256("att-sanity");

    // Build correct messages
    const agentMsg = buildMessage(mandateHashArr, orderHash, attestationHash, traceHash, sigTimestamp);
    const merchantMsg = buildMessage(mandateHashArr, orderHash, cartHash, traceHash, sigTimestamp);

    // Build the dual Ed25519 precompile instruction
    const ed25519Ix = buildDualEd25519Ix(correctAgent, agentMsg, merchant, merchantMsg);

    // Build clear instruction
    const clearIx = await buildClearIx(orderHash, correctAgent, attestationHash);

    // Transaction: ed25519 at index 0, clear at index 1 (clear - 1 = ed25519)
    const tx = new Transaction();
    tx.add(ed25519Ix);
    tx.add(clearIx);

    tx.feePayer = correctAgent.publicKey;
    tx.recentBlockhash = (
      await provider.connection.getLatestBlockhash()
    ).blockhash;
    tx.sign(correctAgent);

    const sig = await provider.connection.sendRawTransaction(tx.serialize());
    await provider.connection.confirmTransaction(sig, "confirmed");

    // Verify verdict was created
    const [verdictPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("verdict"), mandatePda.toBuffer(), Buffer.from(orderHash)],
      program.programId
    );
    const verdictAccount = await program.account.verdictAccount.fetch(verdictPda);
    expect(verdictAccount.mandate.toBase58()).to.equal(mandatePda.toBase58());
    expect(Buffer.from(verdictAccount.orderHash)).to.deep.equal(
      Buffer.from(orderHash)
    );
  });
});
