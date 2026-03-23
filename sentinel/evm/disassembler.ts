/**
 * EVM Bytecode Disassembler
 *
 * Decodes raw EVM bytecode into structured instruction sequences.
 * Full opcode table (~140 opcodes), proper PUSH1-PUSH32 operand handling,
 * JUMPDEST tracking, and unreachable/data region detection.
 */

import type { Hex } from "viem";

// ─── Types ────────────────────────────────────────────────────────────────

export interface EVMInstruction {
  offset: number;
  opcode: number;
  mnemonic: string;
  operand: Uint8Array | null; // non-null only for PUSH1-PUSH32
  size: number; // total bytes (1 for non-PUSH, 1+N for PUSHN)
}

export interface DisassemblyResult {
  instructions: EVMInstruction[];
  jumpDests: Set<number>;
  bytecodeBytes: Uint8Array;
  /** Offsets of bytes that are PUSH operand data, not opcodes. */
  dataOffsets: Set<number>;
}

// ─── Opcode Table ─────────────────────────────────────────────────────────

const MNEMONICS: Record<number, string> = {
  0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
  0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
  0x0a: "EXP", 0x0b: "SIGNEXTEND",
  0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
  0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
  0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR",
  0x20: "SHA3",
  0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
  0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
  0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
  0x3a: "GASPRICE", 0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY",
  0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
  0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER",
  0x44: "PREVRANDAO", 0x45: "GASLIMIT", 0x46: "CHAINID",
  0x47: "SELFBALANCE", 0x48: "BASEFEE",
  0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
  0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
  0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST",
  0x5f: "PUSH0",
  0xa0: "LOG0", 0xa1: "LOG1", 0xa2: "LOG2", 0xa3: "LOG3", 0xa4: "LOG4",
  0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN",
  0xf4: "DELEGATECALL", 0xf5: "CREATE2",
  0xfa: "STATICCALL", 0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
};

// PUSH1-PUSH32: 0x60..0x7f
for (let i = 0; i < 32; i++) {
  MNEMONICS[0x60 + i] = `PUSH${i + 1}`;
}
// DUP1-DUP16: 0x80..0x8f
for (let i = 0; i < 16; i++) {
  MNEMONICS[0x80 + i] = `DUP${i + 1}`;
}
// SWAP1-SWAP16: 0x90..0x9f
for (let i = 0; i < 16; i++) {
  MNEMONICS[0x90 + i] = `SWAP${i + 1}`;
}

export function getMnemonic(opcode: number): string {
  return MNEMONICS[opcode] ?? `UNKNOWN(0x${opcode.toString(16).padStart(2, "0")})`;
}

/** Returns the number of PUSH operand bytes (0 for non-PUSH). */
export function pushSize(opcode: number): number {
  if (opcode >= 0x60 && opcode <= 0x7f) return opcode - 0x5f; // PUSH1=1, PUSH32=32
  return 0;
}

/**
 * Stack effect: [items_popped, items_pushed] for each opcode.
 * Used by abstract stack tracker.
 */
export const STACK_EFFECTS: Record<number, [number, number]> = {
  0x00: [0, 0], // STOP
  0x01: [2, 1], // ADD
  0x02: [2, 1], // MUL
  0x03: [2, 1], // SUB
  0x04: [2, 1], // DIV
  0x05: [2, 1], // SDIV
  0x06: [2, 1], // MOD
  0x07: [2, 1], // SMOD
  0x08: [3, 1], // ADDMOD
  0x09: [3, 1], // MULMOD
  0x0a: [2, 1], // EXP
  0x0b: [2, 1], // SIGNEXTEND
  0x10: [2, 1], // LT
  0x11: [2, 1], // GT
  0x12: [2, 1], // SLT
  0x13: [2, 1], // SGT
  0x14: [2, 1], // EQ
  0x15: [1, 1], // ISZERO
  0x16: [2, 1], // AND
  0x17: [2, 1], // OR
  0x18: [2, 1], // XOR
  0x19: [1, 1], // NOT
  0x1a: [2, 1], // BYTE
  0x1b: [2, 1], // SHL
  0x1c: [2, 1], // SHR
  0x1d: [2, 1], // SAR
  0x20: [2, 1], // SHA3
  0x30: [0, 1], // ADDRESS
  0x31: [1, 1], // BALANCE
  0x32: [0, 1], // ORIGIN
  0x33: [0, 1], // CALLER
  0x34: [0, 1], // CALLVALUE
  0x35: [1, 1], // CALLDATALOAD
  0x36: [0, 1], // CALLDATASIZE
  0x37: [3, 0], // CALLDATACOPY
  0x38: [0, 1], // CODESIZE
  0x39: [3, 0], // CODECOPY
  0x3a: [0, 1], // GASPRICE
  0x3b: [1, 1], // EXTCODESIZE
  0x3c: [4, 0], // EXTCODECOPY
  0x3d: [0, 1], // RETURNDATASIZE
  0x3e: [3, 0], // RETURNDATACOPY
  0x3f: [1, 1], // EXTCODEHASH
  0x40: [1, 1], // BLOCKHASH
  0x41: [0, 1], // COINBASE
  0x42: [0, 1], // TIMESTAMP
  0x43: [0, 1], // NUMBER
  0x44: [0, 1], // PREVRANDAO
  0x45: [0, 1], // GASLIMIT
  0x46: [0, 1], // CHAINID
  0x47: [0, 1], // SELFBALANCE
  0x48: [0, 1], // BASEFEE
  0x50: [1, 0], // POP
  0x51: [1, 1], // MLOAD
  0x52: [2, 0], // MSTORE
  0x53: [2, 0], // MSTORE8
  0x54: [1, 1], // SLOAD
  0x55: [2, 0], // SSTORE
  0x56: [1, 0], // JUMP
  0x57: [2, 0], // JUMPI
  0x58: [0, 1], // PC
  0x59: [0, 1], // MSIZE
  0x5a: [0, 1], // GAS
  0x5b: [0, 0], // JUMPDEST
  0x5f: [0, 1], // PUSH0
  0xa0: [2, 0], // LOG0
  0xa1: [3, 0], // LOG1
  0xa2: [4, 0], // LOG2
  0xa3: [5, 0], // LOG3
  0xa4: [6, 0], // LOG4
  0xf0: [3, 1], // CREATE
  0xf1: [7, 1], // CALL
  0xf2: [7, 1], // CALLCODE
  0xf3: [2, 0], // RETURN
  0xf4: [6, 1], // DELEGATECALL
  0xf5: [4, 1], // CREATE2
  0xfa: [6, 1], // STATICCALL
  0xfd: [2, 0], // REVERT
  0xfe: [0, 0], // INVALID
  0xff: [1, 0], // SELFDESTRUCT
};

// PUSH0-PUSH32
STACK_EFFECTS[0x5f] = [0, 1];
for (let i = 0; i < 32; i++) STACK_EFFECTS[0x60 + i] = [0, 1];
// DUP1-DUP16
for (let i = 0; i < 16; i++) STACK_EFFECTS[0x80 + i] = [i + 1, i + 2];
// SWAP1-SWAP16
for (let i = 0; i < 16; i++) STACK_EFFECTS[0x90 + i] = [i + 2, i + 2];

// ─── Disassembler ─────────────────────────────────────────────────────────

/**
 * Checks if raw bytecode contains a specific opcode, respecting PUSH operand
 * boundaries. This replaces naive `code.includes("f4")` style checks.
 */
export function containsOpcode(bytecodeHex: string, opcodeHex: string): boolean {
  const code = bytecodeHex.startsWith("0x") ? bytecodeHex.slice(2) : bytecodeHex;
  const targetOpcode = parseInt(opcodeHex, 16);
  const bytes = hexToBytes(code);

  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    if (op === targetOpcode) return true;
    const ps = pushSize(op);
    i += 1 + ps;
  }
  return false;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const len = Math.floor(clean.length / 2);
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function operandToHex(operand: Uint8Array | null): string | null {
  if (!operand) return null;
  return "0x" + bytesToHex(operand);
}

export function operandToBigInt(operand: Uint8Array | null): bigint | null {
  if (!operand || operand.length === 0) return null;
  return BigInt("0x" + bytesToHex(operand));
}

/**
 * Disassembles raw EVM bytecode into structured instructions.
 */
export function disassemble(bytecode: Hex | string): DisassemblyResult {
  const hex = bytecode.startsWith("0x") ? bytecode.slice(2) : bytecode;
  const bytes = hexToBytes(hex);
  const instructions: EVMInstruction[] = [];
  const jumpDests = new Set<number>();
  const dataOffsets = new Set<number>();

  let i = 0;
  while (i < bytes.length) {
    const opcode = bytes[i];
    const mnemonic = getMnemonic(opcode);
    const ps = pushSize(opcode);
    let operand: Uint8Array | null = null;

    if (ps > 0) {
      operand = bytes.slice(i + 1, i + 1 + ps);
      // Mark operand bytes as data
      for (let j = i + 1; j < i + 1 + ps && j < bytes.length; j++) {
        dataOffsets.add(j);
      }
    }

    if (opcode === 0x5b) {
      jumpDests.add(i);
    }

    instructions.push({
      offset: i,
      opcode,
      mnemonic,
      operand,
      size: 1 + ps,
    });

    i += 1 + ps;
  }

  return { instructions, jumpDests, bytecodeBytes: bytes, dataOffsets };
}
