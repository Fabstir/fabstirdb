// src/types/libsodium-wrappers.d.ts
declare module "libsodium-wrappers" {
  export function ready(): Promise<void>;

  export function from_string(data: string): Uint8Array;
  export function to_string(data: Uint8Array): string;

  export function to_base64(data: Uint8Array, variant: number): string;
  export function from_base64(data: string, variant: number): Uint8Array;

  export function randombytes_buf(length: number): Uint8Array;

  export function crypto_sign_keypair(): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };

  export function crypto_sign_seed_keypair(seed: Uint8Array): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };

  export function crypto_sign(
    message: Uint8Array,
    privateKey: Uint8Array
  ): Uint8Array;
  export function crypto_sign_open(
    signedMessage: Uint8Array,
    publicKey: Uint8Array
  ): Uint8Array | null;

  export function crypto_secretbox_easy(
    message: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array
  ): Uint8Array;
  export function crypto_secretbox_open_easy(
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array
  ): Uint8Array | null;

  export const crypto_secretbox_KEYBYTES: number;
  export const crypto_secretbox_NONCEBYTES: number;

  export function crypto_pwhash(
    keyLength: number,
    password: Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number,
    alg: number
  ): Uint8Array;

  export function crypto_generichash(
    hashLength: number,
    input: Uint8Array,
    key?: Uint8Array
  ): Uint8Array;

  export const crypto_pwhash_ALG_ARGON2ID13: number;
  export const crypto_pwhash_OPSLIMIT_INTERACTIVE: number;
  export const crypto_pwhash_MEMLIMIT_INTERACTIVE: number;

  // Add base64 variants type definition
  export const base64_variants: {
    ORIGINAL: number;
    ORIGINAL_NO_PADDING: number;
    URLSAFE: number;
    URLSAFE_NO_PADDING: number;
  };
}
