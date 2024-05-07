// src/utils/cryptoConstants.ts
export const crypto_pwhash_SALTBYTES = 16; // Manually set based on your requirements
export const crypto_pwhash_OPSLIMIT_INTERACTIVE = 2; // These are low values, meant for interactive usage. Check libsodium docs for recommendations.
export const crypto_pwhash_MEMLIMIT_INTERACTIVE = 67108864; // 64 MB, for interactive operations
export const crypto_pwhash_ALG_ARGON2ID13 = 2; // Typically, the value for Argon2id is '2', but verify with your libsodium version's documentation.
