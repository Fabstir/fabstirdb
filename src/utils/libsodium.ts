// libsodium.ts
import {
  ready,
  from_string,
  to_string,
  to_hex,
  crypto_sign_keypair,
  crypto_sign,
  crypto_sign_open,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_open_easy,
  crypto_box_seed_keypair,
  crypto_scalarmult,
  to_base64,
  from_base64,
  randombytes_buf,
  crypto_sign_seed_keypair,
  crypto_generichash,
  base64_variants,
} from "libsodium-wrappers";
import bcrypt from "bcryptjs";

const sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7;

interface KeyPair {
  pub: string;
  priv: string;
  epub: string;
  epriv: string;
}

async function generateSeedFromPassword(username: string, password: string) {
  await ready;
  const seedInput = username + password; // Combine or use a more complex scheme
  const seed = crypto_generichash(32, from_string(seedInput)); // Hash to get a 32-byte seed
  return seed;
}

export const libsodium = {
  ready: false,

  async ensureReady() {
    if (!this.ready) {
      await ready;
      this.ready = true;
    }
  },

  async generateKeyPairsFromPassword(username: string, password: string) {
    await this.ensureReady();

    // Generate a seed from the username and password
    const seedInput = username + ":" + password; // Use a delimiter for better security
    const seed = crypto_generichash(32, from_string(seedInput));

    // Generate an Ed25519 key pair for signing from the seed
    const signKeys = crypto_sign_seed_keypair(seed);

    // Generate a Curve25519 key pair for encryption from the same seed
    // If you need to derive encryption keys from the signing keys (not recommended), you could convert them.
    // However, to use the same seed to directly generate encryption keys:
    const encryptKeys = crypto_box_seed_keypair(seed);

    return {
      pub: to_base64(
        signKeys.publicKey,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
      ),
      priv: to_base64(
        signKeys.privateKey,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
      ),
      epub: to_base64(
        encryptKeys.publicKey,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
      ),
      epriv: to_base64(
        encryptKeys.privateKey,
        sodium_base64_VARIANT_URLSAFE_NO_PADDING
      ),
    };
  },

  async generateKeyPairFromSeed(username: string, password: string) {
    const seed = await generateSeedFromPassword(username, password);
    return crypto_sign_seed_keypair(seed);
  },

  async pair() {
    await this.ensureReady();
    const { publicKey, privateKey } = crypto_sign_keypair();
    return {
      pub: to_base64(publicKey, sodium_base64_VARIANT_URLSAFE_NO_PADDING),
      priv: to_base64(privateKey, sodium_base64_VARIANT_URLSAFE_NO_PADDING),
    };
  },

  async sign(message: string, keyPair: { priv: string }) {
    await this.ensureReady();
    const msgUint8 = from_string(message);
    const signedMsg = crypto_sign(msgUint8, from_string(keyPair.priv));
    return to_string(signedMsg);
  },

  async verify(signedMessage: string, pubKey: string) {
    await this.ensureReady();
    const signedMsgUint8 = from_string(signedMessage);
    const message = crypto_sign_open(signedMsgUint8, from_string(pubKey));
    if (message) {
      return to_string(message);
    }
    throw new Error("Invalid signature");
  },

  async encrypt(message: string, keyPair: { priv: string; pub: string }) {
    await this.ensureReady();
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
    const key = from_string(keyPair.priv.substr(0, crypto_secretbox_KEYBYTES));
    const encryptedMsg = crypto_secretbox_easy(
      from_string(message),
      nonce,
      key
    );
    return { cipher: to_string(encryptedMsg), nonce: to_string(nonce) };
  },

  async decrypt(
    cipherData: { cipher: string; nonce: string },
    keyPair: { priv: string }
  ) {
    await this.ensureReady();
    const nonce = from_string(cipherData.nonce);
    const key = from_string(keyPair.priv.substr(0, crypto_secretbox_KEYBYTES));
    const decryptedMsg = crypto_secretbox_open_easy(
      from_string(cipherData.cipher),
      nonce,
      key
    );
    if (decryptedMsg) {
      return to_string(decryptedMsg);
    }
    throw new Error("Decryption failed");
  },

  async hashPassword(password: string) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
  },

  async verifyPassword(password: string, hash: string) {
    return bcrypt.compare(password, hash);
  },

  async secret(theirPublicKey: string, myKeyPair: KeyPair): Promise<string> {
    await this.ensureReady(); // Ensure libsodium is ready

    // Function to safely decode Base64Url
    const safeFromBase64 = (str: string) => {
      try {
        return from_base64(str, base64_variants.URLSAFE_NO_PADDING);
      } catch (e) {
        // If decoding fails, try adding padding
        const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
        return from_base64(padded, base64_variants.URLSAFE_NO_PADDING);
      }
    };

    // Decode the public key and private key
    const theirPubKey = safeFromBase64(theirPublicKey);
    const myPrivKey = safeFromBase64(myKeyPair.epriv);

    // Compute the shared secret
    const sharedSecret = crypto_scalarmult(myPrivKey, theirPubKey);

    // Encode the shared secret to Base64Url
    return to_base64(sharedSecret, base64_variants.URLSAFE_NO_PADDING);
  },
};
