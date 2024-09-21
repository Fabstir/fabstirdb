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
  crypto_sign_ed25519_pk_to_curve25519,
  crypto_sign_ed25519_sk_to_curve25519,
  crypto_scalarmult,
  to_base64,
  from_base64,
  randombytes_buf,
  crypto_sign_seed_keypair,
  crypto_generichash,
  base64_variants,
  crypto_pwhash,
  crypto_pwhash_ALG_ARGON2ID13,
  crypto_pwhash_OPSLIMIT_INTERACTIVE,
  crypto_pwhash_MEMLIMIT_INTERACTIVE,
  crypto_pwhash_SALTBYTES,
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

export const FEA = {
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
    const seedInput = username + ":" + password;
    const seed = crypto_generichash(32, from_string(seedInput));

    // Generate an Ed25519 key pair for signing
    const signKeys = crypto_sign_seed_keypair(seed);

    // Convert Ed25519 keys to Curve25519 keys for encryption
    const encryptPublicKey = crypto_sign_ed25519_pk_to_curve25519(
      signKeys.publicKey
    );
    const encryptPrivateKey = crypto_sign_ed25519_sk_to_curve25519(
      signKeys.privateKey
    );

    return {
      // Ed25519 keys for signing
      pub: to_base64(signKeys.publicKey, base64_variants.URLSAFE_NO_PADDING), // Ed25519 public key
      priv: to_base64(signKeys.privateKey, base64_variants.URLSAFE_NO_PADDING), // Ed25519 private key

      // Curve25519 keys for encryption
      epub: to_base64(encryptPublicKey, base64_variants.URLSAFE_NO_PADDING), // Curve25519 public key
      epriv: to_base64(encryptPrivateKey, base64_variants.URLSAFE_NO_PADDING), // Curve25519 private key
    };
  },

  // Function to generate seed from username and password
  async generateSeedFromPassword(username: string, password: string) {
    await this.ensureReady();
    const seedInput = username + password; // Combine username and password
    const seed = crypto_generichash(32, from_string(seedInput)); // 32-byte seed
    return seed;
  },

  // Function to generate Ed25519 key pair from seed
  async generateKeyPairFromSeed(username: string, password: string) {
    const seed = await generateSeedFromPassword(username, password);
    const ed25519KeyPair = crypto_sign_seed_keypair(seed);

    // Convert Ed25519 keys to Curve25519 keys for encryption
    const curve25519PubKey = crypto_sign_ed25519_pk_to_curve25519(
      ed25519KeyPair.publicKey
    );
    const curve25519PrivKey = crypto_sign_ed25519_sk_to_curve25519(
      ed25519KeyPair.privateKey
    );

    return {
      ed25519KeyPair, // Original Ed25519 key pair
      curve25519KeyPair: {
        publicKey: curve25519PubKey,
        privateKey: curve25519PrivKey,
      },
    };
  },

  async pair() {
    await this.ensureReady();

    // Generate Ed25519 key pair (for signing)
    const { publicKey: ed25519Pub, privateKey: ed25519Priv } =
      crypto_sign_keypair();

    // Convert Ed25519 keys to Curve25519 keys (for encryption)
    const curve25519Pub = crypto_sign_ed25519_pk_to_curve25519(ed25519Pub);
    const curve25519Priv = crypto_sign_ed25519_sk_to_curve25519(ed25519Priv);

    // Return both signing and encryption keys
    return {
      pub: to_base64(ed25519Pub, base64_variants.URLSAFE_NO_PADDING), // Ed25519 public key
      priv: to_base64(ed25519Priv, base64_variants.URLSAFE_NO_PADDING), // Ed25519 private key
      epub: to_base64(curve25519Pub, base64_variants.URLSAFE_NO_PADDING), // Curve25519 public key
      epriv: to_base64(curve25519Priv, base64_variants.URLSAFE_NO_PADDING), // Curve25519 private key
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

  async encrypt(message: string, passphrase: string) {
    await this.ensureReady();

    // Use crypto_pwhash to derive a key from the passphrase
    const salt = randombytes_buf(crypto_pwhash_SALTBYTES); // Generate a random salt
    const key = crypto_pwhash(
      crypto_secretbox_KEYBYTES,
      from_string(passphrase),
      salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_ARGON2ID13
    );

    // Generate a nonce
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);

    // Encrypt the message
    const encryptedMsg = crypto_secretbox_easy(
      from_string(message),
      nonce,
      key
    );

    return {
      cipher: to_base64(encryptedMsg, base64_variants.URLSAFE_NO_PADDING),
      nonce: to_base64(nonce, base64_variants.URLSAFE_NO_PADDING),
      salt: to_base64(salt, base64_variants.URLSAFE_NO_PADDING), // Include the salt
    };
  },

  async decrypt(
    cipherData: { cipher: string; nonce: string; salt: string },
    passphrase: string
  ) {
    await this.ensureReady();

    // Derive the same key from the passphrase and the salt
    const salt = from_base64(
      cipherData.salt,
      base64_variants.URLSAFE_NO_PADDING
    );
    const key = crypto_pwhash(
      crypto_secretbox_KEYBYTES,
      from_string(passphrase),
      salt,
      crypto_pwhash_OPSLIMIT_INTERACTIVE,
      crypto_pwhash_MEMLIMIT_INTERACTIVE,
      crypto_pwhash_ALG_ARGON2ID13
    );

    // Decode the nonce
    const nonce = from_base64(
      cipherData.nonce,
      base64_variants.URLSAFE_NO_PADDING
    );

    // Decrypt the message
    const decryptedMsg = crypto_secretbox_open_easy(
      from_base64(cipherData.cipher, base64_variants.URLSAFE_NO_PADDING),
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

  async secret(
    theirEpub: string,
    myKeyPair: { epub: string; epriv: string }
  ): Promise<string> {
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
    const theirCurve25519PubKey = safeFromBase64(theirEpub); // Their public encryption key (Curve25519)
    const myCurve25519PrivKey = safeFromBase64(myKeyPair.epriv); // My private encryption key (Curve25519)

    // Compute the shared secret using Diffie-Hellman (crypto_scalarmult)
    const sharedSecret = crypto_scalarmult(
      myCurve25519PrivKey,
      theirCurve25519PubKey
    );

    // Encode the shared secret to Base64Url
    return to_base64(sharedSecret, base64_variants.URLSAFE_NO_PADDING);
  },
};
