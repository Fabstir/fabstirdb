import { updateDbClient, dbClient, resetDbClient, dbUrl } from "./GlobalOrbit";
import { eventEmitter } from "./eventEmitter";
import { FEA } from "./utils/libsodium";
import {
  to_base64,
  from_base64,
  from_string,
  crypto_sign_detached,
  base64_variants,
} from "libsodium-wrappers";
import { encodeUriPathSegments } from "./utils/pathUtils";

type UserKeys = {
  priv: string;
  pub: string;
  epriv?: string;
  epub?: string;
};

type UserSession = {
  alias: string;
  keys: UserKeys;
};

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";

type User = {
  create: (alias: string, pass: string, cb: any) => Promise<void>;
  auth: (alias: string, pass: string, cb: any) => Promise<void>;
  get: (path: string) => any;
  leave: () => void;
  recall: (options?: { sessionStorage?: boolean }) => any | null;
  session: () => UserSession | null;
  pair: () => UserKeys | null;
  _: {
    sea: UserKeys | null;
  };
  exists: (alias: string) => Promise<boolean>;
  addWriteAccess: (path: string, publicKey: string) => Promise<void>;
  removeWriteAccess: (path: string, publicKey: string) => Promise<void>;
  is: {
    pub: string;
    priv: string;
    epub: string;
    epriv: string;
    alias: string;
  } | null;
};

/**
 * `user` is an object that provides methods for user management.
 * It includes methods for creating and authenticating users,
 * retrieving user data, checking user existence, adding write access,
 * and managing user sessions.
 *
 * @typedef {Object} user
 * @property {Function} create - Asynchronously creates a new user with the given alias and password.
 * @property {Function} auth - Asynchronously authenticates a user with the given alias and password.
 * @property {Function} get - Retrieves data from a specified path for the current user session.
 * @property {Function} leave - Logs out the current user by removing their session data from the session storage.
 * @property {Function} recall - Retrieves the user's session data from the session storage.
 * @property {Function} pair - Retrieves the user's key pair from the current session.
 * @property {Function} exists - Checks if a user exists based on ACL entries.
 * @property {Function} addWriteAccess - Asynchronously adds write access to a specified path for a user with a given public key.
 * @property {Function} removeWriteAccess - Asynchronously removes write access from a specified path for a user with a given public key.
 * @property {Object} is - An object with a getter for the public key of the current user session.
 */
const user: User = {
  /**
   * Asynchronously creates a new user with the given alias and password.
   *
   * This function generates a key pair from the alias and password, hashes the password,
   * requests a temporary token from the backend, and then sends a registration request to the backend.
   * If the registration is successful, it returns the user's token and keys via the callback function and updates the OrbitDB client.
   * It does not log the user in or store the user's session data in the session storage.
   *
   * @async
   * @param {string} alias - The alias of the new user.
   * @param {string} pass - The password of the new user.
   * @param {function} cb - A callback function to be called with the result of the operation.
   * @throws Will throw an error if the registration fails.
   * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
   */
  create: async (alias: string, pass: string, cb: any) => {
    cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

    try {
      await FEA.ensureReady();
      const keys = await FEA.generateKeyPairsFromPassword(alias, pass);
      const hashedPassword = await FEA.hashPassword(pass);

      const tempTokenResponse = await fetch(`${dbUrl}/request-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias }),
      });

      const tempTokenData = await tempTokenResponse.json();
      if (!tempTokenResponse.ok) {
        throw new Error(
          tempTokenData.message || "Failed to obtain temporary token."
        );
      }

      const registerResponse = await fetch(`${dbUrl}/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tempTokenData.token}`,
        },
        body: JSON.stringify({
          alias: `~%40${encodeURIComponent(alias)}/`,
          publicKey: keys.pub,
          hashedPassword,
        }),
      });

      const registerData = await registerResponse.json();
      if (!registerResponse.ok) {
        throw new Error(registerData.message || "Registration failed.");
      }

      updateDbClient(keys.pub);
      cb(
        { err: undefined },
        {
          token: registerData.token,
          keys,
        }
      );
      // Emit an event upon successful authentication
      eventEmitter.emit("create", {
        success: true,
        message: registerData.message,
        alias,
        keys,
        token: registerData.token,
      });
    } catch (error) {
      if (error instanceof Error) {
        console.error("Failed to create user:", error);
        cb({ err: error.message });
      } else {
        cb({ err: "unknown error" });
      }
    }
  },

  /**
   * Asynchronously authenticates a user with the given alias and password.
   *
   * This function generates a key pair from the alias and password, requests a temporary token from the backend,
   * and then sends an authentication request to the backend.
   * If the authentication is successful, it stores the user's session data in the session storage and updates the OrbitDB client.
   *
   * @async
   * @param {string} alias - The alias of the user.
   * @param {string} pass - The password of the user.
   * @param {function} cb - A callback function to be called with the result of the operation.
   * @throws Will throw an error if the authentication fails.
   * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
   */
  auth: async (alias: string, pass: string, cb: any) => {
    cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

    try {
      await FEA.ensureReady();
      const keys = await FEA.generateKeyPairsFromPassword(alias, pass);

      const tempTokenResponse = await fetch(`${dbUrl}/request-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias }),
      });

      const tempTokenData = await tempTokenResponse.json();
      if (!tempTokenResponse.ok) {
        throw new Error(
          tempTokenData.message || "Failed to obtain temporary token."
        );
      }

      const authResponse = await fetch(`${dbUrl}/authenticate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${tempTokenData.token}`,
        },
        body: JSON.stringify({
          alias: `~%40${encodeURIComponent(alias)}/`,
          pass,
        }),
      });

      if (!authResponse.ok) {
        cb({ err: (await authResponse.text()) || "Authentication failed." });
        return;
      }
      const authData = await authResponse.json();

      sessionStorage.setItem(
        "userSession",
        JSON.stringify({
          alias,
          token: authData.token,
          keys,
        })
      );

      updateDbClient(authData.publicKey);
      cb(
        { err: undefined },
        {
          token: authData.token,
          keys,
        }
      );

      // Emit an event upon successful authentication
      eventEmitter.emit("auth", {
        success: true,
        message: authData.message,
        alias,
        keys,
        token: authData.token,
      });
    } catch (error) {
      if (error instanceof Error) {
        console.error("Authentication error:", error);
        cb({ err: error.message });
      } else {
        cb({ err: "unknown error" });
      }
    }
  },

  /**
   * Retrieves data from a specified path for the current user session.
   *
   * @param {string} path - The path from which data should be retrieved.
   * @throws {Error} Will throw an error if no user session is found.
   * @returns {any} The data retrieved from the specified path.
   */
  get: function (path: string) {
    const session = sessionStorage.getItem("userSession");
    if (session) {
      const sessionObj = JSON.parse(session);
      return dbClient.user(sessionObj.keys.pub).get(path);
    }
    return dbClient.get("");
  },

  leave: () => {
    sessionStorage.removeItem("userSession");
    resetDbClient();
  },

  /**
   * Retrieves the user's session data from the session storage.
   *
   * If a session is found, it reconfigures the OrbitDB client with the user's public key and returns the session data.
   * If no session is found, it resets the OrbitDB client and returns null.
   *
   * @returns {UserSession | null} The user's session data if a session exists, or null if no session is found.
   */
  recall: function ({
    sessionStorage: useSessionStorage = true,
  }: {
    sessionStorage?: boolean;
  } = {}): User | null {
    if (!useSessionStorage) throw new Error("Session storage is not available");

    const sessionData = sessionStorage.getItem("userSession");
    if (sessionData) {
      const session: UserSession = JSON.parse(sessionData);
      updateDbClient(session.keys.pub); // Reconfigure client with current user's public key
      return user;
    }
    resetDbClient(); // No session, reset client
    return null;
  },

  /**
   * Retrieves the user's session data from the session storage.
   *
   * If a session is found, it reconfigures the OrbitDB client with the user's public key and returns the session data.
   * If no session is found, it resets the OrbitDB client and returns null.
   *
   * @returns {UserSession | null} The user's session data if a session exists, or null if no session is found.
   */
  session: function (): UserSession | null {
    const sessionData = sessionStorage.getItem("userSession");
    if (sessionData) {
      const session: UserSession = JSON.parse(sessionData);
      updateDbClient(session.keys.pub); // Reconfigure client with current user's public key
      return session;
    }
    resetDbClient(); // No session, reset client
    return null;
  },

  /**
   * Retrieves the user's key pair from the current session.
   *
   * @returns {UserKeys | null} The user's key pair if a session exists, or null if no session is found.
   */
  pair: (): UserKeys | null => {
    const session = user.recall({ sessionStorage: true });
    return session ? session.keys : null;
  },

  /**
   * Retrieves the user's key pair from the current session.
   *
   * @returns {UserKeys | null} The user's key pair if a session exists, or null if no session is found.
   */
  _: {
    get sea() {
      if (!user.is) return null;

      const pub = user.is.pub;
      const priv = user.is.priv;
      const epub = user.is.epub;
      const epriv = user.is.epriv;
      return { pub, priv, epub, epriv };
    },
  },

  /**
   * Asynchronously checks if a user with the given alias exists.
   *
   * This function sends a POST request to the /acl endpoint of the backend with the alias in the request body.
   * If the request is successful and the response data indicates that the user exists, it returns true.
   * Otherwise, it returns false.
   *
   * @async
   * @param {string} alias - The alias of the user to check.
   * @throws Will log an error to the console if the request fails.
   * @returns {Promise<boolean>} Returns a Promise that resolves to a boolean indicating whether the user exists.
   */
  exists: async (alias: string) => {
    try {
      // Send alias in the request body
      const aclResponse = await fetch(`${dbUrl}/acl`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ alias: `~%40${encodeURIComponent(alias)}/` }), // Send alias in the request body
      });

      const aclData = await aclResponse.json();
      return aclResponse.ok && aclData.exists;
    } catch (error) {
      console.error("Error checking user existence via ACL:", error);
      return false;
    }
  },

  /**
   * Asynchronously adds write access to a specified path for a user with a given public key.
   *
   * @async
   * @param {string} path - The path to which write access should be added.
   * @param {string} publicKey - The public key of the user to whom write access should be granted.
   * @throws Will throw an error if the HTTP request status is not OK.
   * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
   */
  addWriteAccess: async (path, publicKey) => {
    if (!path) {
      throw new Error("Path is not defined.");
    }

    if (!publicKey) {
      throw new Error("Public key is not defined.");
    }

    const formattedPath = path.endsWith("/") ? path : `${path}/`;
    const encodedPath = encodeUriPathSegments(formattedPath);

    const session = sessionStorage.getItem("userSession");
    const sessionData = session ? JSON.parse(session) : null;
    const token = sessionData ? sessionData.token : null;

    if (!sessionData || !sessionData.keys || !sessionData.keys.priv) {
      throw new Error(
        "Private key not found in session. User may need to log in again."
      );
    }

    // Use the `priv` field from sessionData.keys for the private key
    const privateKey = from_base64(
      sessionData.keys.priv,
      base64_variants.URLSAFE_NO_PADDING
    );

    // Message to sign
    const msgToSign = `${encodedPath}-${publicKey}-grant`;
    const msgBytes = from_string(msgToSign);

    // Generate the signature using the user's private key
    const signature = crypto_sign_detached(msgBytes, privateKey);

    try {
      const registerResponse = await fetch(`${dbUrl}/add-write-access`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          path: encodedPath,
          publicKey,
          signature: to_base64(signature, base64_variants.URLSAFE_NO_PADDING), // Send signature as base64
        }),
      });

      if (!registerResponse.ok) {
        throw new Error(`HTTP error! status: ${registerResponse.status}`);
      }
    } catch (error) {
      console.error("An error occurred:", error);
    }
  },

  /**
   * Asynchronously removes write access from a specified path for a user with a given public key.
   *
   * @async
   * @param {string} path - The path to which write access should be removed.
   * @param {string} publicKey - The public key of the user to whom write access should be removed.
   * @throws Will throw an error if the HTTP request status is not OK.
   * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
   */
  removeWriteAccess: async (path, publicKey) => {
    if (!path) {
      throw new Error("Path is not defined.");
    }

    if (!publicKey) {
      throw new Error("Public key is not defined.");
    }

    const formattedPath = path.endsWith("/") ? path : `${path}/`;
    const encodedPath = encodeUriPathSegments(formattedPath);

    const session = sessionStorage.getItem("userSession");
    const sessionData = session ? JSON.parse(session) : null;
    const token = sessionData ? sessionData.token : null;

    if (!sessionData || !sessionData.keys || !sessionData.keys.priv) {
      throw new Error(
        "Private key not found in session. User may need to log in again."
      );
    }

    // Use the `priv` field from sessionData.keys for the private key
    const privateKey = from_base64(
      sessionData.keys.priv,
      base64_variants.URLSAFE_NO_PADDING
    );

    // Message to sign
    const msgToSign = `${encodedPath}-${publicKey}-revoke`;
    const msgBytes = from_string(msgToSign);

    // Generate the signature using the user's private key
    const signature = crypto_sign_detached(msgBytes, privateKey);

    try {
      const registerResponse = await fetch(`${dbUrl}/remove-write-access`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          path: encodedPath,
          publicKey,
          signature: to_base64(signature, base64_variants.URLSAFE_NO_PADDING), // Send signature as base64
        }),
      });

      if (!registerResponse.ok) {
        throw new Error(`HTTP error! status: ${registerResponse.status}`);
      }
    } catch (error) {
      console.error("An error occurred:", error);
    }
  },

  // Define the 'is' property with a getter for the public key
  get is() {
    const sessionData = sessionStorage.getItem("userSession");

    if (!sessionData) {
      return null;
    }

    let sessionObj = null;

    try {
      sessionObj = JSON.parse(sessionData);
    } catch (e) {
      // sessionData is not a valid JSON string, ignore the error
    }

    return sessionObj && Object.keys(sessionObj).length > 0
      ? {
          /**
           * Gets the public key from the current user session.
           *
           * @returns {string} The public key.
           */
          get pub() {
            const { keys } = sessionObj;
            return keys.pub;
          },

          get priv() {
            const { keys } = sessionObj;
            return keys.priv;
          },

          get epub() {
            const { keys } = sessionObj;
            return keys.epub;
          },

          get epriv() {
            const { keys } = sessionObj;
            return keys.epriv;
          },

          /**
           * Gets the user's alias from the current user session.
           *
           * @returns {string} The alias.
           */
          get alias() {
            const { alias } = sessionObj;
            return alias;
          },
        }
      : null;
  },
};

export default user;
