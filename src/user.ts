import { updateDbClient, dbClient, resetDbClient } from "./GlobalOrbit";
import { eventEmitter } from "./eventEmitter";
import { libsodium } from "./utils/libsodium";
import { to_base64, base64_variants } from "libsodium-wrappers";

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
  logout: () => void;
  recall: (options?: { sessionStorage?: boolean }) => any | null;
  session: () => UserSession | null;
  pair: () => UserKeys | null;
  exists: (alias: string) => Promise<boolean>;
  addWriteAcess: (path: string, publicKey: string) => Promise<void>;
  is: {
    pub: string;
    alias: string;
  };
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
 * @property {Function} logout - Logs out the current user by removing their session data from the session storage.
 * @property {Function} recall - Retrieves the user's session data from the session storage.
 * @property {Function} pair - Retrieves the user's key pair from the current session.
 * @property {Function} exists - Checks if a user exists based on ACL entries.
 * @property {Function} addWriteAcess - Asynchronously adds write access to a specified path for a user with a given public key.
 * @property {Object} is - An object with a getter for the public key of the current user session.
 */
const user: User = {
  /**
   * Asynchronously creates a new user with the given alias and password.
   *
   * This function generates a key pair from the alias and password, hashes the password,
   * requests a temporary token from the backend, and then sends a registration request to the backend.
   * If the registration is successful, it stores the user's session data in the session storage and updates the OrbitDB client.
   *
   * @async
   * @param {string} alias - The alias of the new user.
   * @param {string} pass - The password of the new user.
   * @param {function} cb - A callback function to be called with the result of the operation.
   * @throws Will throw an error if the registration fails.
   * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
   */
  create: async (alias: string, pass: string, cb: any) => {
    try {
      await libsodium.ensureReady();
      const keys = await libsodium.generateKeyPairFromSeed(alias, pass);
      const publicKey = to_base64(
        keys.publicKey,
        base64_variants.URLSAFE_NO_PADDING
      );
      const privateKey = to_base64(
        keys.privateKey,
        base64_variants.URLSAFE_NO_PADDING
      );
      const hashedPassword = await libsodium.hashPassword(pass);

      const tempTokenResponse = await fetch(
        `${process.env.NEXT_PUBLIC_BACKEND_URL}/request-token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ alias }),
        }
      );

      const tempTokenData = await tempTokenResponse.json();
      if (!tempTokenResponse.ok) {
        throw new Error(
          tempTokenData.message || "Failed to obtain temporary token."
        );
      }

      const registerResponse = await fetch(
        `${process.env.NEXT_PUBLIC_BACKEND_URL}/register`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tempTokenData.token}`,
          },
          body: JSON.stringify({
            alias,
            publicKey,
            hashedPassword,
          }),
        }
      );

      const registerData = await registerResponse.json();
      if (!registerResponse.ok) {
        throw new Error(registerData.message || "Registration failed.");
      }

      sessionStorage.setItem(
        "userSession",
        JSON.stringify({
          alias,
          token: registerData.token,
          keys: { pub: publicKey, priv: privateKey },
        })
      );

      cb(null, {
        token: registerData.token,
        keys: { pub: publicKey, priv: privateKey },
      });
      updateDbClient(publicKey);
    } catch (error) {
      console.error("Failed to create user:", error);
      cb(error);
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
    try {
      await libsodium.ensureReady();
      const keys = await libsodium.generateKeyPairFromSeed(alias, pass);
      const publicKey = to_base64(
        keys.publicKey,
        base64_variants.URLSAFE_NO_PADDING
      );
      const privateKey = to_base64(
        keys.privateKey,
        base64_variants.URLSAFE_NO_PADDING
      );

      const tempTokenResponse = await fetch(
        `${process.env.NEXT_PUBLIC_BACKEND_URL}/request-token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ alias }),
        }
      );

      const tempTokenData = await tempTokenResponse.json();
      if (!tempTokenResponse.ok) {
        throw new Error(
          tempTokenData.message || "Failed to obtain temporary token."
        );
      }

      const authResponse = await fetch(
        `${process.env.NEXT_PUBLIC_BACKEND_URL}/authenticate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${tempTokenData.token}`,
          },
          body: JSON.stringify({ alias, pass }),
        }
      );

      const authData = await authResponse.json();
      if (!authResponse.ok) {
        throw new Error(authData.message || "Authentication failed.");
      }

      sessionStorage.setItem(
        "userSession",
        JSON.stringify({
          alias,
          token: authData.token,
          keys: { pub: publicKey, priv: privateKey },
        })
      );

      updateDbClient(authData.publicKey);
      cb(null, {
        token: authData.token,
        keys: { pub: authData.publicKey, priv: authData.privateKey },
      });

      // Emit an event upon successful authentication
      eventEmitter.emit("auth", {
        success: true,
        message: "Authentication successful",
        alias,
        keys: { pub: authData.publicKey, priv: authData.privateKey },
        token: authData.token,
      });
    } catch (error) {
      console.error("Authentication error:", error);
      cb(error);
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
      const { keys } = JSON.parse(session);
      return dbClient.user(keys.pub).get(path);
    }
    throw new Error("User is not logged in");
  },

  logout: () => {
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

  // Update the `exists` function to check for the existence of a user based on ACL entries.
  exists: async (alias: string) => {
    const session = sessionStorage.getItem("userSession");
    const sessionData = session ? JSON.parse(session) : null;
    const token = sessionData ? sessionData.token : null;

    try {
      // alias is the username to check for existence
      const aclResponse = await fetch(
        `${process.env.NEXT_PUBLIC_BACKEND_URL}/acl/${alias}`,
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        }
      );

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
  addWriteAcess: async (path: string, publicKey: string) => {
    const session = sessionStorage.getItem("userSession");
    const sessionData = session ? JSON.parse(session) : null;
    const token = sessionData ? sessionData.token : null;

    try {
      const registerResponse = await fetch(
        `${process.env.NEXT_PUBLIC_BACKEND_URL}/add-write-access`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            path,
            publicKey,
          }),
        }
      );

      if (!registerResponse.ok) {
        throw new Error(`HTTP error! status: ${registerResponse.status}`);
      }
    } catch (error) {
      console.error("An error occurred:", error);
    }
  },

  // Define the 'is' property with a getter for the public key
  is: {
    /**
     * Gets the public key from the current user session.
     *
     * @returns {string} The public key.
     * @throws {Error} If no active session is found.
     */
    get pub() {
      const sessionData = sessionStorage.getItem("userSession");
      if (sessionData) {
        const { keys } = JSON.parse(sessionData);
        return keys.pub;
      }
      throw new Error("No active session found");
    },

    /**
     * Gets the user's alias from the current user session.
     *
     * @returns {string} The alias.
     * @throws {Error} If no active session is found.
     */
    get alias() {
      const sessionData = sessionStorage.getItem("userSession");
      if (sessionData) {
        const { alias } = JSON.parse(sessionData);
        return alias;
      }
      throw new Error("No active session found");
    },
  },
};

export default user;
