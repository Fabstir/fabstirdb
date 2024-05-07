import fabstirDBClient from "./fabstirDBClient";
import { config } from "dotenv";
config();

/**
 * Instance of the OrbitDB client, created using the backend URL.
 */
export let dbClient: any;
export let dbUrl: string;

/**
 * Creates a new instance of the OrbitDB client using the provided database URL and user public key.
 * This function is part of the library's public API, allowing external applications to interact with the database.
 *
 * @param {string} databaseUrl - The URL of the database.
 * @param {string} userPubKey - The public key of the user.
 * @returns {Object} An instance of the OrbitDB client, providing methods for interacting with the database.
 */
export const createDBClient = (databaseUrl: string, userPubKey: string) => {
  dbUrl = databaseUrl;
  dbClient = fabstirDBClient(dbUrl || "", userPubKey);

  return dbClient;
};

/**
 * Updates the OrbitDB client with a new instance created using the provided user public key.
 *
 * @param {string} userPubKey - The user's public key.
 */
export const updateDbClient = (userPubKey: string) => {
  dbClient = fabstirDBClient(dbUrl || "", userPubKey);
};

/**
 * Resets the OrbitDB client with a new instance created using the backend URL.
 */
export const resetDbClient = () => {
  dbClient = fabstirDBClient(dbUrl || "");
};

export default createDBClient;
