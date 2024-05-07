import crypto from "crypto";
import user from "./user";
import { config } from "dotenv";
import { dbUrl } from "./GlobalOrbit";
config();

/**
 * Interface for a Node object in OrbitDB.
 *
 * A Node object represents a node in the OrbitDB database. It provides methods for getting, putting, setting, loading data, and performing a one-time operation.
 *
 * @interface
 * @property {Function} get - Retrieves a Node object from the database using the provided key.
 * @property {Function} put - Asynchronously sends data to the server. If provided, calls onSuccess with the result or onError with any errors.
 * @property {Function} set - Asynchronously adds a unique item to an unordered list. If provided, calls onSuccess with the result or onError with any errors.
 * @property {Function} load - Asynchronously fetches data from the server and returns a Promise that resolves with the data.
 * @property {Function} once - Loads data from the node and calls the provided callback function once with the first item in the loaded data.
 */
type Node = {
  get: (key: string) => Node;
  put: (
    data: any,
    onSuccess?: (result: any) => void,
    onError?: (error: Error) => void
  ) => Promise<void>;
  set: (
    target: Node,
    onSuccess?: (result: any) => void,
    onError?: (error: Error) => void
  ) => Promise<void>;
  load: () => Promise<any>;
  once: (callback: (data: any) => void) => void;
};

/**
 * Creates an OrbitDB client with the specified base URL and optional user public key.
 * @param baseUrl - The base URL of the OrbitDB client.
 * @param userPub - Optional. The public key of the user.
 * @returns An object with the `get` method to retrieve data from the OrbitDB client and the `user` method to create a new OrbitDB client for a specific user.
 */
function fabstirDBClient(baseUrl: string, userPub?: string) {
  // Adjust basePath based on whether a userPub is provided
  //baseUrl = "http://localhost:3001";

  const basePath = userPub ? `users/${userPub}` : "";

  const get = (path: string): Node => {
    // Ensure the path is prefixed with the basePath only if it's not already included
    const fullPath = path.startsWith(basePath) ? path : `${basePath}/${path}`;

    type AckError = Error & {
      err?: Error;
    };

    const node: Node = {
      /**
       * Retrieves data from a specified key in the database.
       *
       * @param {string} key - The key from which data should be retrieved.
       * @returns {Promise<any>} Returns a Promise that resolves with the data retrieved from the specified key.
       */
      get: (key: string) => get(`${fullPath}/${key}`),

      /**
       * Asynchronously sends a POST request to the server with the provided data.
       *
       * This function retrieves the user's session data from the session storage,
       * includes the JWT token in the Authorization header, and sends a POST request to the server.
       * If the request is successful, it calls the onSuccess callback. If the request fails, it calls the onError callback.
       *
       * @async
       * @param {any} data - The data to be sent in the request body.
       * @param {function} onSuccess - A callback function to be called if the request is successful.
       * @param {function} onError - A callback function to be called if the request fails.
       * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
       */
      put: async (
        data,
        onSuccess?: (result: any) => void,
        onError?: (ack: AckError) => void
      ) => {
        const session = sessionStorage.getItem("userSession");
        const sessionData = session ? JSON.parse(session) : null;
        const token = sessionData ? sessionData.token : null;

        try {
          const response = await fetch(`${baseUrl}/${fullPath}`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`, // Include the JWT token in the Authorization header
            },
            body: JSON.stringify(data),
          });

          if (!response.ok) {
            const result = await response.text();
            onError?.({
              err: new Error(result),
              name: "NetworkError",
              message: result,
            });
          } else {
            const result = await response.json();
            onSuccess?.({ err: undefined, name: "", message: "" });
          }
        } catch (error) {
          onError?.(
            error instanceof Error
              ? { err: error, name: error.name, message: error.message }
              : {
                  err: new Error("Network error"),
                  name: "NetworkError",
                  message: "Network error occurred",
                }
          );
        }
      },

      /**
       * Asynchronously adds a unique item to an unordered list.
       *
       * This function checks if the item already exists in the list. If it does not, the function adds the item to the list.
       * If the operation is successful, it calls the onSuccess callback. If the operation fails, it calls the onError callback.
       *
       * @async
       * @param {any} item - The item to be added to the list.
       * @param {function} onSuccess - A callback function to be called if the operation is successful.
       * @param {function} onError - A callback function to be called if the operation fails.
       * @returns {Promise<void>} Returns a Promise that resolves when the operation is complete.
       */
      set: async (target, onSuccess, onError) => {
        try {
          const targetString = JSON.stringify(target);
          const hash = crypto
            .createHash("sha256")
            .update(targetString)
            .digest("hex");
          await get(hash).put(target, onSuccess, onError);
        } catch (error) {
          onError?.(
            error instanceof Error ? error : new Error("Network error")
          );
        }
      },

      /**
       * Asynchronously fetches data from the server.
       *
       * This function sends a GET request to the server and returns a Promise that resolves with the response data.
       * If the request fails, the Promise is rejected with an error.
       *
       * @async
       * @returns {Promise<any>} Returns a Promise that resolves with the data fetched from the server.
       * @throws {Error} Will throw an error if the request fails or if the response cannot be parsed.
       */
      load: () => {
        return new Promise((resolve, reject) => {
          fetch(`${baseUrl}/${fullPath}`)
            .then((response) => {
              if (!response.ok) {
                reject(new Error("Failed to fetch data"));
              } else {
                response
                  .json()
                  .then(resolve)
                  .catch(() => {
                    reject(new Error("Failed to parse response"));
                  });
              }
            })
            .catch((error) => {
              reject(
                error instanceof Error ? error : new Error("Network error")
              );
            });
        });
      },

      /**
       * Asynchronously loads data from the node and calls the provided callback function once with the first item in the loaded data.
       *
       * This function sends a load request to the node and returns a Promise that resolves with an array of data.
       * If the array is not empty, the callback is called with the first item in the array. If the array is empty, the callback is called with undefined.
       * If the load request fails, the error is logged to the console.
       *
       * @param {function} callback - A callback function to be called once with the first item in the loaded data.
       */
      once: (callback) => {
        node
          .load()
          .then((array) => {
            callback(array.length > 0 ? array[0] : undefined);
          })
          .catch(console.error);
      },
    };
    return node;
  };

  return {
    get,
    user: function (userPub: string) {
      if (userPub) return fabstirDBClient(baseUrl, userPub);
      else return user;
    },
  };
}

export default fabstirDBClient;
