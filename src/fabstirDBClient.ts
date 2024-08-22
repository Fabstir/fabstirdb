import crypto from "crypto";
import user from "./user";
import { config } from "dotenv";
import { dbUrl } from "./GlobalOrbit";
import { eventEmitter } from "./eventEmitter";
import { libsodium } from "./utils/libsodium";
config();

/**
 * Interface for a Node object in OrbitDB.
 *
 * A Node object represents a node in the OrbitDB database. It provides methods for getting, putting, setting, loading data, performing a one-time operation, and mapping over data.
 *
 * @interface
 * @property {Function} get - Retrieves a Node object from the database using the provided key.
 * @property {Function} put - Asynchronously sends data to the server. If provided, calls onSuccess with the result or onError with any errors.
 * @property {Function} set - Asynchronously adds a unique item to an unordered list. If provided, calls onSuccess with the result or onError with any errors.
 * @property {Function} load - Asynchronously fetches data from the server and returns a Promise that resolves with the data.
 * @property {Function} once - Loads data from the node and calls the provided callback function once with the first item in the loaded data.
 * @property {Function} map - Transforms the data by applying a function to each item and returns an object with a `once` method. The `once` method accepts a callback function and executes it with the transformed data and a key.
 */
type Node = {
  get: (key: string) => Node;
  put: (
    data: any,
    callback?: (errorObject: { err: any; name: string }) => void
  ) => Promise<{ err: any; name: string }>;
  set: (
    target: any,
    callback?: (errorObject: { err: any }) => void
  ) => Promise<{ err: any }>;
  load: (
    callback?: (error: any, data?: any[]) => void
  ) => Promise<any[] | undefined>;
  path: () => string;
  once: (
    callback?: (error: any, data?: any) => void
  ) => Promise<{ err: any; data?: any }>;
  map: (callback?: (error: any, data?: any[]) => void) => {
    once: (callback: (data: any, key: any) => void) => void;
  };
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
      get: (key: string) => get(`${fullPath}/${encodeURIComponent(key)}`),

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
      put: async (data: any, cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        const session = sessionStorage.getItem("userSession");
        const sessionData = session ? JSON.parse(session) : null;
        const token = sessionData ? sessionData.token : null;

        const options = data
          ? {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`, // Include the JWT token in the Authorization header
              },
              body: JSON.stringify({ value: data }),
            }
          : {
              method: "DELETE",
              headers: {
                "Content-Type": "", // Set to an empty string
                Authorization: `Bearer ${token}`, // Include the JWT token in the Authorization header
              },
            };

        try {
          const response = await fetch(
            `${baseUrl}/${encodeURIComponent(fullPath)}`,
            options
          );
          if (!response.ok) {
            const result = await response.text();
            const errorObject = { err: result, name: "NetworkError" };
            cb(errorObject);
            return errorObject;
          } else {
            const result = await response.json();
            const successObject = { err: undefined, name: "" };
            cb(successObject);
            return successObject;
          }
        } catch (error) {
          const errorObject =
            error instanceof Error
              ? { err: error.message, name: error.name }
              : {
                  err: "Network error",
                  name: "NetworkError",
                };
          cb(errorObject);
          return errorObject;
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
      set: async (target, cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        try {
          const targetString = JSON.stringify(target);
          const hash = crypto
            .createHash("sha256")
            .update(targetString)
            .digest("hex");
          const result = await get(fullPath).get(hash).put(target); // Navigate the full path and store the data
          if (result.err) {
            cb({ err: result });
            return { err: result };
          } else {
            cb({ err: undefined });
            return { err: undefined };
          }
        } catch (error) {
          const errorObject = {
            err: error instanceof Error ? error.message : "Network error",
          };
          cb(errorObject);
          return errorObject;
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
      load: (cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        if (!fullPath) {
          cb(undefined);
          return Promise.resolve(undefined);
        }

        return new Promise((resolve, reject) => {
          fetch(`${baseUrl}/${encodeURIComponent(fullPath)}`)
            .then((response) => {
              if (!response.ok) {
                cb(undefined);
                resolve(undefined);
              } else {
                response
                  .json()
                  .then((data) => {
                    // Transform the array of objects into an array of `data` property values
                    const transformedData = data.map((item: any) => item.data);
                    cb(undefined, transformedData);
                    resolve(transformedData);
                  })
                  .catch((error) => {
                    cb(error);
                    reject(new Error("Failed to parse response"));
                  });
              }
            })
            .catch((error) => {
              const errorObject =
                error instanceof Error ? error : new Error("Network error");
              cb(errorObject);
              reject(errorObject);
            });
        });
      },

      /**
       * Executes a callback function with data fetched from a specified path.
       *
       * This function fetches data from a URL constructed with `baseUrl` and `fullPath`.
       * If `fullPath` is not provided, the callback is invoked with `undefined` immediately.
       * Otherwise, it makes an HTTP GET request to the URL, and upon success, it parses the response as JSON and invokes the callback with the parsed data.
       * In case of any error (network error, response not OK, or JSON parsing error), the callback is invoked with an error.
       *
       * @param {Function} cb - Callback function with signature `(error, data) => void`.
       * @returns {Object} An object with a `once` method that takes a callback to be executed once with the fetched data.
       */
      map: (cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        let promise;
        if (!fullPath) {
          cb(undefined);
          promise = Promise.resolve(undefined);
        } else {
          promise = new Promise((resolve, reject) => {
            fetch(`${baseUrl}/${encodeURIComponent(fullPath)}`)
              .then((response) => {
                if (!response.ok) {
                  cb(undefined);
                  resolve(undefined);
                } else {
                  response
                    .json()
                    .then((data) => {
                      // Transform the array of objects into an array of `data` property values
                      cb(undefined, data);
                      resolve(data);
                    })
                    .catch((error) => {
                      cb(error);
                      reject(new Error("Failed to parse response"));
                    });
                }
              })
              .catch((error) => {
                const errorObject =
                  error instanceof Error ? error : new Error("Network error");
                cb(errorObject);
                reject(errorObject);
              });
          });
        }

        return {
          once: (onceCb: (data: any, key: string | undefined) => void) => {
            promise.then((dataArray: unknown) => {
              if (Array.isArray(dataArray) && dataArray.length) {
                dataArray.forEach((item) => {
                  onceCb(item.data, item._id);
                });
              } else {
                onceCb(undefined, undefined);
              }
            });
          },
        };
      },

      /**
       * Returns the full path.
       *
       * @returns {string} The full path.
       */
      path: () => fullPath,

      /**
       * Asynchronously loads data from the node and calls the provided callback function once with the first item in the loaded data.
       *
       * This function sends a load request to the node and returns a Promise that resolves with an array of data.
       * If the array is not empty, the callback is called with the first item in the array. If the array is empty, the callback is called with undefined.
       * If the load request fails, the error is logged to the console.
       *
       * @param {function} cb - A callback function to be called once with the first item in the loaded data.
       */
      once: async (cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        try {
          if (fullPath === "") {
            cb(undefined);
            return { err: undefined };
          }

          if (path === "alias" || path.endsWith("/alias")) {
            const session = sessionStorage.getItem("userSession");
            if (session) {
              const sessionObj = JSON.parse(session);
              cb(sessionObj.alias);
              return { err: undefined, data: sessionObj.alias };
            } else {
              cb(undefined);
              return { err: undefined };
            }
          }

          if (fullPath && fullPath.startsWith("~@")) {
            const alias = fullPath.substring(4);
            const exists = await user.exists(alias);
            cb(exists ? {} : undefined);
            return { err: undefined, data: exists ? {} : undefined };
          } else {
            const array = await node.load();
            if (array) {
              cb(array.length > 0 ? array[0] : undefined);
              return {
                err: undefined,
                data: array.length > 0 ? array[0] : undefined,
              };
            } else {
              cb(undefined);
              return {
                err: undefined,
                data: undefined,
              };
            }
          }
        } catch (error) {
          const errorObject = {
            err: error instanceof Error ? error.message : "Network error",
          };
          cb(errorObject);
          return errorObject;
        }
      },
    };
    return node;
  };

  const secret = async (
    theirPublicKey: string,
    myKeyPair: {
      pub: string;
      priv: string;
      epub: string;
      epriv: string;
    }
  ): Promise<string> => {
    return await libsodium.secret(theirPublicKey, myKeyPair);
  };

  return {
    get,
    user: (userPub?: string) =>
      userPub ? fabstirDBClient(baseUrl, userPub) : user,
    on: (event: string, listener: (data: any) => void) => {
      eventEmitter.on(event, listener);
    },
    secret,
  };
}

export default fabstirDBClient;
