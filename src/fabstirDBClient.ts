import { dbUrl } from "./GlobalOrbit";
import crypto from "crypto";
import user from "./user";
import { config } from "dotenv";
import { eventEmitter } from "./eventEmitter";
import { FEA } from "./utils/libsodium";
import { encodeUriPathSegments, refreshToken } from "./utils/pathUtils";
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
  const basePath = userPub ? `users/${userPub}` : "";

  let isEncoded = false;

  const get = (path: string): Node => {
    // Ensure the path is prefixed with the basePath only if it's not already included
    const formattedPath = path.endsWith("/") ? path : path ? `${path}/` : "";
    const fullPath = path.startsWith(basePath)
      ? formattedPath
      : `${basePath}/${formattedPath}`;

    // Encode the path only if it is not already encoded
    const encodedFullPath = isEncoded
      ? fullPath
      : encodeUriPathSegments(fullPath);
    isEncoded = true; // Set isEncoded to true after encoding the path

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
      get: (key: string) => {
        const formattedKey = key.endsWith("/") ? key : `${key}/`;
        return get(`${encodedFullPath}${encodeUriPathSegments(formattedKey)}`);
      },

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
      put: async (data, cb) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        const session = sessionStorage.getItem("userSession");
        const sessionData = session ? JSON.parse(session) : null;
        let token = sessionData ? sessionData.accessToken : null;

        const options = data
          ? {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`, // Include the JWT token in the Authorization header
              },
              body: JSON.stringify({ path: encodedFullPath, value: data }), // Send fullPath and data in the request body
            }
          : {
              method: "DELETE",
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`, // Include the JWT token in the Authorization header
              },
              body: JSON.stringify({ path: encodedFullPath }), // Send fullPath in the request body for DELETE
            };

        try {
          const url = `${baseUrl}/update-data`; // Use a fixed endpoint for both POST and DELETE

          let response = await fetch(url, options); // Use a fixed endpoint

          if (response.status === 401) {
            // Access token expired, try to refresh it
            try {
              token = await refreshToken(dbUrl);
              options.headers.Authorization = `Bearer ${token}`;
              response = await fetch(url, options);
            } catch (error) {
              throw new Error("Failed to refresh token");
            }
          }

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
          const result = await get(encodedFullPath).get(hash).put(target); // Navigate the full path and store the data
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
       * This function sends a POST request to the server and returns a Promise that resolves with the response data.
       * If the request fails, the Promise is rejected with an error.
       *
       * @async
       * @returns {Promise<any>} Returns a Promise that resolves with the data fetched from the server.
       * @throws {Error} Will throw an error if the request fails or if the response cannot be parsed.
       */
      load: (cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        if (!encodedFullPath) {
          cb(undefined);
          return Promise.resolve(undefined);
        }

        return new Promise((resolve, reject) => {
          fetch(`${baseUrl}/fetch-data`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ path: encodedFullPath }),
          })
            .then((response) => {
              if (!response.ok) {
                cb(undefined);
                resolve(undefined);
              } else {
                response
                  .json()
                  .then((data) => {
                    // Transform the data into the desired structure
                    const transformedData = data.reduce(
                      (acc: any, item: any) => {
                        const pathParts = item._id
                          .split("/")
                          .filter((part: string) => part !== "");
                        const key = pathParts[pathParts.length - 1];

                        // Preserve the data as is, without parsing
                        acc[decodeURIComponent(key)] = item.data;

                        return acc;
                      },
                      {}
                    );

                    if (
                      !transformedData ||
                      Object.keys(transformedData).length === 0
                    ) {
                      cb(undefined, undefined);
                      resolve(undefined);
                    } else {
                      cb(undefined, transformedData);
                      resolve(transformedData);
                    }
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
       * Otherwise, it makes an HTTP POST request to the URL, and upon success, it parses the response as JSON and invokes the callback with the parsed data.
       * In case of any error (network error, response not OK, or JSON parsing error), the callback is invoked with an error.
       *
       * @param {Function} cb - Callback function with signature `(error, data) => void`.
       * @returns {Object} An object with a `once` method that takes a callback to be executed once with the fetched data.
       */
      map: (cb: any) => {
        cb = cb || (() => {}); // If cb is not provided, set it to a no-op function

        let promise;
        if (!encodedFullPath) {
          cb(undefined);
          promise = Promise.resolve(undefined);
        } else {
          promise = new Promise((resolve, reject) => {
            fetch(`${baseUrl}/fetch-data`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ path: encodedFullPath }), // Send fullPath in the request body
            })
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
      path: () => encodedFullPath,

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
          if (encodedFullPath === "") {
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

          if (encodedFullPath && encodedFullPath.startsWith("~%40")) {
            let alias = decodeURIComponent(encodedFullPath.substring(4));
            alias = alias.endsWith("/") ? alias.slice(0, -1) : alias;
            const exists = await user.exists(alias);
            cb(exists ? {} : undefined);
            return { err: undefined, data: exists ? {} : undefined };
          } else {
            const result = await node.load();
            if (
              result &&
              typeof result === "object" &&
              !Array.isArray(result)
            ) {
              if (Object.keys(result).length === 0) {
                cb(undefined);
                return {
                  err: undefined,
                  data: undefined,
                };
              } else {
                const segments = path.split("/");
                const lastSegment =
                  segments[segments.length - 1] ||
                  segments[segments.length - 2];

                cb(result[decodeURIComponent(lastSegment)]);
                return {
                  err: undefined,
                  data: result[decodeURIComponent(lastSegment)],
                };
              }
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
    return await FEA.secret(theirPublicKey, myKeyPair);
  };

  return {
    get: (path: string) => {
      isEncoded = false; // Reset isEncoded to false at the entry point
      return get(path);
    },
    user: (userPub?: string) => {
      isEncoded = false; // Reset isEncoded to false at the entry point
      return userPub ? fabstirDBClient(baseUrl, userPub) : user;
    },
    on: (event: string, listener: (data: any) => void) => {
      eventEmitter.on(event, listener);
    },
    secret,
  };
}

export default fabstirDBClient;
