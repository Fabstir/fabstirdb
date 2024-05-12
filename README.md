# FabstirDB

## Introduction

FabstirDB is a TypeScript package that serves as an interface API for storing data in a graph database using OrbitDB, which is powered by IPFS (InterPlanetary File System). Based off of GUN API, this package provides a scalable solution for developers who want to leverage the benefits of decentralized storage and graph databases.
Future expansion to include support for alternative infrastructure of S5 and Sia storage.

## Summary

This document provides an overview of the API, interfaces, functions, and modules used in the project for a graph database interface similar to GUN API that uses OrbitDb as its backend.

#### `user` Object

The `user` object is a key part of the API, providing methods for user management, including creation, authentication, data retrieval, session management, and access control.

#### Interface: `Node`

The `Node` interface represents a node in the database, providing methods for data retrieval, sending data to the server, adding unique items to a list, fetching data, and performing a one-time operation.

#### Function: `createDBClient`

This function creates a database client with a specified base URL and an optional user public key. It returns an object with methods for data retrieval.

#### Module: `GlobalOrbit`

This module exposes a global OrbitDB instance that implements the `user` graph and `Node` database interfaces. It includes a `dbClient` instance and functions to update and reset this client.

## Example

This code block demonstrates user creation, authentication, granting write access, and data manipulation in a database using dbClient.
Only the logged in user can write to their user graph unless that user grants access to other users; in this example `addWriteAcess` is used to specify that another user can have write permission to a subgraph area "test".

```
user.create("username1", "mypassword1")
const userPub1 = user.is.pub
user.logout();

user.create("username2", "mypassword2")
const userPub2 = user.is.pub

await user.addWriteAcess(`users/${userPub1}/test`, userPub1);
user.logout();

user.auth("username1", "mypassword1")
await dbClient
  .user(userPub2)
  .get("test")
  .get("1")
  .put({message: "hello world"});
user.logout();

user.auth("username2", "mypassword2")
const dataEntries = await dbClient.get('test').load();
const data = dataEntries[0];
user.logout();

user.auth("username1", "mypassword1")
const dataAgain = await dbClient.user(userPub2).get('test').get('1').once();

console.log(data.message); // "hello world"
console.log(dataAgain.message); // "hello world"
```

## API Documentation

## `user` Object

`user` is an object that provides methods for user management. It includes methods for creating and authenticating users, retrieving user data, checking user existence, adding write access, and managing user sessions.

#### Properties

- `create` _(Function)_: Asynchronously creates a new user with the given alias and password.

  - **Parameters**:

    - `alias` _(string)_: The alias of the new user.
    - `pass` _(string)_: The password of the new user.
    - `cb` _(function)_: A callback function to be called with the result of the operation.

  - **Throws**: Will throw an error if the registration fails.

  - **Returns**: A Promise that resolves when the operation is complete.

- `auth` _(Function)_: Asynchronously authenticates a user with the given alias and password.

  - **Parameters**:

    - `alias` _(string)_: The alias of the user.
    - `pass` _(string)_: The password of the user.
    - `cb` _(function)_: A callback function to be called with the result of the operation.

  - **Throws**: Will throw an error if the authentication fails.

  - **Returns**: A Promise that resolves when the operation is complete.

- `get` _(Function)_: Retrieves data from a specified path for the current user session.

  - **Parameters**:

    - `path` _(string)_: The path from which data should be retrieved.

  - **Throws**: Will throw an error if no user session is found.

  - **Returns**: The data retrieved from the specified path.

- `logout` _(Function)_: Logs out the current user by removing their session data from the session storage.

- `recall` _(Function)_: Retrieves the user object from the session storage.

  - **Returns**: The user object if a session exists, or null if no session is found.

- `session` _(Function)_: Retrieves the user's session data from the session storage.

  - **Returns**: The user's session data if a session exists, or null if no session is found.

- `pair` _(Function)_: Retrieves the user's key pair from the current session.

  - **Returns**: The user's key pair if a session exists, or null if no session is found.

- `exists` _(Function)_: Asynchronously checks if a user's alias exists. Equivalent to `.get(`~@${alias}`).once...` syntax, except returns a boolean rather than an object or null.

  - **Parameters**:

    - `alias` _(string)_: The username to check for existence.

  - **Returns**: A Promise that resolves to true if the user exists, otherwise false.

- `addWriteAccess` _(Function)_: Asynchronously adds write access to a specified path for a user with a given public key or '\*' to grant write access to all users.

  - **Parameters**:

    - `path` _(string)_: The path to which write access should be added.
    - `publicKey` _(string)_: The public key of the user to whom write access should be granted.

  - **Throws**: Will throw an error if the HTTP request status is not OK.

  - **Returns**: A Promise that resolves when the operation is complete.

- `is` _(Object)_: An object with a getter for the public key of the current user session.

  - **Properties**:

    - `pub` _(Getter)_: Returns the public key of the current user session.

      - **Throws**: Will throw an error if no active session is found.

    - `alias` _(Getter)_: Returns the user's alias of the current user session.

      - **Throws**: Will throw an error if no active session is found.

## Interface: `Node`

Interface for a Node object that represents a node in the database. It provides methods for getting, putting, setting, loading data, and performing a one-time operation.

#### Properties

- `get` _(Function)_: Retrieves a Node object from the database using the provided key.

  - **Parameters**:

    - `key` _(string)_: The key from which data should be retrieved.

  - **Returns**: A Promise that resolves with the data retrieved from the specified key.

- `put` _(Function)_: Asynchronously sends data to the server. If provided, calls onSuccess with the result or onError with any errors. If the path includes a hash,

  - the data is saved immutabiy under a content-addressed hash after verifying that the provided hash matches the calculated hash of the data.
  - If the path does not include a hash, the data is saved directly under the path.

  * **Parameters**:

    - `data` _(any)_: The data to be sent in the request body.
    - `onSuccess` _(function)_: A callback function to be called if the request is successful.
    - `onError` _(function)_: A callback function to be called if the request fails.

  * **Returns**: A Promise that resolves when the operation is complete.

- `set` _(Function)_: Asynchronously adds a unique item to an unordered list. If provided, calls onSuccess with the result or onError with any errors.

  - **Parameters**:

    - `target` _(Node)_: The item to be added to the list.
    - `onSuccess` _(function)_: A callback function to be called if the operation is successful.
    - `onError` _(function)_: A callback function to be called if the operation fails.

  - **Returns**: A Promise that resolves when the operation is complete.

- `load` _(Function)_: Asynchronously fetches data from the server returning an array of items.

  - **Returns**: A Promise that resolves with the data fetched from the server.

- `path` _(Function)_: Retrieves the full path of any node at any depth.

  - **Returns**: Returns the full path of the node.

- `once` _(Function)_: Asynchronously loads data from the node and calls the provided callback function once with the first item in the loaded data so ensure that only one item is expected.

  - **Parameters**:
    - `callback` _(function)_: A callback function to be called once with the first item in the loaded data.
  - **Returns**: A Promise that resolves with the data for a single item fetched from the server.

---

## Function: `createDBClient`

Creates a database client with the specified base URL for optional user public key.

#### Parameters

- `baseUrl` _(string)_: The base URL of the OrbitDB client.
- `userPub` _(string)_: Optional. The public key of the user.

#### Returns

An object with the `get` method to retrieve data with write access from the database client for the current logged in user and the `user` to retrieve data from a specific user. When `userPub` is not specified, the current database is closed.

---

## Module: `GlobalOrbit`

Exposes a global OrbitDB instance that implements `user` graph and `Node` database interfaces to store and retrieve data from IPFS.

#### Imports

` _(Function)_: Import` from "./utils/createDBClient".

#### Variables

- `dbClient` _(Object)_: Instance of the OrbitDB client, created using the backend URL.

#### Functions

- `updateDbClient` _(Function)_: Updates the OrbitDB client with a new instance created using the provided user public key.

  - **Parameters**:
    - `userPubKey` _(string)_: The user's public key.

- `resetDbClient` _(Function)_: Resets the OrbitDB client with a new instance created using the backend URL.

#### Exports

- `dbClient` _(Object)_: Exports `dbClient`.

## Installation and Setup

```
yarn install
yarn build
```

You need a running instance of FabstirDB-Backend and set `FABSTIRDB_BACKEND_URL` environment variable to its url.
Then in your project...

```
import { createDBClient } from 'fabstirdb-lib';

const dbClient = createDBClient(
  process.env.NEXT_PUBLIC_FABSTIRDB_BACKEND_URL,
);
const user = dbClient.user();

user.create("username1", "mypassword1")
...

```
