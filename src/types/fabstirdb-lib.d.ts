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
  path: () => string;
  once: (callback: (data: any) => void) => void;
};

declare module "fabstirdb-lib" {
  export default function createDBClient(
    baseUrl: string,
    userPub?: string
  ): {
    get: (path: string) => Node;
    user: (userPub?: string) => any; // replace 'any' with the actual type if known
    on: (event: string, listener: (data: any) => void) => void;
  };
}
