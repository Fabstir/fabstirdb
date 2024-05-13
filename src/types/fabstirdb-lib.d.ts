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
