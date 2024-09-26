// pathUtils.ts

export function encodeUriPathSegments(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}
