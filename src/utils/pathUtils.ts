// pathUtils.ts

export function encodeUriPathSegments(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

export const refreshToken = async (dbUrl: string) => {
  const userSessionStr = sessionStorage.getItem("userSession");
  const userSession = userSessionStr ? JSON.parse(userSessionStr) : null;
  if (!userSession || !userSession.refreshToken) {
    throw new Error("No refresh token available");
  }

  const response = await fetch(`${dbUrl}/refresh-token`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken: userSession.refreshToken }),
  });

  if (!response.ok) {
    throw new Error("Failed to refresh token");
  }

  const newTokens = await response.json();
  userSession.accessToken = newTokens.accessToken;
  userSession.refreshToken = newTokens.refreshToken;
  sessionStorage.setItem("userSession", JSON.stringify(userSession));
  return newTokens.accessToken;
};
