const SELF_RAW_PREFIX =
  "https://raw.githubusercontent.com/NikoCera/rule/main/";

function noStoreResponse(body, status, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

function readBearerToken(request) {
  const authorization = request.headers.get("Authorization");
  const bearerMatch = authorization?.match(/^Bearer\s+(.+)$/i);
  return bearerMatch?.[1]?.trim();
}

function parseRequestTarget(request, url) {
  const pathMatch = url.pathname.match(
    /^\/auth\/([^/]+)(\/(?:Surge|Clash)\/.+)$/,
  );

  if (pathMatch) {
    let providedToken;
    try {
      providedToken = decodeURIComponent(pathMatch[1]);
    } catch {
      return null;
    }

    return {
      assetPath: pathMatch[2],
      providedToken,
    };
  }

  if (!isPublishedPath(url.pathname)) {
    return null;
  }

  return {
    assetPath: url.pathname,
    providedToken: readBearerToken(request),
  };
}

async function secretsMatch(provided, expected) {
  if (!provided || !expected) {
    return false;
  }

  const encoder = new TextEncoder();
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);

  return crypto.subtle.timingSafeEqual(providedHash, expectedHash);
}

function isPublishedPath(pathname) {
  return pathname.startsWith("/Surge/") || pathname.startsWith("/Clash/");
}

function isModulePath(pathname) {
  return pathname.endsWith(".sgmodule") || pathname.endsWith(".module");
}

function authenticatedUrl(origin, path, token) {
  const escapedToken = encodeURIComponent(token);
  return `${origin}/auth/${escapedToken}/${path.replace(/^\/+/, "")}`;
}

function rewriteSelfReferences(text, origin, token) {
  const selfUrlPattern = new RegExp(
    `${SELF_RAW_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}([^\\s,\"]+)`,
    "g",
  );

  return text.replace(
    selfUrlPattern,
    (_match, path) => authenticatedUrl(origin, path, token),
  );
}

export default {
  async fetch(request, env) {
    if (!["GET", "HEAD"].includes(request.method)) {
      return noStoreResponse("Method Not Allowed", 405, { Allow: "GET, HEAD" });
    }

    const url = new URL(request.url);
    const requestTarget = parseRequestTarget(request, url);

    if (!requestTarget) {
      return noStoreResponse("Not found", 404);
    }

    if (!env.DOWNLOAD_TOKEN) {
      console.error(JSON.stringify({
        message: "DOWNLOAD_TOKEN is not configured",
        path: url.pathname,
      }));
      return noStoreResponse("Service Unavailable", 503);
    }

    const { assetPath, providedToken } = requestTarget;
    if (!(await secretsMatch(providedToken, env.DOWNLOAD_TOKEN))) {
      return noStoreResponse("Unauthorized", 401, {
        "WWW-Authenticate": 'Bearer realm="rule"',
      });
    }

    const assetUrl = new URL(url);
    assetUrl.pathname = assetPath;
    assetUrl.search = "";
    const assetRequest = new Request(assetUrl, { method: request.method });
    const assetResponse = await env.ASSETS.fetch(assetRequest);
    const headers = new Headers(assetResponse.headers);

    headers.set("Referrer-Policy", "no-referrer");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Vary", "Authorization");

    if (request.method === "GET" && assetResponse.ok && isModulePath(assetPath)) {
      const moduleText = await assetResponse.text();
      const rewritten = rewriteSelfReferences(moduleText, url.origin, providedToken);
      headers.set("Cache-Control", "no-store");
      headers.delete("Content-Length");
      headers.delete("ETag");
      return new Response(rewritten, {
        status: assetResponse.status,
        statusText: assetResponse.statusText,
        headers,
      });
    }

    headers.set("Cache-Control", "private, max-age=300, must-revalidate");
    return new Response(request.method === "HEAD" ? null : assetResponse.body, {
      status: assetResponse.status,
      statusText: assetResponse.statusText,
      headers,
    });
  },
};
