/**
 * CORS Proxy for Cloudflare Workers (workers.dev)
 *
 * Usage:
 *   https://YOUR-WORKER.workers.dev/?url=https://api.example.com/data
 *   https://YOUR-WORKER.workers.dev/https://api.example.com/data
 *
 * Special request headers (all optional):
 *   x-cors-method   : override the HTTP method sent upstream (e.g. PUT)
 *   x-cors-headers  : JSON object of headers to send upstream
 *                     e.g. {"Authorization":"Bearer abc","X-Foo":"bar"}
 *   x-cors-body     : custom request body string to send upstream
 *
 * Optional configuration (works with zero config; override via
 * Worker Settings -> Variables, comma-separated):
 *   ALLOWED_ORIGINS : e.g. "https://myapp.com,https://staging.myapp.com"
 *                     (empty = allow every origin)
 *   BLOCKED_URLS    : e.g. "evil.com,https://api.bad.com/secret"
 *                     (matches hostname or URL prefix)
 */

// ---- Defaults (used when no env variables are set) ----
const DEFAULT_ALLOWED_ORIGINS = []; // [] = allow all
const DEFAULT_BLOCKED_URLS = [];    // e.g. ["badsite.com"]

// Request headers never forwarded upstream
const STRIP_REQUEST_HEADERS = [
  "host", "origin", "referer", "connection", "content-length",
  "x-cors-method", "x-cors-headers", "x-cors-body",
  "x-forwarded-for", "x-forwarded-proto", "x-real-ip",
];

// Response headers never passed back to the browser
const STRIP_RESPONSE_HEADERS = [
  "set-cookie", "set-cookie2", "content-security-policy",
  "content-security-policy-report-only", "x-frame-options",
];

const parseList = (value, fallback) =>
  value ? value.split(",").map((s) => s.trim()).filter(Boolean) : fallback;

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With, Accept, x-cors-headers, x-cors-body, x-cors-method",
    "Access-Control-Expose-Headers": "*, x-cors-cf-info, x-cors-final-url",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(origin) },
  });
}

function getTargetUrl(requestUrl) {
  const u = new URL(requestUrl);
  let target = u.searchParams.get("url");

  if (!target) {
    // Path style: /https://example.com/path?x=1
    const raw = u.pathname.slice(1) + u.search;
    if (/^https?:\/?\/?/i.test(raw)) {
      target = raw.replace(/^(https?):\/+/i, "$1://");
    }
  }
  return target;
}

function isPrivateHost(hostname) {
  const h = hostname.toLowerCase();
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".internal") ||
    h === "[::1]" ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^169\.254\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /^0\./.test(h)
  );
}

function isBlocked(targetUrl, blocklist) {
  const host = targetUrl.hostname.toLowerCase();
  const full = targetUrl.href.toLowerCase();
  return blocklist.some((entry) => {
    const e = entry.toLowerCase();
    return host === e || host.endsWith("." + e) || full.startsWith(e);
  });
}

function cfInfo(request) {
  const cf = request.cf || {};
  return {
    ip: request.headers.get("cf-connecting-ip") || null,
    country: cf.country || request.headers.get("cf-ipcountry") || null,
    city: cf.city || null,
    region: cf.region || null,
    continent: cf.continent || null,
    timezone: cf.timezone || null,
    asn: cf.asn || null,
    datacenter: cf.colo || null,
  };
}

// ---- HLS / streaming helpers ----
const PLAYLIST_RE = /\.m3u8?$/i;
const SEGMENT_RE = /\.(ts|m4s|aac|mp4|m4a|m4v|vtt|webvtt|key)$/i;

// Rewrites every URL inside an .m3u8 so segments, keys and sub-playlists
// also go through the proxy (fixes CORS / mixed-content / relative paths).
function rewritePlaylist(text, baseUrl, proxyOrigin) {
  const toProxy = (u) => {
    try {
      const abs = new URL(u, baseUrl).href;
      return `${proxyOrigin}/?url=${encodeURIComponent(abs)}`;
    } catch {
      return u;
    }
  };
  return text
    .split(/\r?\n/)
    .map((line) => {
      const t = line.trim();
      if (!t) return line;
      if (t.startsWith("#")) {
        return line.replace(/URI="([^"]+)"/g, (_, u) => `URI="${toProxy(u)}"`);
      }
      return toProxy(t);
    })
    .join("\n");
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin");
    const allowedOrigins = parseList(env?.ALLOWED_ORIGINS, DEFAULT_ALLOWED_ORIGINS);
    const blockedUrls = parseList(env?.BLOCKED_URLS, DEFAULT_BLOCKED_URLS);

    // ---- Origin whitelisting ----
    if (allowedOrigins.length > 0 && (!origin || !allowedOrigins.includes(origin))) {
      return json({ error: "Origin not allowed", origin }, 403, null);
    }

    // ---- Preflight (OPTIONS) ----
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    const incoming = new URL(request.url);
    const targetRaw = getTargetUrl(request.url);

    // ---- Info / help page ----
    if (!targetRaw) {
      return json(
        {
          name: "CORS Proxy (Cloudflare Workers)",
          usage: [
            `${incoming.origin}/?url=https://api.example.com/data`,
            `${incoming.origin}/https://api.example.com/data`,
          ],
          headers: {
            "x-cors-method": "Override HTTP method",
            "x-cors-headers": "JSON of headers to send upstream",
            "x-cors-body": "Custom request body",
          },
          cloudflare: cfInfo(request),
        },
        200,
        origin
      );
    }

    // ---- Validate target ----
    let target;
    try {
      target = new URL(targetRaw);
    } catch {
      return json({ error: "Invalid target URL", url: targetRaw }, 400, origin);
    }

    if (!["http:", "https:"].includes(target.protocol)) {
      return json({ error: "Only http and https URLs are supported" }, 400, origin);
    }
    if (target.hostname === incoming.hostname) {
      return json({ error: "Proxying to itself is not allowed" }, 400, origin);
    }
    if (isPrivateHost(target.hostname)) {
      return json({ error: "Private/local addresses are not allowed" }, 403, origin);
    }

    // ---- URL blacklisting ----
    if (isBlocked(target, blockedUrls)) {
      return json({ error: "This URL is blocked", url: target.href }, 403, origin);
    }

    // ---- Method override ----
    const method = (request.headers.get("x-cors-method") || request.method).toUpperCase();

    // ---- Build upstream headers ----
    const upstreamHeaders = new Headers();
    for (const [key, value] of request.headers) {
      const k = key.toLowerCase();
      if (STRIP_REQUEST_HEADERS.includes(k) || k.startsWith("cf-") || k.startsWith("x-forwarded-")) {
        continue;
      }
      upstreamHeaders.set(key, value);
    }

    // ---- Custom headers via x-cors-headers ----
    const customHeaders = request.headers.get("x-cors-headers");
    if (customHeaders) {
      try {
        const parsed = JSON.parse(customHeaders);
        for (const [k, v] of Object.entries(parsed)) {
          upstreamHeaders.set(k, String(v));
        }
      } catch {
        return json({ error: "x-cors-headers must be valid JSON" }, 400, origin);
      }
    }

    // ---- Body (custom via x-cors-body, otherwise pass-through) ----
    let body;
    if (!["GET", "HEAD"].includes(method)) {
      const customBody = request.headers.get("x-cors-body");
      body = customBody !== null ? customBody : request.body;
    }

    // ---- Forward the request ----
    let upstream;
    try {
      // Edge caching: playlists 2s (keeps live streams fresh), segments 60s.
      // Big speed-up when several viewers watch the same stream.
      const cacheable =
        method === "GET" && !customHeaders && !request.headers.get("authorization");
      let cf;
      if (cacheable && PLAYLIST_RE.test(target.pathname)) {
        cf = { cacheEverything: true, cacheTtl: 2 };
      } else if (cacheable && SEGMENT_RE.test(target.pathname)) {
        cf = { cacheEverything: true, cacheTtl: 60 };
      }

      upstream = await fetch(target.href, {
        method,
        headers: upstreamHeaders,
        body,
        redirect: "follow",
        ...(cf ? { cf } : {}),
      });
    } catch (err) {
      return json({ error: "Upstream request failed", message: String(err) }, 502, origin);
    }

    // ---- Build response with CORS + Cloudflare info ----
    const responseHeaders = new Headers();
    for (const [key, value] of upstream.headers) {
      if (!STRIP_RESPONSE_HEADERS.includes(key.toLowerCase())) {
        responseHeaders.set(key, value);
      }
    }
    for (const [k, v] of Object.entries(corsHeaders(origin))) {
      responseHeaders.set(k, v);
    }
    responseHeaders.set("x-cors-cf-info", JSON.stringify(cfInfo(request)));
    responseHeaders.set("x-cors-final-url", upstream.url || target.href);

    // ---- HLS playlist: rewrite inner URLs so they also use the proxy ----
    const ct = (upstream.headers.get("content-type") || "").toLowerCase();
    const isPlaylist =
      upstream.ok &&
      method !== "HEAD" &&
      (ct.includes("mpegurl") || PLAYLIST_RE.test(target.pathname));
    if (isPlaylist) {
      const text = await upstream.text();
      const rewritten = text.trimStart().startsWith("#EXTM3U")
        ? rewritePlaylist(text, upstream.url || target.href, incoming.origin)
        : text;
      responseHeaders.delete("content-length");
      responseHeaders.delete("content-encoding");
      responseHeaders.set("content-type", "application/vnd.apple.mpegurl");
      responseHeaders.set("cache-control", "public, max-age=2");
      return new Response(rewritten, {
        status: upstream.status,
        headers: responseHeaders,
      });
    }

    // Media segments: let browsers/edge reuse them
    if (upstream.ok && SEGMENT_RE.test(target.pathname) && !responseHeaders.has("cache-control")) {
      responseHeaders.set("cache-control", "public, max-age=60");
    }

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  },
};
