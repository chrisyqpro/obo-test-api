const { app } = require("@azure/functions");

function base64UrlDecode(input) {
  input = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = input.length % 4;
  if (pad) input += "=".repeat(4 - pad);
  return Buffer.from(input, "base64").toString("utf8");
}

function safePickClaims(claims) {
  return {
    aud: claims.aud,
    scp: claims.scp,
    roles: claims.roles,
    tid: claims.tid,
    oid: claims.oid,
    sub: claims.sub,
    upn: claims.upn,
    preferred_username: claims.preferred_username,
    name: claims.name,

    appid: claims.appid,
    azp: claims.azp,
    azpacr: claims.azpacr,
    appidacr: claims.appidacr,
    idtyp: claims.idtyp,

    iss: claims.iss,
    iat: claims.iat,
    nbf: claims.nbf,
    exp: claims.exp
  };
}

app.http("whoami", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  handler: async (request, context) => {
    const auth = request.headers.get("authorization") || "";

    if (!auth.toLowerCase().startsWith("bearer ")) {
      return {
        status: 401,
        jsonBody: {
          error: "Missing Authorization: Bearer token"
        }
      };
    }

    const token = auth.substring("bearer ".length);

    let header;
    let claims;

    try {
      const parts = token.split(".");
      if (parts.length !== 3) {
        throw new Error("JWT must have 3 parts");
      }

      header = JSON.parse(base64UrlDecode(parts[0]));
      claims = JSON.parse(base64UrlDecode(parts[1]));
    } catch (err) {
      return {
        status: 400,
        jsonBody: {
          error: `Invalid JWT format: ${err.message}`
        }
      };
    }

    // PoC only. Do not keep this in production.
    context.warn("=== RAW TOKEN - POC DEBUG ONLY ===");
    context.warn(token);

    context.warn("=== TOKEN HEADER ===");
    context.warn(JSON.stringify(header, null, 2));

    context.warn("=== TOKEN CLAIMS ===");
    context.warn(JSON.stringify(claims, null, 2));

    const now = Math.floor(Date.now() / 1000);
    const returnFullToken = request.query.get("return_token") === "1";

    const response = {
      token_received: true,
      ...safePickClaims(claims),
      now,
      seconds_until_expiry: claims.exp ? claims.exp - now : null,
      token_prefix: token.substring(0, 30),
      token_suffix: token.substring(token.length - 20)
    };

    // Only for one-shot debugging. Remove after you prove the flow.
    if (returnFullToken) {
      response.raw_token_for_debug = token;
    }

    return {
      status: 200,
      jsonBody: response
    };
  }
});