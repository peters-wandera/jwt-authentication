
require("dotenv").config();

const http = require("http");
const jwt = require("jsonwebtoken");

const PORT = Number(process.env.PORT) || 3000;
const CLOCK_TOLERANCE_SECONDS = 300;

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
const ISSUER = process.env.JWT_ISSUER;
const AUDIENCE = process.env.JWT_AUDIENCE;

const DEMO_USERNAME = process.env.DEMO_USERNAME;
const DEMO_PASSWORD = process.env.DEMO_PASSWORD;

if (
  !ACCESS_SECRET ||
  !REFRESH_SECRET ||
  ACCESS_SECRET === REFRESH_SECRET ||
  !ISSUER ||
  !AUDIENCE ||
  !DEMO_USERNAME ||
  !DEMO_PASSWORD
) {
  throw new Error("Missing or invalid required environment configuration.");
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });

  res.end(JSON.stringify(data));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";

    req.on("data", (chunk) => {
      body += chunk;

      if (body.length > 10_000) {
        reject(new Error("Request body too large"));
        req.destroy();
      }
    });

    req.on("end", () => {
      try {
        resolve(JSON.parse(body || "{}"));
      } catch {
        reject(new Error("Invalid JSON"));
      }
    });

    req.on("error", reject);
  });
}

function signToken(username, type) {
  const isAccessToken = type === "access";

  return jwt.sign(
    { type },
    isAccessToken ? ACCESS_SECRET : REFRESH_SECRET,
    {
      subject: username,
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithm: "HS256",
      expiresIn: isAccessToken ? "5m" : "3d",
    }
  );
}

function verifyToken(token, type) {
  const isAccessToken = type === "access";

  const payload = jwt.verify(
    token,
    isAccessToken ? ACCESS_SECRET : REFRESH_SECRET,
    {
      algorithms: ["HS256"],
      issuer: ISSUER,
      audience: AUDIENCE,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    }
  );

  if (
    payload.type !== type ||
    typeof payload.sub !== "string"
  ) {
    throw new Error("Invalid token type or subject");
  }

  return payload;
}

const server = http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "http://localhost:4200");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const route = url.pathname;

  if (req.method === "GET" && route === "/api/health") {
    return sendJson(res, 200, {
      status: "success",
      message: "JWT Authentication API is running",
    });
  }

  if (req.method === "POST" && route === "/api/auth/login") {
    try {
      const body = await readJsonBody(req);

      if (
        typeof body.username !== "string" ||
        typeof body.password !== "string" ||
        body.username !== DEMO_USERNAME ||
        body.password !== DEMO_PASSWORD
      ) {
        return sendJson(res, 401, {
          status: "error",
          message: "Invalid username or password",
        });
      }

      const accessToken = signToken(body.username, "access");
      const refreshToken = signToken(body.username, "refresh");

      return sendJson(res, 200, {
        status: "success",
        message: "Login successful",
        accessToken,
        refreshToken,
        tokenType: "Bearer",
        expiresIn: 300,
      });
    } catch (error) {
      return sendJson(res, 400, {
        status: "error",
        message:
          error.message === "Invalid JSON"
            ? "Request body must contain valid JSON"
            : "Unable to process login request",
      });
    }
  }

  if (req.method === "POST" && route === "/api/auth/refresh") {
    try {
      const body = await readJsonBody(req);

      if (typeof body.refreshToken !== "string") {
        return sendJson(res, 400, {
          status: "error",
          message: "Refresh token is required",
        });
      }

      const payload = verifyToken(body.refreshToken, "refresh");
      const accessToken = signToken(payload.sub, "access");

      return sendJson(res, 200, {
        status: "success",
        message: "Access token refreshed",
        accessToken,
        tokenType: "Bearer",
        expiresIn: 300,
      });
    } catch {
      return sendJson(res, 401, {
        status: "error",
        message: "Invalid, expired, or incorrect refresh token",
      });
    }
  }

  if (req.method === "GET" && route === "/api/auth/protected") {
    const authorization = req.headers.authorization || "";
    const match = authorization.match(/^Bearer\s+(\S+)$/i);

    if (!match) {
      return sendJson(res, 401, {
        status: "error",
        message: "A Bearer access token is required",
      });
    }

    try {
      const payload = verifyToken(match[1], "access");

      return sendJson(res, 200, {
        status: "success",
        message: "You accessed a protected endpoint",
        user: { username: payload.sub },
      });
    } catch {
      return sendJson(res, 401, {
        status: "error",
        message: "Invalid, expired, or incorrect access token",
      });
    }
  }

  return sendJson(res, 404, {
    status: "error",
    message: "Route not found",
  });
});

server.listen(PORT, () => {
  console.log(`JWT Authentication API running at http://localhost:${PORT}`);
});
