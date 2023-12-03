#!/usr/bin/env node

/**
 * @type {any}
 */
const WebSocket = require("ws");
require("dotenv").config();
const http = require("http");
const consumers = require("stream/consumers");
const wss = new WebSocket.Server({ noServer: true });
const setupWSConnection = require("./utils.js").setupWSConnection;
const { v4: uuidv4 } = require("uuid");
const cookie = require("cookie");

const host = process.env.HOST || "localhost";
const port = process.env.PORT || 1234;

const secure = host === "localhost" ? "" : "Secure; ";

const { AsyncDatabase } = require("promised-sqlite3");

const listUsers = async (request, response) => {
  const cookies = cookie.parse(request.headers.cookie || "");
  if (!cookies || !cookies.session) {
    response.writeHead(403, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "you are not authed" }));
    return;
  }
  const { session } = cookies;
  const user = await findUserFromSession(session);
  if (!user) {
    response.writeHead(403, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "you are not authed" }));
    return;
  }
  const host_id = user.user_id;
  const rows = await db.all(
    "SELECT user_id, username, CASE WHEN host IS NULL THEN 0 ELSE 1 END AS allowed FROM users LEFT JOIN permissions ON permissions.guest = user_id AND permissions.host = ? WHERE user_id != ? ORDER BY allowed DESC",
    host_id,
    host_id
  );
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify({ data: rows }));
};

const register = async (request, response) => {
  const { code, redirect_uri } = JSON.parse(
    (await consumers.buffer(request)).toString()
  );
  const resp = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "post",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: process.env.TWITCH_CLIENT_ID,
      client_secret: process.env.TWITCH_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri,
    }),
  });
  const stuff = await resp.json();
  const { access_token } = stuff;
  const twitch_resp = await fetch("https://id.twitch.tv/oauth2/validate", {
    headers: { Authorization: `OAuth ${access_token}` },
  });
  const { login, user_id } = await twitch_resp.json();
  if (!login || !user_id) {
    response.writeHead(403, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "bad token" }));
    return;
  }
  // TODO: save the login and user id to a database of some kind
  const session = await insertUser(user_id, login);
  if (session) {
    response.writeHead(200, {
      "Content-Type": "application/json",
      "Set-Cookie": `session=${session}; Path=/; Max-Age=315360000; HttpOnly; ${secure}SameSite=strict`,
    });
    response.end(JSON.stringify({ ok: "ok", username: login }));
  } else {
    response.writeHead(500, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "it blew up" }));
  }
};

const checkPerms = async (host_id, guest_id) => {
  if (host_id === guest_id) return true;
  try {
    const row = await db.get(
      "SELECT COUNT(*) as c FROM permissions WHERE host = ? AND guest = ?",
      host_id,
      guest_id
    );
    if (row?.c > 0) {
      return true;
    }
  } catch (e) {
    console.error("perm check failed", e);
  }
  return false;
};

const permissionUpdateEndpoint = async (request, response, allow) => {
  const guest_id = Number.parseInt(makeDocName(request) || "0");
  if (!guest_id) {
    response.writeHead(400, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "user not found" }));
    return;
  }
  const cookies = cookie.parse(request.headers.cookie || "");
  if (!cookies || !cookies.session) {
    response.writeHead(403, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "you are not authed" }));
    return;
  }
  const { session } = cookies;
  const user = await findUserFromSession(session);
  if (!user) {
    response.writeHead(403, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ error: "you are not authed" }));
    return;
  }
  const host_id = user.user_id;
  if (allow) {
    await db.run(
      "INSERT OR REPLACE INTO permissions VALUES (?, ?)",
      host_id,
      guest_id
    );
  } else {
    await db.run(
      "DELETE FROM permissions WHERE host = ? AND guest = ?",
      host_id,
      guest_id
    );
  }
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify({ ok: "it is done" }));
};

const permissionCheckEndpoint = async (request, response) => {
  const docName = makeDocName(request);
  const get_rekt = (why) => {
    if (why === "badguest") {
      response.writeHead(403, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "you dont exist" }));
    } else if (why === "badhost") {
      response.writeHead(404, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "host dont exist" }));
    } else {
      response.writeHead(401, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ error: "you cant do that" }));
    }
  };
  const ids = await getGuestAndHostId(request, docName);
  if (typeof ids === "string") {
    get_rekt(ids);
    return;
  }
  const { host_id, guest_id } = ids;
  const allowed = await checkPerms(host_id, guest_id);
  if (allowed) {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify({
        ok: "come on in",
        username: await usernameFromId(guest_id),
      })
    );
    return;
  }
  get_rekt();
};

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL("http://localhost" + request.url);
    const method = request.method?.toLowerCase();
    if (method === "post" && url.pathname === "/api/register") {
      await register(request, response);
    } else if (method === "get" && url.pathname === "/api/list") {
      await listUsers(request, response);
    } else if (url.pathname.startsWith("/api/perms/")) {
      if (method === "put") {
        await permissionUpdateEndpoint(request, response, true);
      } else if (method === "delete") {
        await permissionUpdateEndpoint(request, response, false);
      } else {
        response.writeHead(405, { "Content-Type": "text/plain" });
        response.end("no thanks");
      }
    } else if (
      method === "get" &&
      url.pathname.startsWith("/api/permission_slip/")
    ) {
      await permissionCheckEndpoint(request, response);
    } else {
      response.writeHead(200, { "Content-Type": "text/plain" });
      response.end("okay");
    }
  } catch (e) {
    // lol
    console.error(e);
  }
});

const makeDocName = (request) =>
  request.url.slice(1).split("?")[0].split("/").slice(2).join("/") || "";

wss.on("connection", (conn, request) => {
  const docName = makeDocName(request);
  return setupWSConnection(conn, request, { docName });
});

const getGuestAndHostId = async (request, host_username) => {
  const cookies = cookie.parse(request.headers.cookie || "");
  if (!cookies || !cookies.session) {
    return "badguest";
  }
  const { session } = cookies;
  const user = await findUserFromSession(session);
  if (!user) {
    return "badguest";
  }

  const host_id = await findUserIdFromUsername(host_username);
  if (!host_id) {
    return "badhost";
  }
  return { guest_id: user.user_id, host_id };
};

server.on("upgrade", (request, socket, head) => {
  const docName = makeDocName(request);
  // You may check auth of request here..
  // See https://github.com/websockets/ws#client-authentication
  /**
   * @param {any} ws
   */
  const handleAuth = async (ws) => {
    const ids = await getGuestAndHostId(request, docName);
    if (typeof ids === "string") {
      ws.close();
      return;
    }
    const { host_id, guest_id } = ids;
    // Check permissions
    const allowed = await checkPerms(host_id, guest_id);
    if (!allowed) {
      ws.close();
      return;
    }
    wss.emit("connection", ws, request);
  };
  wss.handleUpgrade(request, socket, head, handleAuth);
});

const usernameFromId = async (id) => {
  try {
    const row = await db.get(
      "SELECT username FROM users WHERE user_id = ?",
      id
    );
    return row?.username || null;
  } catch (e) {
    console.error("finding username failed", e);
  }
  return null;
};

const findUserIdFromUsername = async (username) => {
  try {
    const row = await db.get(
      "SELECT user_id FROM users WHERE username = ?",
      username
    );
    return row?.user_id || null;
  } catch (e) {
    console.error("finding user id failed", e);
  }
  return null;
};

const findUserFromSession = async (session) => {
  try {
    const row = await db.get(
      "SELECT sessions.user_id, users.username FROM sessions LEFT JOIN users ON users.user_id = sessions.user_id WHERE session = ?",
      session
    );
    return row;
  } catch (e) {
    console.error("finding user failed", e);
  }
  return null;
};
const insertUser = async (user_id, username) => {
  try {
    await db.run(
      "INSERT OR REPLACE INTO users VALUES (?, ?)",
      user_id,
      username
    );
    const session = uuidv4();
    await db.run("INSERT INTO sessions VALUES (?, ?)", session, user_id);
    return session;
  } catch (e) {
    console.log("user creation error", e);
  }
  return null;
};

const createTables = async () => {
  try {
    await db.run(
      "CREATE TABLE IF NOT EXISTS users (user_id INTEGER NOT NULL PRIMARY KEY, username TEXT NOT NULL)"
    );
    await db.run(
      "CREATE TABLE IF NOT EXISTS sessions (session TEXT NOT NULL PRIMARY KEY, user_id INTEGER)"
    );
    await db.run(
      "CREATE TABLE IF NOT EXISTS permissions (host INTEGER NOT NULL, guest INTEGER NOT NULL, PRIMARY KEY(host,guest))"
    );
  } catch (e) {
    console.log("table creation error", e);
  }
};

let db;
(async () => {
  db = await AsyncDatabase.open("sqlite/users.sqlite");
  await createTables();
  server.listen(port, host, async () => {
    console.log(`running at '${host}' on port ${port}`);
  });
})();
