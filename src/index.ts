import Fastify from "fastify";
import formbody from "@fastify/formbody";
import mqtt, { IClientOptions, MqttClient } from "mqtt";
import os from "node:os";
import crypto from "node:crypto";

type Env = {
  HTTP_HOST: string;
  HTTP_PORT: number;
  HTTP_PATH: string;

  MQTT_URL: string;
  MQTT_USERNAME?: string;
  MQTT_PASSWORD?: string;

  MQTT_QOS: 0 | 1 | 2;
  MQTT_RETAIN_RAW: boolean;
  MQTT_RETAIN_NORMALIZED: boolean;

  TOPIC_PREFIX: string; // e.g. emby
  CLIENT_ID_PREFIX: string;
  KEEPALIVE_SEC: number;

  // Optional shared-secret auth:
  // Emby can be configured to add headers in some setups; if not, you can leave unset.
  // We'll check: x-emby-webhook-secret == WEBHOOK_SECRET
  WEBHOOK_SECRET?: string;

  // Optional HMAC validation if you can configure a signature header from your webhook sender:
  // x-emby-signature: sha256=<hex>
  WEBHOOK_HMAC_SECRET?: string;

  LOG_LEVEL: "debug" | "info" | "warn" | "error";
};

const DEFAULTS = {
  HTTP_HOST: "0.0.0.0",
  HTTP_PORT: 8787,
  HTTP_PATH: "/emby-webhook",

  MQTT_QOS: 1 as const,
  MQTT_RETAIN_RAW: false,
  MQTT_RETAIN_NORMALIZED: false,

  TOPIC_PREFIX: "emby",
  CLIENT_ID_PREFIX: "emby-webhook-bridge",
  KEEPALIVE_SEC: 30,

  LOG_LEVEL: "info" as const,
};

const readEnv = (): Env => {
  const opt = (k: string) => {
    const v = process.env[k];
    return v && v.trim() ? v.trim() : undefined;
  };

  const must = (k: string) => {
    const v = opt(k);
    if (!v) throw new Error(`Missing required env var: ${k}`);
    return v;
  };

  const num = (k: string, def: number) => {
    const v = opt(k);
    if (!v) return def;
    const n = Number(v);
    if (!Number.isFinite(n) || n <= 0) throw new Error(`Invalid ${k}: ${v}`);
    return n;
  };

  const bool = (k: string, def: boolean) => {
    const v = opt(k);
    if (!v) return def;
    if (["1", "true", "yes", "on"].includes(v.toLowerCase())) return true;
    if (["0", "false", "no", "off"].includes(v.toLowerCase())) return false;
    throw new Error(`Invalid boolean ${k}: ${v}`);
  };

  const qos = (k: string, def: 0 | 1 | 2) => {
    const v = opt(k);
    if (!v) return def;
    if (v === "0" || v === "1" || v === "2") return Number(v) as 0 | 1 | 2;
    throw new Error(`Invalid ${k}: ${v} (must be 0|1|2)`);
  };

  const level = (k: string, def: Env["LOG_LEVEL"]) => {
    const v = opt(k);
    if (!v) return def;
    const vv = v.toLowerCase();
    if (vv === "debug" || vv === "info" || vv === "warn" || vv === "error") return vv;
    throw new Error(`Invalid ${k}: ${v}`);
  };

  return {
    HTTP_HOST: opt("HTTP_HOST") ?? DEFAULTS.HTTP_HOST,
    HTTP_PORT: num("HTTP_PORT", DEFAULTS.HTTP_PORT),
    HTTP_PATH: opt("HTTP_PATH") ?? DEFAULTS.HTTP_PATH,

    MQTT_URL: must("MQTT_URL"),
    MQTT_USERNAME: opt("MQTT_USERNAME"),
    MQTT_PASSWORD: opt("MQTT_PASSWORD"),

    MQTT_QOS: qos("MQTT_QOS", DEFAULTS.MQTT_QOS),
    MQTT_RETAIN_RAW: bool("MQTT_RETAIN_RAW", DEFAULTS.MQTT_RETAIN_RAW),
    MQTT_RETAIN_NORMALIZED: bool("MQTT_RETAIN_NORMALIZED", DEFAULTS.MQTT_RETAIN_NORMALIZED),

    TOPIC_PREFIX: opt("TOPIC_PREFIX") ?? DEFAULTS.TOPIC_PREFIX,
    CLIENT_ID_PREFIX: opt("CLIENT_ID_PREFIX") ?? DEFAULTS.CLIENT_ID_PREFIX,
    KEEPALIVE_SEC: num("KEEPALIVE_SEC", DEFAULTS.KEEPALIVE_SEC),

    WEBHOOK_SECRET: opt("WEBHOOK_SECRET"),
    WEBHOOK_HMAC_SECRET: opt("WEBHOOK_HMAC_SECRET"),

    LOG_LEVEL: level("LOG_LEVEL", DEFAULTS.LOG_LEVEL),
  };
};

const log = (level: Env["LOG_LEVEL"], current: Env["LOG_LEVEL"], msg: string, extra?: unknown) => {
  const order: Record<Env["LOG_LEVEL"], number> = { debug: 10, info: 20, warn: 30, error: 40 };
  if (order[level] < order[current]) return;
  const prefix = `[${new Date().toISOString()}] [${level}]`;
  if (extra !== undefined) console.log(prefix, msg, extra);
  else console.log(prefix, msg);
};

const asJsonString = (v: unknown) => JSON.stringify(v);

const toSafeEventSlug = (raw: unknown) => {
  const s = String(raw ?? "unknown").trim();
  const slug = s
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80);
  return slug.length ? slug : "unknown";
};

/**
 * Emby webhook payloads vary. We extract best-effort event fields.
 * We keep this intentionally defensive: you always get raw.
 */
const extractEventInfo = (body: any) => {
  const eventRaw =
    body?.Event
    ?? body?.event
    ?? body?.Name
    ?? body?.name
    ?? body?.NotificationType
    ?? body?.notificationType
    ?? body?.Type
    ?? body?.type;

  const event = toSafeEventSlug(eventRaw);

  const userName = body?.User?.Name ?? body?.UserName ?? body?.userName ?? body?.user?.name;
  const serverName = body?.Server?.Name ?? body?.ServerName ?? body?.serverName ?? body?.server?.name;

  const itemName =
    body?.Item?.Name
    ?? body?.ItemName
    ?? body?.itemName
    ?? body?.item?.name
    ?? body?.Title
    ?? body?.title;

  const itemId =
    body?.Item?.Id
    ?? body?.ItemId
    ?? body?.itemId
    ?? body?.item?.id
    ?? body?.Id
    ?? body?.id;

  const sessionId = body?.Session?.Id ?? body?.SessionId ?? body?.sessionId ?? body?.session?.id;

  return {
    event,
    userName: userName ? String(userName) : undefined,
    serverName: serverName ? String(serverName) : undefined,
    itemName: itemName ? String(itemName) : undefined,
    itemId: itemId ? String(itemId) : undefined,
    sessionId: sessionId ? String(sessionId) : undefined,
  };
};

const normalize = (body: any) => {
  const info = extractEventInfo(body);
  return {
    ts: new Date().toISOString(),
    host: os.hostname(),
    event: info.event,
    userName: info.userName,
    serverName: info.serverName,
    item: info.itemId || info.itemName ? { id: info.itemId, name: info.itemName } : undefined,
    sessionId: info.sessionId,
  };
};

const mkTopics = (prefix: string, event: string) => ({
  raw: `${prefix}/raw/${event}`,
  normalized: `${prefix}/event/${event}`,
  bridgeStatus: `${prefix}/status/bridge`,
});

const publish = async (
  client: MqttClient,
  topic: string,
  payload: string,
  qos: 0 | 1 | 2,
  retain: boolean
) =>
  new Promise<void>((resolve, reject) => {
    client.publish(topic, payload, { qos, retain }, (err) => (err ? reject(err) : resolve()));
  });

const verifySharedSecret = (env: Env, headers: Record<string, any>) => {
  if (!env.WEBHOOK_SECRET) return true;
  const got = headers["x-emby-webhook-secret"] ?? headers["x-webhook-secret"];
  return typeof got === "string" && got === env.WEBHOOK_SECRET;
};

const verifyHmac = (env: Env, headers: Record<string, any>, rawBody: string) => {
  if (!env.WEBHOOK_HMAC_SECRET) return true;
  const header = headers["x-emby-signature"] ?? headers["x-signature"];
  if (typeof header !== "string") return false;

  // Expect: "sha256=<hex>" OR "<hex>"
  const parts = header.split("=", 2);
  const hex = (parts.length === 2 ? parts[1] : parts[0]).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) return false;

  const h = crypto.createHmac("sha256", env.WEBHOOK_HMAC_SECRET).update(rawBody, "utf8").digest("hex");
  return crypto.timingSafeEqual(Buffer.from(h, "hex"), Buffer.from(hex, "hex"));
};

const main = async () => {
  const env = readEnv();

  const mqttClientId = `${env.CLIENT_ID_PREFIX}-${os.hostname()}-${Math.random().toString(16).slice(2, 10)}`;

  const mqttOpts: IClientOptions = {
    clientId: mqttClientId,
    username: env.MQTT_USERNAME,
    password: env.MQTT_PASSWORD,
    keepalive: env.KEEPALIVE_SEC,
    reconnectPeriod: 2000,
    connectTimeout: 10_000,
    clean: true,
    will: {
      topic: `${env.TOPIC_PREFIX}/status/bridge`,
      payload: asJsonString({ state: "offline", ts: new Date().toISOString(), host: os.hostname() }),
      qos: env.MQTT_QOS,
      retain: true,
    },
  };

  log("info", env.LOG_LEVEL, `Connecting to MQTT`, { url: env.MQTT_URL, clientId: mqttClientId });
  const mqttClient = mqtt.connect(env.MQTT_URL, mqttOpts);

  mqttClient.on("connect", async () => {
    log("info", env.LOG_LEVEL, `MQTT connected`);
    try {
      await publish(
        mqttClient,
        `${env.TOPIC_PREFIX}/status/bridge`,
        asJsonString({ state: "online", ts: new Date().toISOString(), host: os.hostname() }),
        env.MQTT_QOS,
        true
      );
      log("info", env.LOG_LEVEL, `Bridge status online published`, { topic: `${env.TOPIC_PREFIX}/status/bridge` });
    } catch (e) {
      log("warn", env.LOG_LEVEL, `Bridge status publish failed`, { error: String(e) });
    }
  });

  mqttClient.on("error", (err) => log("error", env.LOG_LEVEL, `MQTT error`, { error: String(err) }));

  // Fastify server
  const app = Fastify({
    logger: false,
    // Capture raw body for HMAC verification when needed.
    // Fastify only populates request.rawBody if configured like this:
    bodyLimit: 2 * 1024 * 1024,
  });

  await app.register(formbody);

  // Minimal "alive" endpoint
  app.get("/healthz", async () => ({ ok: true }));

  // Webhook endpoint
  app.post(env.HTTP_PATH, async (req, reply) => {
    const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), v]));

    // Best-effort raw body:
    // If Emby posts JSON, Fastify parses it, so we reconstruct a stable raw json.
    // For HMAC, we accept using reconstructed raw when req.body is object, unless you provide x-emby-signature (then this must match).
    const rawBody = typeof req.body === "string" ? req.body : asJsonString(req.body);

    if (!verifySharedSecret(env, headers)) {
      log("warn", env.LOG_LEVEL, `Rejected webhook: bad shared secret`, { from: req.ip });
      return reply.code(401).send({ ok: false });
    }
    if (!verifyHmac(env, headers, rawBody)) {
      log("warn", env.LOG_LEVEL, `Rejected webhook: bad HMAC`, { from: req.ip });
      return reply.code(401).send({ ok: false });
    }

    const body: any = req.body ?? {};
    const info = extractEventInfo(body);
    const topics = mkTopics(env.TOPIC_PREFIX, info.event);

    const rawPayload = asJsonString({
      ts: new Date().toISOString(),
      host: os.hostname(),
      ip: req.ip,
      headers: {
        // keep only a few useful headers to avoid leaking too much
        "user-agent": req.headers["user-agent"],
        "content-type": req.headers["content-type"],
      },
      body,
    });

    const normalizedPayload = asJsonString(normalize(body));

    if (!mqttClient.connected) {
      log("warn", env.LOG_LEVEL, `MQTT not connected; dropping webhook event`, { event: info.event });
      return reply.code(503).send({ ok: false, reason: "mqtt_disconnected" });
    }

    try {
      await publish(mqttClient, topics.raw, rawPayload, env.MQTT_QOS, env.MQTT_RETAIN_RAW);
      await publish(mqttClient, topics.normalized, normalizedPayload, env.MQTT_QOS, env.MQTT_RETAIN_NORMALIZED);
      log("info", env.LOG_LEVEL, `Forwarded webhook → MQTT`, { event: info.event, raw: topics.raw, evt: topics.normalized });
      return { ok: true, event: info.event };
    } catch (e) {
      log("error", env.LOG_LEVEL, `Failed to publish to MQTT`, { error: String(e), event: info.event });
      return reply.code(500).send({ ok: false });
    }
  });

  await app.listen({ host: env.HTTP_HOST, port: env.HTTP_PORT });
  log("info", env.LOG_LEVEL, `HTTP listening`, { host: env.HTTP_HOST, port: env.HTTP_PORT, path: env.HTTP_PATH });

  const shutdown = async (signal: string) => {
    log("info", env.LOG_LEVEL, `Shutting down`, { signal });
    try {
      if (mqttClient.connected) {
        await publish(
          mqttClient,
          `${env.TOPIC_PREFIX}/status/bridge`,
          asJsonString({ state: "offline", ts: new Date().toISOString(), host: os.hostname() }),
          env.MQTT_QOS,
          true
        );
      }
    } catch { }
    await app.close();
    mqttClient.end(true, () => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
};

main().catch((e) => {
  console.error(`[fatal] ${String(e)}`);
  process.exit(1);
});
