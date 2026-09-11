const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// --- 1. FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const auth = admin.auth();

const app = express();
app.set('trust proxy', 1);

// --- 2. CORS RESTRINGIDO FINAL ---
const allowedOrigins = [
    'https://golazosp.net',
    'https://www.golazosp.net',
    'https://zonagolazo.net',
    'https://www.zonagolazo.net',
    'https://thony-gsp.github.io'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        console.warn(`❌ CORS bloqueado para origin: ${origin}`);
        return callback(null, false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json());

// Las respuestas contienen sesiones, URLs firmadas y configuración en vivo.
// Ningún navegador, proxy o CDN debe reutilizarlas entre solicitudes.
app.use((req, res, next) => {
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Surrogate-Control': 'no-store'
    });
    res.vary('Origin');
    res.vary('Authorization');
    next();
});

// --- 3. RATE LIMITS CONFIGURABLES ---
const GENERAL_RATE_LIMIT_MAX = parseInt(process.env.GENERAL_RATE_LIMIT_MAX || "120", 10);
const STREAM_RATE_LIMIT_MAX = parseInt(process.env.STREAM_RATE_LIMIT_MAX || "30", 10);
const ADMIN_RATE_LIMIT_MAX = parseInt(process.env.ADMIN_RATE_LIMIT_MAX || "20", 10);
const CREATE_PASS_RATE_LIMIT_MAX = parseInt(process.env.CREATE_PASS_RATE_LIMIT_MAX || "100", 10);
const QUICK_LOGIN_RATE_LIMIT_MAX = parseInt(process.env.QUICK_LOGIN_RATE_LIMIT_MAX || "12", 10);

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: GENERAL_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: {
        success: false,
        code: "RATE_LIMIT",
        error: "Demasiadas solicitudes."
    }
});

const streamLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: STREAM_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: {
        success: false,
        code: "STREAM_RATE_LIMIT",
        error: "Demasiadas solicitudes de stream."
    }
});

const adminLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: ADMIN_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: {
        success: false,
        code: "ADMIN_RATE_LIMIT",
        error: "Demasiadas solicitudes administrativas."
    }
});

const createPassLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: CREATE_PASS_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: {
        success: false,
        code: "CREATE_PASS_RATE_LIMIT",
        error: "Demasiadas solicitudes de creación de pases."
    }
});

const quickLoginLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: QUICK_LOGIN_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: {
        success: false,
        code: "QUICK_LOGIN_RATE_LIMIT",
        error: "Demasiados intentos de código. Intenta nuevamente en un momento."
    }
});

app.use(generalLimiter);

// --- 4. CONFIGURACIÓN ---
const BUNNY_CDN_URL = 'https://stream.golazosp.net';
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY.trim();
const STREAM_PATH = '/stream/master.m3u8';
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// Selector de fuente de stream.
// Valores permitidos:
// iframe   = usa el reproductor aislado de player-latam-hd.site.
// external = usa la señal HLS directa de live.site.pe.
// bunny    = usa Bunny CDN con token firmado.
const STREAM_MODE_DEFAULT = String(process.env.STREAM_MODE || "bunny").trim().toLowerCase();
const EXTERNAL_STREAM_URL_DEFAULT = String(
    process.env.EXTERNAL_STREAM_URL || "https://live.site.pe/live/golazosp.m3u8"
).trim();
const IFRAME_PLAYER_URL_DEFAULT = String(
    process.env.IFRAME_PLAYER_URL ||
    "https://player-latam-hd.site/index.php?prov=la14hd&stream=sv24je.html&v=5"
).trim();
const STREAM_FALLBACK_ORDER_DEFAULT = ["iframe", "external", "bunny"];

// Cache para no leer Firestore en cada /generate-stream.
const STREAM_CONFIG_CACHE_TTL_MS = parseInt(
    process.env.STREAM_CONFIG_CACHE_TTL_MS || "5000",
    10
);

const MAX_TRANSMISSIONS = 10;
const MAX_OPTIONS_PER_TRANSMISSION = 5;

let cachedStreamConfig = null;
let cachedStreamConfigExpiresAt = 0;

// Código rápido
const QUICK_CODE_SECRET = (process.env.QUICK_CODE_SECRET || process.env.BUNNY_KEY || "").trim();

// URL pública de la web para generar links rápidos
const APP_BASE_URL = process.env.APP_BASE_URL || "https://golazosp.net";

// --- 4.1 OPTIMIZACIÓN DE ESCALA ---
const HEARTBEAT_WRITE_MIN_INTERVAL_MS = parseInt(
    process.env.HEARTBEAT_WRITE_MIN_INTERVAL_MS || "90000",
    10
);

const ACTIVE_SESSION_WINDOW_MS = parseInt(
    process.env.ACTIVE_SESSION_WINDOW_MS || "150000",
    10
);

const BUNNY_TOKEN_DURATION_SECONDS = parseInt(
    process.env.BUNNY_TOKEN_DURATION_SECONDS || "600",
    10
);

// --- 5. HEALTH CHECK ---
app.get('/', (req, res) => {
    res.json({
        success: true,
        service: "Golazo Stream Backend",
        status: "online",
        version: "FASE 10.4 - gestion de accesos y analitica",
        stream_mode_default: STREAM_MODE_DEFAULT
    });
});

// --- 6. HELPERS GENERALES ---
function getTimestampMillis(value) {
    return value && typeof value.toMillis === "function"
        ? value.toMillis()
        : 0;
}

function shouldWriteHeartbeat(userData, now, minIntervalMs = HEARTBEAT_WRITE_MIN_INTERVAL_MS) {
    const lastHeartbeatMillis = getTimestampMillis(userData.last_heartbeat);

    if (!lastHeartbeatMillis) return true;
    return now - lastHeartbeatMillis >= minIntervalMs;
}

function nowTimestamp() {
    return admin.firestore.Timestamp.now();
}

function normalizeClientId(value) {
    const normalized = String(value || "").trim();

    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(normalized)) {
        return "";
    }

    return normalized;
}

async function verifyUserRequest(req) {
    const authHeader = req.headers.authorization || "";
    const tokenFromHeader = authHeader.startsWith("Bearer ")
        ? authHeader.replace("Bearer ", "").trim()
        : "";
    const tokenFromBody = String(req.body?.id_token || "").trim();
    const idToken = tokenFromHeader || tokenFromBody;

    if (!idToken) return null;

    try {
        return await auth.verifyIdToken(idToken);
    } catch (_) {
        return null;
    }
}

function normalizeStreamSource(value) {
    const source = String(value || "").trim().toLowerCase();

    if (source === "iframe") return "iframe";
    if (source === "external" || source === "hls") return "external";
    if (source === "bunny") return "bunny";

    return "bunny";
}

function normalizeFallbackOrder(value, primarySource = "iframe") {
    const rawOrder = Array.isArray(value)
        ? value
        : String(value || "").split(",");
    const validSources = new Set(["iframe", "external", "bunny"]);
    const normalized = [];

    [primarySource, ...rawOrder, ...STREAM_FALLBACK_ORDER_DEFAULT].forEach((item) => {
        const source = String(item || "").trim().toLowerCase();
        if (validSources.has(source) && !normalized.includes(source)) {
            normalized.push(source);
        }
    });

    return normalized;
}

function isValidHttpUrl(value) {
    try {
        const url = new URL(String(value || "").trim());
        return url.protocol === "http:" || url.protocol === "https:";
    } catch (_) {
        return false;
    }
}

function normalizeCatalogId(value, fallback = "") {
    const normalized = String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 64);

    return normalized || fallback;
}

function normalizeDisplayText(value, maxLength = 80) {
    return String(value || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, maxLength);
}

function createCatalogId(prefix) {
    return `${prefix}-${crypto.randomBytes(6).toString("hex")}`;
}

function normalizeBunnyPath(value) {
    let path = String(value || STREAM_PATH).trim();

    if (isValidHttpUrl(path)) {
        try {
            path = new URL(path).pathname;
        } catch (_) {
            return "";
        }
    }

    if (!path.startsWith("/")) path = `/${path}`;
    if (!path.startsWith("/stream/") || path.includes("..")) return "";
    if (!/\.m3u8$/i.test(path)) return "";

    return path;
}

function normalizeTransmissionCatalog(rawTransmissions, strict = false) {
    const errors = [];
    const transmissions = [];
    const transmissionIds = new Set();
    const input = Array.isArray(rawTransmissions)
        ? rawTransmissions.slice(0, MAX_TRANSMISSIONS)
        : [];

    input.forEach((rawTransmission, transmissionIndex) => {
        if (!rawTransmission || typeof rawTransmission !== "object") {
            if (strict) errors.push(`Transmisión ${transmissionIndex + 1}: formato inválido.`);
            return;
        }

        let transmissionId = normalizeCatalogId(
            rawTransmission.id,
            `transmision-${transmissionIndex + 1}`
        );
        if (transmissionIds.has(transmissionId)) {
            transmissionId = strict
                ? createCatalogId("transmision")
                : `${transmissionId}-${transmissionIndex + 1}`;
        }
        transmissionIds.add(transmissionId);

        const name = normalizeDisplayText(
            rawTransmission.name || rawTransmission.title,
            80
        );
        const channel = normalizeDisplayText(rawTransmission.channel, 80);
        const visible = rawTransmission.visible !== false;
        const options = [];
        const optionIds = new Set();
        const rawOptions = Array.isArray(rawTransmission.options)
            ? rawTransmission.options.slice(0, MAX_OPTIONS_PER_TRANSMISSION)
            : [];

        if (!name && strict) {
            errors.push(`Transmisión ${transmissionIndex + 1}: falta el nombre visible.`);
        }

        if (
            Array.isArray(rawTransmission.options) &&
            rawTransmission.options.length > MAX_OPTIONS_PER_TRANSMISSION
        ) {
            errors.push(
                `${name || `Transmisión ${transmissionIndex + 1}`}: ` +
                `solo se permiten ${MAX_OPTIONS_PER_TRANSMISSION} opciones.`
            );
        }

        rawOptions.forEach((rawOption, optionIndex) => {
            if (!rawOption || typeof rawOption !== "object") {
                if (strict) errors.push(`${name || `Transmisión ${transmissionIndex + 1}`}: opción inválida.`);
                return;
            }

            let optionId = normalizeCatalogId(
                rawOption.id,
                `opcion-${optionIndex + 1}`
            );
            if (optionIds.has(optionId)) {
                optionId = strict
                    ? createCatalogId("opcion")
                    : `${optionId}-${optionIndex + 1}`;
            }
            optionIds.add(optionId);

            const rawSourceType = String(
                rawOption.source_type || rawOption.type || ""
            ).trim().toLowerCase();

            if (!["iframe", "external", "hls", "bunny"].includes(rawSourceType)) {
                if (strict) errors.push(
                    `${name || transmissionId} / Opción ${optionIndex + 1}: tipo de fuente inválido.`
                );
                return;
            }

            const sourceType = normalizeStreamSource(rawSourceType);
            const label = normalizeDisplayText(
                rawOption.label || `Opción ${optionIndex + 1}`,
                40
            );
            const enabled = rawOption.enabled !== false && rawOption.visible !== false;
            const option = {
                id: optionId,
                label,
                source_type: sourceType,
                enabled
            };

            if (sourceType === "bunny") {
                option.path = normalizeBunnyPath(rawOption.path || rawOption.url);
                if (!option.path) {
                    if (strict) errors.push(`${name || transmissionId} / ${label}: ruta Bunny inválida.`);
                    return;
                }
            } else {
                option.url = String(rawOption.url || "").trim();
                if (!isValidHttpUrl(option.url)) {
                    if (strict) errors.push(`${name || transmissionId} / ${label}: URL inválida.`);
                    return;
                }
            }

            options.push(option);
        });

        if (!options.length && strict) {
            errors.push(`${name || `Transmisión ${transmissionIndex + 1}`}: agrega al menos una opción válida.`);
        }

        const requestedDefaultOptionId = normalizeCatalogId(
            rawTransmission.default_option_id
        );
        const firstEnabledOption = options.find(option => option.enabled) || options[0];
        const defaultOption = options.find(
            option => option.id === requestedDefaultOptionId && option.enabled
        ) || firstEnabledOption;

        if (name && options.length) {
            transmissions.push({
                id: transmissionId,
                name,
                channel,
                visible,
                default_option_id: defaultOption?.id || "",
                options
            });
        }
    });

    if (Array.isArray(rawTransmissions) && rawTransmissions.length > MAX_TRANSMISSIONS) {
        errors.push(`Solo se permiten ${MAX_TRANSMISSIONS} transmisiones.`);
    }

    return { transmissions, errors };
}

function createStreamConfigVersion(config) {
    const stableConfig = {
        default_transmission_id: String(config.default_transmission_id || ""),
        transmissions: config.transmissions || [],
        active_source: String(config.active_source || ""),
        external_url: String(config.external_url || ""),
        iframe_url: String(config.iframe_url || ""),
        fallback_order: config.fallback_order || []
    };

    return crypto
        .createHash("sha256")
        .update(JSON.stringify(stableConfig))
        .digest("hex")
        .slice(0, 16);
}

function createLegacyTransmission(config) {
    const activeSource = normalizeStreamSource(config.active_source);
    const option = {
        id: "opcion-1",
        label: "Opción 1",
        source_type: activeSource,
        enabled: true
    };

    if (activeSource === "iframe") option.url = config.iframe_url;
    if (activeSource === "external") option.url = config.external_url;
    if (activeSource === "bunny") option.path = STREAM_PATH;

    return {
        id: "transmision-principal",
        name: "Transmisión principal",
        channel: "",
        visible: true,
        default_option_id: option.id,
        options: [option]
    };
}

// Lee la fuente activa desde Firestore.
// Ruta Firestore recomendada:
// collection: config
// document: stream
async function getActiveStreamConfig(forceRefresh = false) {
    const now = Date.now();

    if (!forceRefresh && cachedStreamConfig && now < cachedStreamConfigExpiresAt) {
        return cachedStreamConfig;
    }

    let config = {
        schema_version: 1,
        active_source: normalizeStreamSource(STREAM_MODE_DEFAULT),
        external_url: EXTERNAL_STREAM_URL_DEFAULT,
        iframe_url: IFRAME_PLAYER_URL_DEFAULT,
        fallback_order: normalizeFallbackOrder(null, normalizeStreamSource(STREAM_MODE_DEFAULT)),
        default_transmission_id: "",
        transmissions: []
    };

    try {
        const doc = await db.collection("config").doc("stream").get();

        if (doc.exists) {
            const data = doc.data() || {};

            config = {
                schema_version: Number(data.schema_version || 1),
                active_source: normalizeStreamSource(data.active_source || STREAM_MODE_DEFAULT),
                external_url: String(data.external_url || EXTERNAL_STREAM_URL_DEFAULT).trim(),
                iframe_url: String(data.iframe_url || IFRAME_PLAYER_URL_DEFAULT).trim(),
                fallback_order: normalizeFallbackOrder(
                    data.fallback_order,
                    normalizeStreamSource(data.active_source || STREAM_MODE_DEFAULT)
                ),
                default_transmission_id: normalizeCatalogId(data.default_transmission_id),
                transmissions: []
            };

            if (Array.isArray(data.transmissions)) {
                config.schema_version = 2;
                config.transmissions = normalizeTransmissionCatalog(
                    data.transmissions,
                    false
                ).transmissions;
            }
        }

        if (!isValidHttpUrl(config.external_url)) {
            console.warn("⚠️ external_url inválida. Se restauró el valor predeterminado.");
            config.external_url = EXTERNAL_STREAM_URL_DEFAULT;
            if (config.active_source === "external") config.active_source = "bunny";
        }

        if (!isValidHttpUrl(config.iframe_url)) {
            console.warn("⚠️ iframe_url inválida. Se restauró el valor predeterminado.");
            config.iframe_url = IFRAME_PLAYER_URL_DEFAULT;
            if (config.active_source === "iframe") config.active_source = "bunny";
        }

        config.fallback_order = normalizeFallbackOrder(
            config.fallback_order,
            config.active_source
        );

        if (config.schema_version < 2) {
            config.transmissions = [createLegacyTransmission(config)];
            config.default_transmission_id = config.transmissions[0].id;
        } else {
            const visibleTransmissions = config.transmissions.filter(transmission =>
                transmission.visible && transmission.options.some(option => option.enabled)
            );

            if (!visibleTransmissions.some(
                transmission => transmission.id === config.default_transmission_id
            )) {
                config.default_transmission_id = visibleTransmissions[0]?.id || "";
            }
        }

        config.version = createStreamConfigVersion(config);

        cachedStreamConfig = config;
        cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;

        return config;

    } catch (error) {
        console.error("❌ Error leyendo config stream desde Firestore:", error.message);

        config.transmissions = [createLegacyTransmission(config)];
        config.default_transmission_id = config.transmissions[0].id;
        config.version = createStreamConfigVersion(config);

        cachedStreamConfig = config;
        cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;

        return config;
    }
}

// --- 7. GENERADOR DE TOKEN BUNNY PARA DIRECTORIOS ---
function base64Url(buffer) {
    return buffer.toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
        .replace(/\n/g, "");
}

function generateBunnyTokenForStream(path, securityKey, duration = 120) {
    const expires = Math.floor(Date.now() / 1000) + duration;

    const tokenPath = "/stream/";
    const signaturePath = tokenPath;
    const signingData = `token_path=${tokenPath}`;
    const userIp = "";

    const message = `${signaturePath}${expires}${signingData}${userIp}`;

    const token = "HS256-" + base64Url(
        crypto.createHmac("sha256", securityKey)
            .update(message)
            .digest()
    );

    const encodedTokenPath = encodeURIComponent(tokenPath);

    return {
        token,
        expires,
        token_path: tokenPath,
        url: `${BUNNY_CDN_URL}/bcdn_token=${token}&expires=${expires}&token_path=${encodedTokenPath}${path}`
    };
}

function materializeTransmissionCatalog(config, tokenDuration) {
    const transmissions = (config.transmissions || [])
        .filter(transmission => transmission.visible)
        .map(transmission => {
            const options = transmission.options
                .filter(option => option.enabled)
                .map(option => {
                    if (option.source_type === "bunny") {
                        const signed = generateBunnyTokenForStream(
                            option.path,
                            BUNNY_SECURITY_KEY,
                            tokenDuration
                        );

                        return {
                            id: option.id,
                            label: option.label,
                            source_type: "bunny",
                            type: "hls",
                            url: signed.url,
                            expires: signed.expires
                        };
                    }

                    return {
                        id: option.id,
                        label: option.label,
                        source_type: option.source_type,
                        type: option.source_type === "iframe" ? "iframe" : "hls",
                        url: option.url
                    };
                });

            if (!options.length) return null;

            const defaultOption = options.find(
                option => option.id === transmission.default_option_id
            ) || options[0];

            return {
                id: transmission.id,
                name: transmission.name,
                channel: transmission.channel,
                default_option_id: defaultOption.id,
                options
            };
        })
        .filter(Boolean);

    const defaultTransmission = transmissions.find(
        transmission => transmission.id === config.default_transmission_id
    ) || transmissions[0] || null;

    return {
        transmissions,
        default_transmission_id: defaultTransmission?.id || ""
    };
}

// --- 8. MIDDLEWARE ADMIN ESTRICTO ---
async function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Falta token de administrador"
        });
    }

    const idToken = authHeader.replace("Bearer ", "").trim();

    try {
        const decodedToken = await auth.verifyIdToken(idToken);

        if (decodedToken.admin === true) {
            return next();
        }

        return res.status(403).json({
            success: false,
            message: "Permisos denegados. No eres administrador."
        });

    } catch (error) {
        console.error("❌ Token admin inválido:", error.message);

        return res.status(401).json({
            success: false,
            message: "Token de administrador inválido o expirado"
        });
    }
}

// --- 9. EXTRAER IP y USER-AGENT ---
function getClientData(req) {
    const forwardedFor = req.headers['x-forwarded-for'];

    const ip = forwardedFor
        ? forwardedFor.split(',')[0].trim()
        : (req.ip || req.connection.remoteAddress || 'Desconocida');

    const userAgent = req.headers['user-agent'] || 'Desconocido';

    return { ip, userAgent };
}


// --- 9.1 GESTIÓN DE ACCESOS Y ANALÍTICA ---
function formatPeruDateKey(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return "sin-fecha";

    return new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Lima',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).format(date);
}

function buildEventId(label, dateValue) {
    const normalizedLabel = normalizeDisplayText(label || "Sin etiqueta", 80).toLowerCase();
    const dateKey = formatPeruDateKey(dateValue);

    return crypto
        .createHash('sha256')
        .update(`${normalizedLabel}|${dateKey}`)
        .digest('hex')
        .slice(0, 16);
}

function getUserEventId(data) {
    if (data?.event_id) return String(data.event_id);

    const label = normalizeDisplayText(data?.etiqueta || "Sin etiqueta", 80).toLowerCase();
    return `legacy-${crypto.createHash('sha256').update(label).digest('hex').slice(0, 12)}`;
}

function summarizeUserAgent(userAgent) {
    if (!userAgent || userAgent === "Sin registro") return "Sin registro";

    const ua = String(userAgent).toLowerCase();

    if (ua.includes("tizen")) return "Samsung TV";
    if (ua.includes("webos")) return "LG Smart TV";
    if (ua.includes("android tv")) return "Android TV";
    if (ua.includes("aft") || ua.includes("fire tv")) return "Fire TV";
    if (ua.includes("roku")) return "Roku TV";
    if (ua.includes("smart-tv") || ua.includes("smarttv") || ua.includes("hbbtv")) return "Smart TV";
    if (ua.includes("iphone")) return "iPhone";
    if (ua.includes("ipad")) return "iPad";
    if (ua.includes("android")) return "Android";
    if (ua.includes("windows")) return "Windows";
    if (ua.includes("mac os")) return "Mac";
    if (ua.includes("edg")) return "Edge";
    if (ua.includes("chrome")) return "Chrome";
    if (ua.includes("firefox")) return "Firefox";
    if (ua.includes("safari") && !ua.includes("chrome")) return "Safari";

    return "Navegador";
}

function isRevokedUser(data) {
    return data?.last_status === "revoked_by_admin" ||
        String(data?.session_id || "").startsWith("revoked_");
}

function isUserWatchingNow(data, now = Date.now()) {
    const expiraMillis = getTimestampMillis(data?.fecha_expiracion);
    const lastHeartbeatMillis = getTimestampMillis(data?.last_heartbeat);
    const sessionId = String(data?.session_id || "");
    const status = String(data?.last_status || "");

    if (!expiraMillis || expiraMillis <= now) return false;
    if (!lastHeartbeatMillis || now - lastHeartbeatMillis >= ACTIVE_SESSION_WINDOW_MS) return false;
    if (!sessionId || sessionId.startsWith("revoked_")) return false;
    if (["expired", "revoked_by_admin", "released"].includes(status)) return false;

    return true;
}

function userNeverEntered(data) {
    return !data?.last_quick_login_at &&
        !data?.last_heartbeat &&
        !data?.session_started_at;
}

function serializeExtensionHistory(history) {
    if (!Array.isArray(history)) return [];

    return history.map(item => ({
        at_ms: getTimestampMillis(item?.at),
        mode: item?.mode || "add",
        minutes: Number.isFinite(Number(item?.minutes)) ? Number(item.minutes) : null,
        old_expiration_ms: getTimestampMillis(item?.old_expiration),
        new_expiration_ms: getTimestampMillis(item?.new_expiration),
        old_label: item?.old_label || "",
        new_label: item?.new_label || ""
    }));
}

async function syncEventPeaks(eventSummaries) {
    if (!eventSummaries.length) return eventSummaries;

    const refs = eventSummaries.map(item => db.collection('event_stats').doc(item.event_id));
    const snaps = await db.getAll(...refs);
    const batch = db.batch();
    let needsCommit = false;

    snaps.forEach((snap, index) => {
        const summary = eventSummaries[index];
        const storedPeak = snap.exists ? Number(snap.data()?.peak_concurrent || 0) : 0;
        const finalPeak = Math.max(storedPeak, summary.viendo_ahora);
        summary.peak_concurrent = finalPeak;

        if (!snap.exists || finalPeak > storedPeak) {
            batch.set(refs[index], {
                event_id: summary.event_id,
                etiqueta: summary.etiqueta,
                peak_concurrent: finalPeak,
                updated_at: nowTimestamp()
            }, { merge: true });
            needsCommit = true;
        }
    });

    if (needsCommit) await batch.commit();
    return eventSummaries;
}

// --- 10. CÓDIGO RÁPIDO DE ACCESO ---
function normalizarCodigoRapido(value) {
    return String(value || "")
        .replace(/\D/g, "")
        .trim();
}

function hashQuickCode(code) {
    if (!QUICK_CODE_SECRET) {
        throw new Error("Falta QUICK_CODE_SECRET o BUNNY_KEY para firmar códigos rápidos.");
    }

    return crypto
        .createHmac("sha256", QUICK_CODE_SECRET)
        .update(String(code).trim())
        .digest("hex");
}

function generarCodigoSeisDigitos() {
    return crypto.randomInt(100000, 1000000).toString();
}

async function generarCodigoRapidoUnico(maxIntentos = 20) {
    for (let i = 0; i < maxIntentos; i++) {
        const codigo = generarCodigoSeisDigitos();
        const hash = hashQuickCode(codigo);

        const snap = await db.collection("usuarios")
            .where("quick_code_hash", "==", hash)
            .limit(1)
            .get();

        if (snap.empty) {
            return { codigo, hash };
        }
    }

    throw new Error("No se pudo generar un código rápido único.");
}

function generarPasswordInternoSeguro() {
    return crypto.randomBytes(24).toString("base64url");
}

// --- 11. LOGIN RÁPIDO POR CÓDIGO ---
app.post('/auth/quick-login', quickLoginLimiter, async (req, res) => {
    try {
        const codigo = normalizarCodigoRapido(req.body?.codigo);

        if (!/^\d{6}$/.test(codigo)) {
            return res.status(400).json({
                success: false,
                code: "INVALID_CODE",
                error: "Código inválido."
            });
        }

        const codeHash = hashQuickCode(codigo);

        const snap = await db.collection("usuarios")
            .where("quick_code_hash", "==", codeHash)
            .limit(1)
            .get();

        if (snap.empty) {
            return res.status(401).json({
                success: false,
                code: "CODE_NOT_FOUND",
                error: "Código incorrecto."
            });
        }

        const doc = snap.docs[0];
        const uid = doc.id;
        const userData = doc.data();

        if (!userData.fecha_expiracion || typeof userData.fecha_expiracion.toMillis !== "function") {
            return res.status(403).json({
                success: false,
                code: "NO_EXPIRATION",
                error: "Pase sin expiración."
            });
        }

        const expiraMillis = userData.fecha_expiracion.toMillis();
        const ahora = Date.now();

        if (expiraMillis <= ahora) {
            await doc.ref.update({
                last_status: "expired",
                last_heartbeat: nowTimestamp()
            });

            return res.status(403).json({
                success: false,
                code: "PASS_EXPIRED",
                error: "El pase ha caducado."
            });
        }

        if (
            userData.last_status === "revoked_by_admin" ||
            String(userData.session_id || "").startsWith("revoked_")
        ) {
            return res.status(403).json({
                success: false,
                code: "SESSION_REVOKED",
                error: "Pase revocado por administración."
            });
        }

        const { ip, userAgent } = getClientData(req);

        const customToken = await auth.createCustomToken(uid, {
            login_mode: "quick_code",
            tipo_acceso: "partido"
        });

        await doc.ref.update({
            last_login_method: "quick_code",
            last_quick_login_at: nowTimestamp(),
            last_ip: ip,
            last_user_agent: userAgent
        });

        return res.json({
            success: true,
            customToken,
            expires_at: expiraMillis
        });

    } catch (error) {
        console.error("❌ Error en /auth/quick-login:", error);

        return res.status(500).json({
            success: false,
            code: "SERVER_ERROR",
            error: "Error del servidor."
        });
    }
});

// --- 12. GENERATE STREAM OPTIMIZADO + SELECTOR BUNNY/EXTERNAL ---
app.get('/generate-stream', streamLimiter, async (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                code: "NO_AUTH"
            });
        }

        const idToken = authHeader.replace("Bearer ", "").trim();

        let decodedToken;
        try {
            decodedToken = await auth.verifyIdToken(idToken);
        } catch (authError) {
            return res.status(401).json({
                success: false,
                code: "INVALID_AUTH"
            });
        }

        const uid = decodedToken.uid;
        const requestedSessionId = normalizeClientId(req.query.session_id);
        const deviceId = normalizeClientId(req.query.device_id);
        const pageId = normalizeClientId(req.query.page_id);
        const takeoverRequested = req.query.takeover === "1";
        const forceConfigRefresh = req.query.refresh_config === "1";

        const userRef = db.collection('usuarios').doc(uid);
        const ahora = Date.now();
        const { ip, userAgent } = getClientData(req);

        let decision;

        await db.runTransaction(async transaction => {
            const userDoc = await transaction.get(userRef);

            if (!userDoc.exists) {
                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "PASS_INACTIVE"
                    }
                };
                return;
            }

            const userData = userDoc.data() || {};

            if (!userData.fecha_expiracion || typeof userData.fecha_expiracion.toMillis !== "function") {
                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "NO_EXPIRATION"
                    }
                };
                return;
            }

            const expiraMillis = userData.fecha_expiracion.toMillis();
            const segundosRestantesPase = Math.floor((expiraMillis - ahora) / 1000);

            if (segundosRestantesPase <= 0) {
                transaction.update(userRef, {
                    last_status: "expired",
                    last_heartbeat: nowTimestamp(),
                    last_ip: ip,
                    last_user_agent: userAgent
                });

                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "PASS_EXPIRED",
                        error: "Pase expirado"
                    }
                };
                return;
            }

            if (
                userData.last_status === "revoked_by_admin" ||
                String(userData.session_id || "").startsWith("revoked_")
            ) {
                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "SESSION_REVOKED",
                        error: "Sesión revocada por administración"
                    }
                };
                return;
            }

            const lastHeartbeatMillis = getTimestampMillis(userData.last_heartbeat);
            const sesionActivaReciente = Boolean(
                userData.session_id &&
                !String(userData.session_id).startsWith("revoked_") &&
                userData.last_status !== "expired" &&
                userData.last_status !== "revoked_by_admin" &&
                lastHeartbeatMillis &&
                ahora - lastHeartbeatMillis < ACTIVE_SESSION_WINDOW_MS
            );

            const mismaSesion = Boolean(
                requestedSessionId && requestedSessionId === userData.session_id
            );

            // Caso clave anti-409:
            // Si el navegador dispara dos generate-stream casi juntos, el segundo
            // puede llegar sin session_id porque el frontend aún no alcanzó a guardarlo.
            // Si viene del mismo device_id y el mismo page_id activos, se trata como
            // la misma página y se devuelve la sesión existente, no un 409.
            const mismaPaginaActiva = Boolean(
                !requestedSessionId &&
                sesionActivaReciente &&
                deviceId &&
                pageId &&
                userData.active_device_id === deviceId &&
                userData.active_page_id === pageId
            );

            const sesionReutilizable = mismaSesion || mismaPaginaActiva;

            // Un session_id inventado, antiguo o una página distinta no debe saltarse
            // el bloqueo, salvo que el usuario pulse CONTINUAR AQUÍ / takeover=1.
            if (sesionActivaReciente && !sesionReutilizable && !takeoverRequested) {
                decision = {
                    ok: false,
                    status: 409,
                    body: {
                        success: false,
                        code: "SESSION_ALREADY_ACTIVE",
                        error: "Ya existe una sesión activa para este usuario.",
                        can_takeover: true
                    }
                };
                return;
            }

            let sessionIdFinal = userData.session_id || "";
            let createdNewSession = false;

            if (!sesionReutilizable) {
                sessionIdFinal = crypto.randomUUID();
                createdNewSession = true;

                transaction.update(userRef, {
                    session_id: sessionIdFinal,
                    session_started_at: nowTimestamp(),
                    last_heartbeat: nowTimestamp(),
                    last_status: takeoverRequested ? "stream_takeover" : "stream_started",
                    last_ip: ip,
                    last_user_agent: userAgent,
                    active_device_id: deviceId,
                    active_page_id: pageId,
                    last_takeover_at: takeoverRequested ? nowTimestamp() : null
                });
            } else {
                const sessionPatch = {};

                // Actualizar page_id en cada carga evita que el cierre de una página
                // anterior libere accidentalmente una sesión recién reanudada.
                if (pageId && pageId !== userData.active_page_id) {
                    sessionPatch.active_page_id = pageId;
                }

                if (deviceId && deviceId !== userData.active_device_id) {
                    sessionPatch.active_device_id = deviceId;
                }

                if (shouldWriteHeartbeat(userData, ahora)) {
                    sessionPatch.last_heartbeat = nowTimestamp();
                    sessionPatch.last_status = mismaPaginaActiva
                        ? "stream_reattached"
                        : "stream_renewed";
                    sessionPatch.last_ip = ip;
                    sessionPatch.last_user_agent = userAgent;
                }

                if (Object.keys(sessionPatch).length) {
                    transaction.update(userRef, sessionPatch);
                }
            }

            decision = {
                ok: true,
                sessionIdFinal,
                expiraMillis,
                segundosRestantesPase,
                reusedSession: sesionReutilizable,
                reattachedSamePage: mismaPaginaActiva,
                takeoverApplied: takeoverRequested && createdNewSession,
                createdNewSession
            };
        });

        if (!decision || !decision.ok) {
            const status = decision?.status || 500;
            const body = decision?.body || {
                success: false,
                code: "SERVER_ERROR"
            };
            return res.status(status).json(body);
        }

        const tokenDuration = Math.min(
            BUNNY_TOKEN_DURATION_SECONDS,
            decision.segundosRestantesPase
        );

        // Catálogo dinámico para los clientes nuevos. También se mantienen los
        // campos legacy hasta terminar la migración de en-directo.html y tv.html.
        const streamConfig = await getActiveStreamConfig(forceConfigRefresh);
        const playbackCatalog = materializeTransmissionCatalog(
            streamConfig,
            tokenDuration
        );
        const signed = generateBunnyTokenForStream(
            STREAM_PATH,
            BUNNY_SECURITY_KEY,
            tokenDuration
        );
        const sources = {
            iframe: {
                type: "iframe",
                url: streamConfig.iframe_url
            },
            external: {
                type: "hls",
                url: streamConfig.external_url
            },
            bunny: {
                type: "hls",
                url: signed.url
            }
        };
        const fallbackOrder = normalizeFallbackOrder(
            streamConfig.fallback_order,
            streamConfig.active_source
        );
        const legacyHlsSource = fallbackOrder.find((source) => sources[source]?.type === "hls") || "bunny";
        const finalUrl = sources[legacyHlsSource].url;
        const bunnyExpires = signed.expires;

        console.log(
            `✅ Stream [${decision.reusedSession ? 'RENOVADO' : 'NUEVO'}] | uid=${uid} | transmisiones=${playbackCatalog.transmissions.length} | legacy=${legacyHlsSource} | duration=${tokenDuration}s | reattach=${decision.reattachedSamePage ? '1' : '0'} | takeover=${decision.takeoverApplied ? '1' : '0'}`
        );

        res.set('X-Stream-Config-Version', streamConfig.version);

        return res.json({
            success: true,
            stream_url: finalUrl,
            stream_source: legacyHlsSource,
            primary_source: streamConfig.active_source,
            fallback_order: fallbackOrder,
            sources,
            schema_version: 2,
            transmissions: playbackCatalog.transmissions,
            default_transmission_id: playbackCatalog.default_transmission_id,
            stream_config_version: streamConfig.version,
            session_id: decision.sessionIdFinal,
            reused_session: decision.reusedSession,
            reattached_same_page: decision.reattachedSamePage,
            takeover: decision.takeoverApplied,
            bunny_expires: bunnyExpires,
            pase_expira: decision.expiraMillis
        });

    } catch (error) {
        console.error("❌ Error en /generate-stream:", error);

        return res.status(500).json({
            success: false,
            code: "SERVER_ERROR"
        });
    }
});

// Libera únicamente la página que creó el bloqueo. Acepta el ID token en el
// body para que pagehide pueda usar navigator.sendBeacon en TVs y móviles.
app.post('/release-session', streamLimiter, async (req, res) => {
    try {
        const decodedToken = await verifyUserRequest(req);

        if (!decodedToken) {
            return res.status(401).json({ success: false, code: "NO_AUTH" });
        }

        const sessionId = normalizeClientId(req.body?.session_id);
        const pageId = normalizeClientId(req.body?.page_id);

        if (!sessionId || !pageId) {
            return res.status(400).json({ success: false, code: "INVALID_RELEASE" });
        }

        const userRef = db.collection('usuarios').doc(decodedToken.uid);
        let released = false;

        await db.runTransaction(async transaction => {
            const snap = await transaction.get(userRef);
            if (!snap.exists) return;

            const data = snap.data();

            if (data.session_id !== sessionId || data.active_page_id !== pageId) {
                return;
            }

            transaction.update(userRef, {
                session_id: "",
                active_device_id: "",
                active_page_id: "",
                last_status: "released",
                session_released_at: nowTimestamp()
            });

            released = true;
        });

        return res.json({ success: true, released });

    } catch (error) {
        console.error("Error en /release-session:", error);
        return res.status(500).json({ success: false, code: "SERVER_ERROR" });
    }
});

// --- 13. CHECK SESSION OPTIMIZADO ---
app.post('/check-session', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                valid: false,
                motivo: "no_auth"
            });
        }

        const idToken = authHeader.replace("Bearer ", "").trim();

        let decodedToken;
        try {
            decodedToken = await auth.verifyIdToken(idToken);
        } catch (e) {
            return res.status(401).json({
                valid: false,
                motivo: "no_auth"
            });
        }

        const sessionId = normalizeClientId(req.body?.session_id);
        const pageId = normalizeClientId(req.body?.page_id);

        if (!sessionId) {
            return res.status(400).json({
                valid: false,
                motivo: "missing_session"
            });
        }

        const uid = decodedToken.uid;

        const userRef = db.collection('usuarios').doc(uid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(403).json({
                valid: false,
                motivo: "pase_inactivo"
            });
        }

        const userData = userDoc.data();

        if (!userData.fecha_expiracion) {
            return res.status(403).json({
                valid: false,
                motivo: "pase_sin_expiracion"
            });
        }

        const expiraMillis = userData.fecha_expiracion.toMillis();
        const ahora = Date.now();

        const { ip, userAgent } = getClientData(req);

        if (expiraMillis <= ahora) {
            await userRef.update({
                last_heartbeat: nowTimestamp(),
                last_status: "expired",
                last_ip: ip,
                last_user_agent: userAgent
            });

            return res.json({
                valid: false,
                motivo: "expirado"
            });
        }

        if (
            userData.last_status === "revoked_by_admin" ||
            String(userData.session_id || "").startsWith("revoked_")
        ) {
            await userRef.update({
                last_heartbeat: nowTimestamp(),
                last_status: "revoked_by_admin",
                last_ip: ip,
                last_user_agent: userAgent
            });

            return res.json({
                valid: false,
                motivo: "revocado"
            });
        }

        if (
            sessionId !== userData.session_id ||
            (userData.active_page_id && pageId && pageId !== userData.active_page_id)
        ) {
            return res.json({
                valid: false,
                motivo: "pirateria"
            });
        }

        if (shouldWriteHeartbeat(userData, ahora)) {
            await userRef.update({
                last_heartbeat: nowTimestamp(),
                last_status: "active",
                last_ip: ip,
                last_user_agent: userAgent
            });
        }

        const streamConfig = await getActiveStreamConfig();

        res.set('X-Stream-Config-Version', streamConfig.version);

        return res.json({
            valid: true,
            motivo: "ok",
            pase_expira: expiraMillis,
            default_transmission_id: streamConfig.default_transmission_id,
            stream_config_version: streamConfig.version
        });

    } catch (e) {
        console.error("❌ Error en /check-session:", e);

        return res.status(500).json({
            valid: false,
            motivo: "server_error"
        });
    }
});

// --- 14. PANEL ADMIN: GENERAR PASE ---
app.post('/admin/generar-pase-rapido', createPassLimiter, verifyAdmin, async (req, res) => {
    const { partido, email_manual, pass_manual, fecha_corte } = req.body;

    try {
        if (!partido) {
            return res.status(400).json({
                success: false,
                code: "MISSING_MATCH",
                message: "Falta el partido o etiqueta del pase."
            });
        }

        const exp = fecha_corte
            ? new Date(fecha_corte)
            : new Date(Date.now() + 24 * 60 * 60 * 1000);

        if (Number.isNaN(exp.getTime())) {
            return res.status(400).json({
                success: false,
                code: "INVALID_DATE",
                message: "Fecha de corte inválida."
            });
        }

        const esSocioVip = Boolean(email_manual);

        if (esSocioVip) {
            const emailFinal = String(email_manual).trim().toLowerCase();

            if (!emailFinal.includes("@")) {
                return res.status(400).json({
                    success: false,
                    code: "INVALID_EMAIL",
                    message: "Email VIP inválido."
                });
            }

            const claveFinal = pass_manual || Math.floor(100000 + Math.random() * 900000).toString();

            const userRecord = await auth.createUser({
                email: emailFinal,
                password: claveFinal,
                displayName: partido
            });

            await db.collection('usuarios').doc(userRecord.uid).set({
                uid: userRecord.uid,
                usuario_corto: emailFinal,
                etiqueta: partido,
                tipo_acceso: "vip",
                login_mode: "email_password",
                event_id: null,
                event_name: partido,
                fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
                creado_el: nowTimestamp(),
                session_id: "",
                extension_count: 0,
                extension_history: [],
                password_stored: false,
                last_status: "created"
            });

            return res.json({
                success: true,
                tipo_acceso: "vip",
                usuario: emailFinal,
                clave: claveFinal
            });
        }

        let userRecord = null;
        let codigo = null;
        let codeHash = null;
        let emailFinal = null;
        let claveInterna = null;

        for (let intento = 0; intento < 20; intento++) {
            const generado = await generarCodigoRapidoUnico();

            codigo = generado.codigo;
            codeHash = generado.hash;
            emailFinal = `${codigo}@golazosp.net`;
            claveInterna = generarPasswordInternoSeguro();

            try {
                userRecord = await auth.createUser({
                    email: emailFinal,
                    password: claveInterna,
                    displayName: partido
                });

                break;

            } catch (e) {
                if (e.code === "auth/email-already-exists") {
                    continue;
                }

                throw e;
            }
        }

        if (!userRecord) {
            throw new Error("No se pudo crear usuario para código rápido.");
        }

        const linkRapido = `${APP_BASE_URL}/?c=${encodeURIComponent(codigo)}`;
        const eventId = buildEventId(partido, exp);
        const eventDateKey = formatPeruDateKey(exp);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            etiqueta: partido,
            tipo_acceso: "partido",
            login_mode: "quick_code",
            event_id: eventId,
            event_name: partido,
            event_date_key: eventDateKey,
            quick_code_hash: codeHash,
            quick_code_created_at: nowTimestamp(),
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: nowTimestamp(),
            session_id: "",
            extension_count: 0,
            extension_history: [],
            password_stored: false,
            last_status: "created"
        });

        return res.json({
            success: true,
            tipo_acceso: "partido",
            codigo,
            link_rapido: linkRapido,
            usuario: emailFinal,
            clave: null
        });

    } catch (e) {
        console.error("❌ Error creando pase:", e);

        return res.status(500).json({
            success: false,
            code: "CREATE_PASS_ERROR",
            message: e.message
        });
    }
});

// --- 15. PANEL ADMIN: REVOCAR SESIÓN MANUALMENTE ---
app.post('/admin/revocar-sesion', adminLimiter, verifyAdmin, async (req, res) => {
    const { uid } = req.body;

    if (!uid) {
        return res.status(400).json({
            success: false,
            message: "Falta UID"
        });
    }

    try {
        await db.collection('usuarios').doc(uid).update({
            session_id: "revoked_" + Date.now(),
            last_status: "revoked_by_admin",
            last_heartbeat: nowTimestamp()
        });

        return res.json({
            success: true,
            message: "Sesión revocada exitosamente. El usuario será expulsado pronto."
        });

    } catch (e) {
        console.error("❌ Error revocando sesión:", e);

        return res.status(500).json({
            success: false,
            message: "Error al revocar sesión"
        });
    }
});

// --- 15.1 PANEL ADMIN: VER CONFIG STREAM ---
app.post('/admin/ver-config-stream', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const config = await getActiveStreamConfig();

        return res.json({
            success: true,
            config,
            cache_ttl_ms: STREAM_CONFIG_CACHE_TTL_MS
        });

    } catch (e) {
        console.error("❌ Error viendo config stream:", e);

        return res.status(500).json({
            success: false,
            message: "Error viendo config stream."
        });
    }
});

// --- 15.2 PANEL ADMIN: ACTUALIZAR CONFIG STREAM ---
app.post('/admin/actualizar-config-stream', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const currentConfig = await getActiveStreamConfig();

        if (Array.isArray(req.body?.transmissions)) {
            const normalizedCatalog = normalizeTransmissionCatalog(
                req.body.transmissions,
                true
            );

            if (normalizedCatalog.errors.length) {
                return res.status(400).json({
                    success: false,
                    code: "INVALID_TRANSMISSION_CATALOG",
                    message: normalizedCatalog.errors[0],
                    errors: normalizedCatalog.errors
                });
            }

            const publicTransmissions = normalizedCatalog.transmissions.filter(
                transmission =>
                    transmission.visible &&
                    transmission.options.some(option => option.enabled)
            );
            const requestedDefaultId = normalizeCatalogId(
                req.body.default_transmission_id
            );
            const defaultTransmission = publicTransmissions.find(
                transmission => transmission.id === requestedDefaultId
            ) || publicTransmissions[0] || null;

            const payload = {
                schema_version: 2,
                transmissions: normalizedCatalog.transmissions,
                default_transmission_id: defaultTransmission?.id || "",
                updated_at: nowTimestamp()
            };

            await db.collection("config").doc("stream").set(payload, { merge: true });

            cachedStreamConfig = null;
            cachedStreamConfigExpiresAt = 0;

            const savedConfig = await getActiveStreamConfig(true);

            console.log(
                `✅ Catálogo actualizado | versión ${currentConfig.version || 'inicial'} -> ${savedConfig.version}`
            );

            return res.json({
                success: true,
                message: `${publicTransmissions.length} transmisión(es) activa(s).`,
                previous_stream_config_version: currentConfig.version || "",
                stream_config_version: savedConfig.version,
                config: savedConfig
            });
        }

        const activeSource = normalizeStreamSource(
            req.body?.active_source || currentConfig.active_source
        );
        const externalUrl = String(
            req.body?.external_url || currentConfig.external_url || EXTERNAL_STREAM_URL_DEFAULT
        ).trim();
        const iframeUrl = String(
            req.body?.iframe_url || currentConfig.iframe_url || IFRAME_PLAYER_URL_DEFAULT
        ).trim();
        const fallbackOrder = normalizeFallbackOrder(
            req.body?.fallback_order || currentConfig.fallback_order,
            activeSource
        );

        if (!isValidHttpUrl(externalUrl)) {
            return res.status(400).json({
                success: false,
                message: "external_url inválida."
            });
        }

        if (!isValidHttpUrl(iframeUrl)) {
            return res.status(400).json({
                success: false,
                message: "iframe_url inválida."
            });
        }

        const payload = {
            active_source: activeSource,
            external_url: externalUrl,
            iframe_url: iframeUrl,
            fallback_order: fallbackOrder,
            updated_at: nowTimestamp()
        };

        await db.collection("config").doc("stream").set(payload, { merge: true });

        cachedStreamConfig = null;
        cachedStreamConfigExpiresAt = 0;

        return res.json({
            success: true,
            message: `Fuente de stream actualizada a: ${activeSource}`,
            config: payload
        });

    } catch (e) {
        console.error("❌ Error actualizando config stream:", e);

        return res.status(500).json({
            success: false,
            message: "Error actualizando config stream."
        });
    }
});

// --- 16. PANEL ADMIN: LIMPIAR CADUCADOS + ARCHIVO HISTÓRICO ---
app.post('/admin/limpiar-caducados', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const ahora = nowTimestamp();

        const vencidosSnap = await db.collection('usuarios')
            .where('fecha_expiracion', '<', ahora)
            .get();

        if (vencidosSnap.empty) {
            return res.json({
                success: true,
                mensaje: "✅ No hay usuarios vencidos."
            });
        }

        let borrados = 0;
        let archivados = 0;
        let errores = 0;

        for (const doc of vencidosSnap.docs) {
            try {
                const data = doc.data() || {};

                // Se conserva solo información operativa útil. No se archivan
                // códigos hash, session_id, IP ni user-agent completo.
                await db.collection('historial_accesos').doc(doc.id).set({
                    uid: data.uid || doc.id,
                    usuario_corto: data.usuario_corto || "-",
                    etiqueta: data.etiqueta || "-",
                    tipo_acceso: data.tipo_acceso || "manual",
                    login_mode: data.login_mode || "-",
                    event_id: data.event_id || getUserEventId(data),
                    event_name: data.event_name || data.etiqueta || "-",
                    event_date_key: data.event_date_key || null,
                    fecha_expiracion: data.fecha_expiracion || null,
                    creado_el: data.creado_el || null,
                    last_status: data.last_status || "-",
                    last_connection_at: data.last_heartbeat || null,
                    tuvo_ingreso: !userNeverEntered(data),
                    dispositivo: summarizeUserAgent(data.last_user_agent || "Sin registro"),
                    extension_count: Number(data.extension_count || 0),
                    extension_history: Array.isArray(data.extension_history) ? data.extension_history.slice(-20) : [],
                    last_extension_at: data.last_extension_at || null,
                    last_extension_minutes: Number.isFinite(Number(data.last_extension_minutes))
                        ? Number(data.last_extension_minutes)
                        : null,
                    archivado_el: nowTimestamp(),
                    archive_reason: "expired_cleanup"
                }, { merge: true });
                archivados++;

                try {
                    await auth.deleteUser(doc.id);
                } catch (authError) {
                    if (authError.code !== 'auth/user-not-found') throw authError;
                }

                await doc.ref.delete();
                borrados++;
            } catch (err) {
                errores++;
                console.error("❌ Error archivando/borrando usuario vencido:", doc.id, err.message);
            }
        }

        return res.json({
            success: true,
            mensaje: `🧹 ${borrados} pases eliminados · ${archivados} archivados${errores ? ` · ${errores} con error` : ''}.`,
            borrados,
            archivados,
            errores
        });

    } catch (e) {
        console.error("❌ Error limpiando caducados:", e);

        return res.status(500).json({
            success: false,
            mensaje: "Error al limpiar usuarios caducados."
        });
    }
});

// --- 17. GESTIÓN ADMINISTRATIVA DE ACCESOS ---
app.post('/admin/extender-accesos', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const rawUids = Array.isArray(req.body?.uids) ? req.body.uids : [];
        const uids = [...new Set(rawUids.map(uid => String(uid || '').trim()).filter(Boolean))];
        const mode = req.body?.mode === 'set' ? 'set' : 'add';
        const minutes = Number(req.body?.minutes);
        const newLabel = normalizeDisplayText(req.body?.new_label || '', 80);
        const requestedExpiration = req.body?.new_expiration ? new Date(req.body.new_expiration) : null;

        if (!uids.length || uids.length > 300) {
            return res.status(400).json({
                success: false,
                message: "Selecciona entre 1 y 300 usuarios."
            });
        }

        if (mode === 'add' && (!Number.isFinite(minutes) || minutes < 1 || minutes > 10080)) {
            return res.status(400).json({
                success: false,
                message: "Los minutos deben estar entre 1 y 10080."
            });
        }

        if (mode === 'set' && (!requestedExpiration || Number.isNaN(requestedExpiration.getTime()) || requestedExpiration.getTime() <= Date.now())) {
            return res.status(400).json({
                success: false,
                message: "La nueva fecha de expiración debe ser futura y válida."
            });
        }

        const refs = uids.map(uid => db.collection('usuarios').doc(uid));
        const snaps = await db.getAll(...refs);
        const batch = db.batch();
        const nowMillis = Date.now();
        const extensionAt = nowTimestamp();
        const results = [];
        let updated = 0;

        snaps.forEach((snap, index) => {
            if (!snap.exists) {
                results.push({ uid: uids[index], success: false, reason: 'not_found' });
                return;
            }

            const data = snap.data() || {};
            const currentExpirationMillis = getTimestampMillis(data.fecha_expiracion);
            const targetMillis = mode === 'set'
                ? requestedExpiration.getTime()
                : Math.max(currentExpirationMillis || 0, nowMillis) + Math.round(minutes * 60 * 1000);

            const targetExpiration = admin.firestore.Timestamp.fromMillis(targetMillis);
            const previousLabel = normalizeDisplayText(data.etiqueta || "Sin etiqueta", 80);
            const targetLabel = newLabel || previousLabel;
            const labelChanged = Boolean(newLabel && newLabel !== previousLabel);
            const targetEventId = labelChanged
                ? buildEventId(targetLabel, new Date(targetMillis))
                : (data.event_id || getUserEventId(data));

            const history = Array.isArray(data.extension_history)
                ? data.extension_history.slice(-19)
                : [];

            history.push({
                at: extensionAt,
                mode,
                minutes: mode === 'add' ? Math.round(minutes) : null,
                old_expiration: currentExpirationMillis
                    ? admin.firestore.Timestamp.fromMillis(currentExpirationMillis)
                    : null,
                new_expiration: targetExpiration,
                old_label: previousLabel,
                new_label: targetLabel
            });

            const patch = {
                fecha_expiracion: targetExpiration,
                etiqueta: targetLabel,
                event_name: targetLabel,
                event_id: targetEventId,
                event_date_key: formatPeruDateKey(new Date(targetMillis)),
                extension_count: Number(data.extension_count || 0) + 1,
                extension_history: history,
                last_extension_at: extensionAt,
                last_extension_minutes: mode === 'add' ? Math.round(minutes) : null
            };

            if (data.last_status === 'expired') {
                patch.last_status = 'extended';
                patch.session_id = '';
                patch.active_device_id = '';
                patch.active_page_id = '';
            }

            batch.update(refs[index], patch);
            updated++;
            results.push({
                uid: uids[index],
                success: true,
                new_expiration_ms: targetMillis,
                etiqueta: targetLabel
            });
        });

        if (updated) await batch.commit();

        return res.json({
            success: true,
            updated,
            requested: uids.length,
            results,
            message: `✅ ${updated} acceso(s) extendido(s).`
        });

    } catch (e) {
        console.error("❌ Error extendiendo accesos:", e);
        return res.status(500).json({
            success: false,
            message: "Error extendiendo accesos."
        });
    }
});

app.post('/admin/revocar-multiples', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const rawUids = Array.isArray(req.body?.uids) ? req.body.uids : [];
        const uids = [...new Set(rawUids.map(uid => String(uid || '').trim()).filter(Boolean))];

        if (!uids.length || uids.length > 300) {
            return res.status(400).json({
                success: false,
                message: "Selecciona entre 1 y 300 usuarios."
            });
        }

        const refs = uids.map(uid => db.collection('usuarios').doc(uid));
        const snaps = await db.getAll(...refs);
        const batch = db.batch();
        let updated = 0;
        const revokedAt = nowTimestamp();

        snaps.forEach((snap, index) => {
            if (!snap.exists) return;
            batch.update(refs[index], {
                session_id: "revoked_" + Date.now() + "_" + index,
                last_status: "revoked_by_admin",
                last_heartbeat: revokedAt
            });
            updated++;
        });

        if (updated) await batch.commit();

        return res.json({
            success: true,
            updated,
            message: `✅ ${updated} sesión(es) revocada(s).`
        });
    } catch (e) {
        console.error("❌ Error revocando múltiples sesiones:", e);
        return res.status(500).json({
            success: false,
            message: "Error revocando sesiones."
        });
    }
});

app.post('/admin/historial-usuario', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const uid = String(req.body?.uid || '').trim();
        if (!uid) {
            return res.status(400).json({ success: false, message: "Falta UID." });
        }

        let snap = await db.collection('usuarios').doc(uid).get();
        let archived = false;

        if (!snap.exists) {
            snap = await db.collection('historial_accesos').doc(uid).get();
            archived = true;
        }

        if (!snap.exists) {
            return res.status(404).json({ success: false, message: "Usuario no encontrado." });
        }

        const data = snap.data() || {};
        return res.json({
            success: true,
            archived,
            usuario: {
                uid: data.uid || uid,
                usuario_corto: data.usuario_corto || "-",
                etiqueta: data.etiqueta || "-",
                tipo_acceso: data.tipo_acceso || "manual",
                creado_ms: getTimestampMillis(data.creado_el),
                expira_ms: getTimestampMillis(data.fecha_expiracion),
                extension_count: Number(data.extension_count || 0),
                extension_history: serializeExtensionHistory(data.extension_history)
            }
        });
    } catch (e) {
        console.error("❌ Error consultando historial de usuario:", e);
        return res.status(500).json({ success: false, message: "Error consultando historial." });
    }
});

app.post('/admin/listar-historial', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const snap = await db.collection('historial_accesos')
            .orderBy('archivado_el', 'desc')
            .limit(100)
            .get();

        const items = snap.docs.map(doc => {
            const data = doc.data() || {};
            return {
                uid: data.uid || doc.id,
                usuario_corto: data.usuario_corto || "-",
                etiqueta: data.etiqueta || "-",
                tipo_acceso: data.tipo_acceso || "manual",
                creado_ms: getTimestampMillis(data.creado_el),
                expira_ms: getTimestampMillis(data.fecha_expiracion),
                archivado_ms: getTimestampMillis(data.archivado_el),
                extension_count: Number(data.extension_count || 0),
                last_status: data.last_status || "-"
            };
        });

        return res.json({ success: true, items });
    } catch (e) {
        console.error("❌ Error listando historial archivado:", e);
        return res.status(500).json({ success: false, message: "Error cargando historial archivado." });
    }
});

// --- 17.1 PANEL ADMIN: LISTAR USUARIOS + DASHBOARD EN VIVO ---
app.post('/admin/listar-usuarios', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const snap = await db.collection('usuarios')
            .orderBy('creado_el', 'desc')
            .get();

        const now = Date.now();
        const resumen = {
            total: 0,
            vigentes: 0,
            viendo_ahora: 0,
            desconectados: 0,
            vencidos: 0,
            revocados: 0,
            nunca_ingresaron: 0,
            pases_rapidos: 0,
            vip: 0,
            dispositivos: {}
        };

        const eventMap = new Map();

        const usuariosFormateados = snap.docs.map(d => {
            const data = d.data() || {};
            const expiraMillis = getTimestampMillis(data.fecha_expiracion);
            const fechaVigente = Boolean(expiraMillis && expiraMillis > now);
            const revocado = isRevokedUser(data);
            const esActivo = fechaVigente && !revocado;
            const viendoAhora = isUserWatchingNow(data, now);
            const nuncaIngreso = userNeverEntered(data);
            const tipoAcceso = data.tipo_acceso || (data.login_mode === "quick_code" ? "partido" : "manual");
            const dispositivo = summarizeUserAgent(data.last_user_agent || "Sin registro");
            const eventId = getUserEventId(data);

            resumen.total++;
            if (esActivo) resumen.vigentes++;
            if (!fechaVigente) resumen.vencidos++;
            if (revocado) resumen.revocados++;
            if (viendoAhora) resumen.viendo_ahora++;
            if (esActivo && !viendoAhora) resumen.desconectados++;
            if (nuncaIngreso) resumen.nunca_ingresaron++;
            if (tipoAcceso === 'partido' || data.login_mode === 'quick_code') resumen.pases_rapidos++;
            if (tipoAcceso === 'vip' || data.login_mode === 'email_password') resumen.vip++;

            if (viendoAhora) {
                resumen.dispositivos[dispositivo] = (resumen.dispositivos[dispositivo] || 0) + 1;
            }

            if (tipoAcceso === 'partido' || data.login_mode === 'quick_code') {
                if (!eventMap.has(eventId)) {
                    eventMap.set(eventId, {
                        event_id: eventId,
                        etiqueta: data.etiqueta || "Sin etiqueta",
                        total: 0,
                        vigentes: 0,
                        viendo_ahora: 0,
                        nunca_ingresaron: 0,
                        revocados: 0,
                        peak_concurrent: 0
                    });
                }

                const eventSummary = eventMap.get(eventId);
                eventSummary.total++;
                if (esActivo) eventSummary.vigentes++;
                if (viendoAhora) eventSummary.viendo_ahora++;
                if (nuncaIngreso) eventSummary.nunca_ingresaron++;
                if (revocado) eventSummary.revocados++;
            }

            let ultimaConexion = "-";
            if (data.last_heartbeat) {
                ultimaConexion = new Date(data.last_heartbeat.toMillis()).toLocaleTimeString('es-PE', {
                    timeZone: 'America/Lima'
                });
            }

            let estado = 'VENCIDO';
            if (revocado) estado = 'REVOCADO';
            else if (esActivo) estado = viendoAhora ? 'EN VIVO' : 'ACTIVO';

            return {
                uid: data.uid || d.id,
                usuario_corto: data.usuario_corto || "-",
                codigo: String(data.usuario_corto || '').split('@')[0] || "-",
                etiqueta: data.etiqueta || "-",
                event_id: eventId,
                tipo_acceso: tipoAcceso,
                login_mode: data.login_mode || "-",
                tiene_codigo_rapido: Boolean(data.quick_code_hash),
                estado,
                esActivo,
                fecha_vigente: fechaVigente,
                revocado,
                viendo_ahora: viendoAhora,
                nunca_ingreso: nuncaIngreso,
                dispositivo,
                expira_ms: expiraMillis,
                creado_ms: getTimestampMillis(data.creado_el),
                last_heartbeat_ms: getTimestampMillis(data.last_heartbeat),
                tiempo: expiraMillis ? new Date(expiraMillis).toLocaleString('es-PE', {
                    timeZone: 'America/Lima',
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true
                }) : "-",
                ultima_conexion: ultimaConexion,
                last_status: data.last_status || "-",
                last_ip: data.last_ip || "Sin registro",
                last_user_agent: data.last_user_agent || "Sin registro",
                password_stored: data.password_stored === false ? false : true,
                extension_count: Number(data.extension_count || 0),
                last_extension_ms: getTimestampMillis(data.last_extension_at),
                last_extension_minutes: Number.isFinite(Number(data.last_extension_minutes))
                    ? Number(data.last_extension_minutes)
                    : null
            };
        });

        const eventos = await syncEventPeaks([...eventMap.values()]);
        eventos.sort((a, b) => b.vigentes - a.vigentes || b.total - a.total);

        return res.json({
            success: true,
            usuarios: usuariosFormateados,
            resumen,
            eventos,
            active_session_window_ms: ACTIVE_SESSION_WINDOW_MS,
            generated_at: now
        });

    } catch (e) {
        console.error("❌ Error listando usuarios:", e);

        return res.status(500).json({
            success: false,
            message: "Error listando usuarios."
        });
    }
});

// --- 18. START SERVER ---
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 GOLAZO SECURE STREAM READY (FASE 10.4: GESTION DE ACCESOS Y ANALITICA)`);
});
