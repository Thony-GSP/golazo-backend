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

// --- 3. RATE LIMITS CONFIGURABLES ---
const GENERAL_RATE_LIMIT_MAX = parseInt(process.env.GENERAL_RATE_LIMIT_MAX || "120", 10);
const STREAM_RATE_LIMIT_MAX = parseInt(process.env.STREAM_RATE_LIMIT_MAX || "30", 10);
const ADMIN_RATE_LIMIT_MAX = parseInt(process.env.ADMIN_RATE_LIMIT_MAX || "20", 10);
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

// ✅ NUEVO: selector de fuente de stream.
// Valores permitidos:
// bunny    = usa Bunny CDN con token firmado.
// external = usa la señal directa de live.site.pe.
const STREAM_MODE_DEFAULT = String(process.env.STREAM_MODE || "bunny").trim().toLowerCase();
const EXTERNAL_STREAM_URL_DEFAULT = String(
    process.env.EXTERNAL_STREAM_URL || "https://live.site.pe/live/golazosp.m3u8"
).trim();

// Cache para no leer Firestore en cada /generate-stream.
const STREAM_CONFIG_CACHE_TTL_MS = parseInt(
    process.env.STREAM_CONFIG_CACHE_TTL_MS || "15000",
    10
);

let cachedStreamConfig = null;
let cachedStreamConfigExpiresAt = 0;

// 🔐 Código rápido
const QUICK_CODE_SECRET = (process.env.QUICK_CODE_SECRET || process.env.BUNNY_KEY || "").trim();

// 🌐 URL pública de la web para generar links rápidos
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
        version: "FASE 9 - selector Bunny / External Stream",
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

function normalizeStreamSource(value) {
    const source = String(value || "").trim().toLowerCase();

    if (source === "external") return "external";
    if (source === "bunny") return "bunny";

    return "bunny";
}

function isValidHttpUrl(value) {
    try {
        const url = new URL(String(value || "").trim());
        return url.protocol === "http:" || url.protocol === "https:";
    } catch (_) {
        return false;
    }
}

// ✅ NUEVO: lee la fuente activa desde Firestore.
// Ruta Firestore recomendada:
// collection: config
// document: stream
//
// Ejemplo external:
// {
//   active_source: "external",
//   external_url: "https://live.site.pe/live/golazosp.m3u8"
// }
//
// Ejemplo bunny:
// {
//   active_source: "bunny",
//   external_url: "https://live.site.pe/live/golazosp.m3u8"
// }
async function getActiveStreamConfig() {
    const now = Date.now();

    if (cachedStreamConfig && now < cachedStreamConfigExpiresAt) {
        return cachedStreamConfig;
    }

    let config = {
        active_source: normalizeStreamSource(STREAM_MODE_DEFAULT),
        external_url: EXTERNAL_STREAM_URL_DEFAULT
    };

    try {
        const doc = await db.collection("config").doc("stream").get();

        if (doc.exists) {
            const data = doc.data() || {};

            config = {
                active_source: normalizeStreamSource(data.active_source || STREAM_MODE_DEFAULT),
                external_url: String(data.external_url || EXTERNAL_STREAM_URL_DEFAULT).trim()
            };
        }

        if (config.active_source === "external" && !isValidHttpUrl(config.external_url)) {
            console.warn("⚠️ external_url inválida. Se usará Bunny como respaldo.");
            config.active_source = "bunny";
        }

        cachedStreamConfig = config;
        cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;

        return config;

    } catch (error) {
        console.error("❌ Error leyendo config stream desde Firestore:", error.message);

        cachedStreamConfig = config;
        cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;

        return config;
    }
}

// --- 7. GENERADOR DE TOKEN BUNNY PARA DIRECTORIOS (BUNNY TOKEN V2 HMAC-SHA256) ---
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
        const requestedSessionId = req.query.session_id || null;

        const userRef = db.collection('usuarios').doc(uid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(403).json({
                success: false,
                code: "PASS_INACTIVE"
            });
        }

        const userData = userDoc.data();

        if (!userData.fecha_expiracion) {
            return res.status(403).json({
                success: false,
                code: "NO_EXPIRATION"
            });
        }

        const ahora = Date.now();
        const expiraMillis = userData.fecha_expiracion.toMillis();
        const segundosRestantesPase = Math.floor((expiraMillis - ahora) / 1000);

        if (segundosRestantesPase <= 0) {
            return res.status(403).json({
                success: false,
                code: "PASS_EXPIRED",
                error: "Pase expirado"
            });
        }

        if (
            requestedSessionId &&
            (
                userData.last_status === "revoked_by_admin" ||
                String(userData.session_id || "").startsWith("revoked_")
            )
        ) {
            return res.status(403).json({
                success: false,
                code: "SESSION_REVOKED",
                error: "Sesión revocada por administración"
            });
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

        if (!requestedSessionId && sesionActivaReciente) {
            return res.status(409).json({
                success: false,
                code: "SESSION_ALREADY_ACTIVE",
                error: "Ya existe una sesión activa para este usuario."
            });
        }

        const { ip, userAgent } = getClientData(req);

        let sessionIdFinal = userData.session_id || "";
        const mismaSesion = Boolean(requestedSessionId && requestedSessionId === userData.session_id);

        if (!mismaSesion) {
            sessionIdFinal = crypto.randomUUID();

            await userRef.update({
                session_id: sessionIdFinal,
                session_started_at: nowTimestamp(),
                last_heartbeat: nowTimestamp(),
                last_status: "stream_started",
                last_ip: ip,
                last_user_agent: userAgent
            });

        } else {
            if (shouldWriteHeartbeat(userData, ahora)) {
                await userRef.update({
                    last_heartbeat: nowTimestamp(),
                    last_status: "stream_renewed",
                    last_ip: ip,
                    last_user_agent: userAgent
                });
            }
        }

        const tokenDuration = Math.min(BUNNY_TOKEN_DURATION_SECONDS, segundosRestantesPase);

        // ✅ NUEVO: aquí se decide si se devuelve Bunny o live.site.pe.
        const streamConfig = await getActiveStreamConfig();

        let finalUrl = "";
        let bunnyExpires = Math.floor(Date.now() / 1000) + tokenDuration;
        let streamSource = streamConfig.active_source;

        if (streamConfig.active_source === "external") {
            finalUrl = streamConfig.external_url;
        } else {
            const signed = generateBunnyTokenForStream(
                STREAM_PATH,
                BUNNY_SECURITY_KEY,
                tokenDuration
            );

            finalUrl = signed.url;
            bunnyExpires = signed.expires;
            streamSource = "bunny";
        }

        console.log(
            `✅ Stream [${mismaSesion ? 'RENOVADO' : 'NUEVO'}] | uid=${uid} | source=${streamSource} | duration=${tokenDuration}s`
        );

        return res.json({
            success: true,
            stream_url: finalUrl,
            stream_source: streamSource,
            session_id: sessionIdFinal,
            reused_session: mismaSesion,
            bunny_expires: bunnyExpires,
            pase_expira: expiraMillis
        });

    } catch (error) {
        console.error("❌ Error en /generate-stream:", error);

        return res.status(500).json({
            success: false,
            code: "SERVER_ERROR"
        });
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

        const { session_id } = req.body || {};

        if (!session_id) {
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

        if (session_id !== userData.session_id) {
            await userRef.update({
                last_heartbeat: nowTimestamp(),
                last_status: "replaced_session",
                last_ip: ip,
                last_user_agent: userAgent
            });

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

        return res.json({
            valid: true,
            motivo: "ok",
            pase_expira: expiraMillis
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
app.post('/admin/generar-pase-rapido', adminLimiter, verifyAdmin, async (req, res) => {
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
                fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
                creado_el: nowTimestamp(),
                session_id: "",
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

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            etiqueta: partido,
            tipo_acceso: "partido",
            login_mode: "quick_code",
            quick_code_hash: codeHash,
            quick_code_created_at: nowTimestamp(),
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: nowTimestamp(),
            session_id: "",
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
        const activeSource = normalizeStreamSource(req.body?.active_source);
        const externalUrl = String(req.body?.external_url || EXTERNAL_STREAM_URL_DEFAULT).trim();

        if (activeSource === "external" && !isValidHttpUrl(externalUrl)) {
            return res.status(400).json({
                success: false,
                message: "external_url inválida."
            });
        }

        const payload = {
            active_source: activeSource,
            external_url: externalUrl,
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

// --- 16. PANEL ADMIN: LIMPIAR CADUCADOS ---
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

        for (const doc of vencidosSnap.docs) {
            try {
                await auth.deleteUser(doc.id);
                await doc.ref.delete();
                borrados++;
            } catch (err) {
                console.error("❌ Error borrando usuario vencido:", doc.id, err.message);
            }
        }

        return res.json({
            success: true,
            mensaje: `🧹 ${borrados} pases vencidos eliminados.`
        });

    } catch (e) {
        console.error("❌ Error limpiando caducados:", e);

        return res.status(500).json({
            success: false,
            mensaje: "Error al limpiar usuarios caducados."
        });
    }
});

// --- 17. PANEL ADMIN: LISTAR USUARIOS ---
app.post('/admin/listar-usuarios', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const snap = await db.collection('usuarios')
            .orderBy('creado_el', 'desc')
            .get();

        const usuariosFormateados = snap.docs.map(d => {
            const data = d.data();
            const expiraMillis = data.fecha_expiracion.toMillis();
            const esActivo = expiraMillis > Date.now();

            let ultimaConexion = "-";

            if (data.last_heartbeat) {
                ultimaConexion = new Date(data.last_heartbeat.toMillis()).toLocaleTimeString('es-PE', {
                    timeZone: 'America/Lima'
                });
            }

            return {
                uid: data.uid || d.id,
                usuario_corto: data.usuario_corto || "-",
                etiqueta: data.etiqueta || "-",

                tipo_acceso: data.tipo_acceso || (
                    data.login_mode === "quick_code"
                        ? "partido"
                        : "manual"
                ),

                login_mode: data.login_mode || "-",
                tiene_codigo_rapido: Boolean(data.quick_code_hash),

                estado: esActivo ? 'ACTIVO' : 'VENCIDO',
                esActivo: esActivo,

                tiempo: new Date(expiraMillis).toLocaleString('es-PE', {
                    timeZone: 'America/Lima',
                    year: 'numeric',
                    month: '2-digit',
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: true
                }),

                ultima_conexion: ultimaConexion,
                last_status: data.last_status || "-",
                last_ip: data.last_ip || "Sin registro",
                last_user_agent: data.last_user_agent || "Sin registro",
                password_stored: data.password_stored === false ? false : true
            };
        });

        return res.json({
            success: true,
            usuarios: usuariosFormateados
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
    console.log(`🚀 GOLAZO SECURE STREAM READY (FASE 9: SELECTOR BUNNY / EXTERNAL)`);
});
