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
// Valores normales de producción.
// Para prueba de carga controlada puedes subirlos temporalmente desde Render env vars.
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

// 🔐 Código rápido
// Recomendado: crear QUICK_CODE_SECRET en Render.
// Si no existe, usa BUNNY_KEY como respaldo.
const QUICK_CODE_SECRET = (process.env.QUICK_CODE_SECRET || process.env.BUNNY_KEY || "").trim();

// 🌐 URL pública de la web para generar links rápidos
const APP_BASE_URL = process.env.APP_BASE_URL || "https://golazosp.net";

// --- 4.1 OPTIMIZACIÓN DE ESCALA ---
// Frontend recomendado:
// check-session cada 60-75s con jitter.
// generate-stream / renovación cada 8-8.5 min.
//
// Firestore no debe recibir escritura en cada heartbeat.
// Se escribirá heartbeat solo si ya pasó este tiempo.
const HEARTBEAT_WRITE_MIN_INTERVAL_MS = parseInt(
    process.env.HEARTBEAT_WRITE_MIN_INTERVAL_MS || "90000",
    10
);

// Ventana para considerar que una sesión sigue activa.
// Debe ser mayor al heartbeat + jitter + margen.
// Con heartbeat 60-75s y escritura cada 90s, 150s es buen equilibrio.
const ACTIVE_SESSION_WINDOW_MS = parseInt(
    process.env.ACTIVE_SESSION_WINDOW_MS || "150000",
    10
);

// Token Bunny máximo.
// El frontend renovará aprox. cada 8 min.
// 600s = 10 min, deja margen suficiente.
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
        version: "FASE 8 - backend optimized for 400-500 users"
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

    // Autoriza todo lo que está debajo de /stream/
    const tokenPath = "/stream/";
    const signaturePath = tokenPath;

    // Para firmar: token_path SIN encodear.
    // Para URL final: token_path SÍ encodeado.
    const signingData = `token_path=${tokenPath}`;

    // Token IP Validation está OFF, así que no firmamos IP.
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

// --- 12. GENERATE STREAM OPTIMIZADO ---
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

        // Bloqueo por revocación.
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

        // Bloqueo de segunda sesión activa reciente.
        // Antes era 45s. Ahora se amplía porque el heartbeat frontend será 60-75s.
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
            // Optimización:
            // Renovar URL no debe escribir en Firestore siempre.
            // Solo refrescamos auditoría/heartbeat si ya pasó el intervalo mínimo.
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

        const signed = generateBunnyTokenForStream(
            STREAM_PATH,
            BUNNY_SECURITY_KEY,
            tokenDuration
        );

        const finalUrl = signed.url;

        console.log(
            `✅ Stream [${mismaSesion ? 'RENOVADO' : 'NUEVO'}] | uid=${uid} | duration=${tokenDuration}s`
        );

        return res.json({
            success: true,
            stream_url: finalUrl,
            session_id: sessionIdFinal,
            reused_session: mismaSesion,
            bunny_expires: signed.expires,
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

        // Optimización principal:
        // No escribir en Firestore en cada heartbeat correcto.
        // Solo actualizar last_heartbeat si ya pasó el intervalo mínimo.
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

        // ==========================
        // 💎 SOCIO VIP: email + clave
        // ==========================
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

        // =====================================
        // ⚽ PASE POR PARTIDO: código rápido
        // =====================================
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

            // Contraseña interna. No se muestra al cliente.
            claveInterna = generarPasswordInternoSeguro();

            try {
                userRecord = await auth.createUser({
                    email: emailFinal,
                    password: claveInterna,
                    displayName: partido
                });

                break;

            } catch (e) {
                // Si justo existe ese correo interno, intentamos con otro código.
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
    console.log(`🚀 GOLAZO SECURE STREAM READY (FASE 8: BACKEND OPTIMIZADO 400-500 USERS)`);
});
