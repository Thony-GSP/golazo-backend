const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Telegraf, Markup } = require('telegraf');

// --- 1. FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const auth = admin.auth();

const app = express();
app.set('trust proxy', 1);

// --- 🔥 FASE 3: CORS RESTRINGIDO ---
const allowedOrigins = [
    'https://golazosp.net',
    'https://www.golazosp.net',
    'https://zonagolazo.net',
    'https://www.zonagolazo.net',
    'https://thony-gsp.github.io/golazo-backend/panel.html',
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) { return callback(null, true); }
        if (allowedOrigins.includes(origin)) { return callback(null, true); }
        
        console.warn(`❌ CORS bloqueado para origin: ${origin}`);
        return callback(null, false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false
};

app.use(cors(corsOptions));
app.use(express.json());

// --- 🔥 FASE 3: LIMITADORES DE VELOCIDAD (RATE LIMITS) ---
const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: { success: false, code: "RATE_LIMIT", error: "Demasiadas solicitudes. Intenta nuevamente en unos segundos." }
});

const streamLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: { success: false, code: "STREAM_RATE_LIMIT", error: "Demasiadas solicitudes de stream. Espera unos segundos." }
});

const adminLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.method === 'OPTIONS',
    message: { success: false, code: "ADMIN_RATE_LIMIT", error: "Demasiadas solicitudes administrativas." }
});

// Aplicar limitador general a todas las rutas
app.use(generalLimiter);

// --- 2. CONFIGURACIÓN ---
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY.trim(); 
const STREAM_PATH = '/stream/canal.m3u8';
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- 3. GENERADOR DE TOKEN ---
function generateBunnyToken(path, securityKey, duration = 120) {
    const expires = Math.floor(Date.now() / 1000) + duration;
    const hashString = securityKey + path + expires;
    const token = crypto.createHash('md5').update(hashString).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '').replace(/\n/g, '');
    
    return { token, expires };
}

// --- 🔥 FASE 4: MIDDLEWARE DE SEGURIDAD ADMIN ---
async function verifyAdmin(req, res, next) {
    // 1. Soporte temporal: Mantiene vivo tu panel actual con el admin_secret
    if (req.body.admin_secret && req.body.admin_secret === ADMIN_SECRET) {
        return next();
    }

    // 2. Nueva seguridad: Validación por Token de Firebase
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, message: "Falta token de administrador" });
    }

    const idToken = authHeader.replace("Bearer ", "").trim();
    try {
        const decodedToken = await auth.verifyIdToken(idToken);
        
        // Verificamos si el usuario tiene el "sello" de administrador
        if (decodedToken.admin === true) {
            return next();
        } else {
            return res.status(403).json({ success: false, message: "Permisos denegados. No eres administrador." });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: "Token de administrador inválido o expirado" });
    }
}

// --- 4. GENERATE STREAM (CON LIMITADOR) ---
app.get('/generate-stream', streamLimiter, async (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";
        if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ success: false, code: "NO_AUTH" });

        const idToken = authHeader.replace("Bearer ", "").trim();
        let decodedToken;
        try {
            decodedToken = await auth.verifyIdToken(idToken);
        } catch (authError) {
            return res.status(401).json({ success: false, code: "INVALID_AUTH" });
        }

        const uid = decodedToken.uid;
        const requestedSessionId = req.query.session_id || null;
        const userRef = db.collection('usuarios').doc(uid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) return res.status(403).json({ success: false, code: "PASS_INACTIVE" });
        
        const userData = userDoc.data();
        if (!userData.fecha_expiracion) return res.status(403).json({ success: false, code: "NO_EXPIRATION" });

        const ahora = Date.now();
        const expiraMillis = userData.fecha_expiracion.toMillis();
        const segundosRestantesPase = Math.floor((expiraMillis - ahora) / 1000);

        if (segundosRestantesPase <= 0) {
            return res.status(403).json({ success: false, code: "PASS_EXPIRED", error: "Pase expirado" });
        }

        let sessionIdFinal = userData.session_id || "";
        const mismaSesion = Boolean(requestedSessionId && requestedSessionId === userData.session_id);

        if (!mismaSesion) {
            sessionIdFinal = crypto.randomUUID();
            await userRef.update({
                session_id: sessionIdFinal,
                session_started_at: admin.firestore.Timestamp.now(),
                last_heartbeat: admin.firestore.Timestamp.now(),
                last_status: "stream_started"
            });
        } else {
            await userRef.update({
                last_heartbeat: admin.firestore.Timestamp.now(),
                last_status: "stream_renewed"
            });
        }

        const tokenDuration = Math.min(120, segundosRestantesPase);
        const { token, expires } = generateBunnyToken(STREAM_PATH, BUNNY_SECURITY_KEY, tokenDuration);
        const finalUrl = `${BUNNY_URL}${STREAM_PATH}?token=${token}&expires=${expires}`;

        console.log(`✅ Stream [${mismaSesion ? 'RENOVADO' : 'NUEVO'}] | uid=${uid} | duration=${tokenDuration}s`);

        return res.json({
            success: true,
            stream_url: finalUrl,
            session_id: sessionIdFinal,
            reused_session: mismaSesion,
            bunny_expires: expires,
            pase_expira: expiraMillis
        });

    } catch (error) {
        console.error("❌ Error en /generate-stream:", error);
        return res.status(500).json({ success: false, code: "SERVER_ERROR" });
    }
});

// --- 5. CHECK SESSION (HEARTBEAT) ---
app.post('/check-session', async (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";
        if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ valid: false, motivo: "no_auth" });

        const idToken = authHeader.replace("Bearer ", "").trim();
        let decodedToken;
        try { decodedToken = await auth.verifyIdToken(idToken); } 
        catch (e) { return res.status(401).json({ valid: false, motivo: "no_auth" }); }

        const { session_id } = req.body || {};
        if (!session_id) return res.status(400).json({ valid: false, motivo: "missing_session" });

        const uid = decodedToken.uid;
        const userRef = db.collection('usuarios').doc(uid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) return res.status(403).json({ valid: false, motivo: "pase_inactivo" });
        
        const userData = userDoc.data();
        if (!userData.fecha_expiracion) return res.status(403).json({ valid: false, motivo: "pase_sin_expiracion" });

        const expiraMillis = userData.fecha_expiracion.toMillis();
        const ahora = Date.now();

        if (expiraMillis <= ahora) {
            await userRef.update({ 
                last_heartbeat: admin.firestore.Timestamp.now(),
                last_status: "expired" 
            });
            return res.json({ valid: false, motivo: "expirado" });
        }

        if (session_id !== userData.session_id) {
            await userRef.update({ 
                last_heartbeat: admin.firestore.Timestamp.now(),
                last_status: "replaced_session" 
            });
            return res.json({ valid: false, motivo: "pirateria" });
        }

        await userRef.update({ last_heartbeat: admin.firestore.Timestamp.now(), last_status: "active" });
        return res.json({ valid: true, motivo: "ok", pase_expira: expiraMillis });

    } catch (e) {
        return res.status(500).json({ valid: false, motivo: "server_error" });
    }
});

// --- 6. PANEL ADMIN Y LIMPIEZA ---

// Ruta temporal para crear al primer administrador mediante Postman
app.post('/admin/set-admin-claim', adminLimiter, async (req, res) => {
    const { admin_secret, email } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        const user = await auth.getUserByEmail(email);
        await auth.setCustomUserClaims(user.uid, { admin: true });
        res.json({ success: true, message: `✅ Rol de administrador asignado correctamente a: ${email}` });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/admin/generar-pase-rapido', adminLimiter, verifyAdmin, async (req, res) => {
    const { partido, email_manual, pass_manual, fecha_corte } = req.body;

    try {
        let emailFinal = email_manual || `${Math.floor(100000 + Math.random() * 900000)}@golazosp.net`;
        let claveFinal = pass_manual || Math.floor(100000 + Math.random() * 900000).toString();
        
        const userRecord = await auth.createUser({ email: emailFinal, password: claveFinal, displayName: partido });
        const exp = fecha_corte ? new Date(fecha_corte) : new Date(Date.now() + 24 * 60 * 60 * 1000);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid, 
            usuario_corto: emailFinal, 
            clave: claveFinal,
            etiqueta: partido, 
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: admin.firestore.Timestamp.now(), 
            session_id: ""
        });

        res.json({ success: true, usuario: emailFinal, clave: claveFinal });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/admin/limpiar-caducados', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const ahora = admin.firestore.Timestamp.now();
        const vencidosSnap = await db.collection('usuarios').where('fecha_expiracion', '<', ahora).get();
        if (vencidosSnap.empty) return res.json({ success: true, mensaje: "✅ No hay usuarios vencidos." });

        let borrados = 0;
        for (const doc of vencidosSnap.docs) {
            try {
                await auth.deleteUser(doc.id); 
                await doc.ref.delete();        
                borrados++;
            } catch (err) {}
        }
        res.json({ success: true, mensaje: `🧹 ${borrados} pases vencidos eliminados.` });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/admin/listar-usuarios', adminLimiter, verifyAdmin, async (req, res) => {
    const snap = await db.collection('usuarios').orderBy('creado_el', 'desc').get();
    const usuariosFormateados = snap.docs.map(d => {
        const data = d.data();
        const expiraMillis = data.fecha_expiracion.toMillis();
        const esActivo = expiraMillis > Date.now();
        
        return {
            ...data,
            estado: esActivo ? 'ACTIVO' : 'VENCIDO',
            esActivo: esActivo,
            tiempo: new Date(expiraMillis).toLocaleString('es-PE', {
                timeZone: 'America/Lima', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: true
            })
        };
    });
    res.json({ success: true, usuarios: usuariosFormateados });
});

// --- 7. BOT TELEGRAM ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const iniciarBot = async () => {
    try {
        await new Promise(r => setTimeout(r, 12000));
        await bot.launch({ dropPendingUpdates: true });
        console.log("✅ Bot conectado.");
    } catch (e) { setTimeout(iniciarBot, 20000); }
};
iniciarBot();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLAZO SECURE STREAM READY (FASE 4: RATE LIMIT & ADMIN MIDDLEWARE)`));
