const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// 1. INICIALIZAR FIREBASE
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();
const app = express();

// ✅ CORRECCIÓN CRÍTICA: Confiar en el proxy de Render para el Rate Limit
app.set('trust proxy', 1);

// --- 🚀 SISTEMA DE CACHÉ PRO PERMISIVO (v1.4.1) ---
const userCache = new Map(); 
const CACHE_TTL = 5 * 60 * 1000; // ⏱️ Subido a 5 minutos para evitar bloqueos por reconexión

// 🧹 GARBAGE COLLECTOR: Limpia la memoria cada 10 minutos
setInterval(() => {
    const now = Date.now();
    let count = 0;
    for (const [uid, value] of userCache.entries()) {
        if (now - value.timestamp > CACHE_TTL) {
            userCache.delete(uid);
            count++;
        }
    }
    if(count > 0) console.log(`[Cache] 🧹 Limpieza realizada: ${count} registros eliminados.`);
}, 10 * 60 * 1000);

const getUserData = async (uid) => {
    const now = Date.now();
    const cached = userCache.get(uid);
    if (cached && (now - cached.timestamp < CACHE_TTL)) return cached.data;

    const userDoc = await db.collection('usuarios').doc(uid).get();
    if (!userDoc.exists) return null;
    const data = userDoc.data();
    userCache.set(uid, { data, timestamp: now });
    return data;
};

// 2. SEGURIDAD DE INFRAESTRUCTURA
app.use(helmet()); 
app.use(cors({ origin: ['https://golazosp.net', 'https://www.golazosp.net'] }));
app.use(express.json());

// 3. RATE LIMITERS (Arquitectura de Escudo)
const streamLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, max: 10, // 🔓 Un poco más flexible para pruebas
    message: { error: 'Muchos pedidos. Espera 1 min.' }
});
const heartbeatLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, max: 120, 
    message: { error: 'Actividad sospechosa.' }
});

// 4. CONFIGURACIÓN DE STREAMING
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; 
const STREAM_PATH = '/stream/canal.m3u8';
const TOKEN_DURATION = 7200; // 2 horas

// MIDDLEWARE: Autenticación
const authenticateUser = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
    const idToken = authHeader.split('Bearer ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken;
        next();
    } catch (e) { res.status(401).json({ error: 'Sesión expirada.' }); }
};

// 🎯 ENDPOINT 1: GENERAR STREAM
app.get('/generate-stream', streamLimiter, authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const userIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    
    try {
        const userData = await getUserData(uid);
        const expiresAt = userData?.expires_at?.toMillis ? userData.expires_at.toMillis() : userData?.expires_at;

        if (!userData || !expiresAt || expiresAt < Date.now()) return res.status(403).json({ error: 'Inactivo' });

        const newSessionId = crypto.randomUUID();
        await db.collection('usuarios').doc(uid).update({ session_id: newSessionId });
        
        // Actualizamos caché inmediatamente con la nueva sesión
        userCache.set(uid, { data: { ...userData, session_id: newSessionId }, timestamp: Date.now() });

        const expires = Math.floor(Date.now() / 1000) + TOKEN_DURATION;
        const pathAllowed = '/stream/'; 
        const hashableBase = BUNNY_SECURITY_KEY + pathAllowed + expires + 'token_path=' + pathAllowed;
        const token = crypto.createHash('sha256').update(hashableBase).digest('base64').replace(/\n/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

        const finalUrl = `${BUNNY_URL}/bcdn_token=${token}&expires=${expires}&token_path=%2Fstream%2F${STREAM_PATH}`;
        
        console.log(`[${new Date().toISOString()}] ✅ Stream OK: ${uid} | ${userIp}`);
        res.json({ stream_url: finalUrl, session_id: newSessionId });
    } catch (e) { 
        console.error("Error en generate-stream:", e);
        res.status(500).json({ error: 'Error interno' }); 
    }
});

// 🎯 ENDPOINT 2: HEARTBEAT
app.post('/check-session', heartbeatLimiter, authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const { session_id } = req.body;
    if (!session_id) return res.status(400).json({ valid: false });
    try {
        const userData = await getUserData(uid);
        // Si la sesión coincide, mantenemos el acceso vivo
        if (userData && userData.session_id === session_id) {
            res.json({ valid: true });
        } else {
            // Si no coincide, borramos caché para forzar re-validación con DB en el siguiente intento
            userCache.delete(uid);
            res.json({ valid: false });
        }
    } catch (e) { res.status(500).json({ valid: false }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLAZO SP PLATFORM v1.4.1 [PERMISSIVE] READY`));
