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

app.set('trust proxy', 1);

// --- 🚀 SISTEMA DE CACHÉ PRO PERMISIVO ---
const userCache = new Map(); 
const CACHE_TTL = 5 * 60 * 1000; 

setInterval(() => {
    const now = Date.now();
    let count = 0;
    for (const [uid, value] of userCache.entries()) {
        if (now - value.timestamp > CACHE_TTL) {
            userCache.delete(uid);
            count++;
        }
    }
    if(count > 0) console.log(`[Cache] Limpieza: ${count} eliminados.`);
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

// 2. SEGURIDAD Y CORS
app.use(helmet()); 
app.use(cors()); // Permite conexiones desde tu panel local
app.use(express.json());

// 3. RATE LIMITERS
const streamLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, max: 10,
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
const TOKEN_DURATION = 7200; 

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

// 🎯 ENDPOINT 2: HEARTBEAT (Expulsión exacta basada en el tiempo real)
app.post('/check-session', heartbeatLimiter, authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const { session_id } = req.body;
    if (!session_id) return res.status(400).json({ valid: false });
    try {
        const userData = await getUserData(uid);
        const expiresAt = userData?.expires_at?.toMillis ? userData.expires_at.toMillis() : userData?.expires_at;
        
        // Solo es válido si la sesión coincide y el tiempo actual es MENOR a la fecha de expiración
        if (userData && userData.session_id === session_id && expiresAt && expiresAt > Date.now()) {
            res.json({ valid: true });
        } else {
            userCache.delete(uid); // Expulsión de caché
            res.json({ valid: false });
        }
    } catch (e) { res.status(500).json({ valid: false }); }
});

// 🎯 ENDPOINT 3: GENERAR PASE RÁPIDO (Con Fecha y Hora Exacta)
app.post('/admin/generar-pase-rapido', async (req, res) => {
    try {
        const { admin_secret, fecha_corte, partido } = req.body; 

        if (admin_secret !== process.env.PANEL_SECRET) {
            return res.status(403).json({ success: false, error: "Acceso denegado: Clave maestra incorrecta." });
        }

        if (!fecha_corte) {
            return res.status(400).json({ success: false, error: "Debes especificar la fecha y hora de corte." });
        }

        const nombrePartido = partido || 'Sin especificar'; 
        const randomUser = Math.floor(10000 + Math.random() * 90000).toString();
        const randomPass = Math.floor(100000 + Math.random() * 900000).toString();
        const correoFirebase = `${randomUser}@golazosp.net`;

        const userRecord = await admin.auth().createUser({
            email: correoFirebase,
            password: randomPass,
        });

        // Convertimos la fecha exacta enviada desde tu panel a formato Firebase
        const fechaExpiracion = admin.firestore.Timestamp.fromDate(new Date(fecha_corte));

        await db.collection('usuarios').doc(userRecord.uid).set({
            email: correoFirebase,
            usuario_corto: randomUser, 
            expires_at: fechaExpiracion,
            tipo: 'pase_ocasional',
            etiqueta: nombrePartido, 
            creado_el: admin.firestore.FieldValue.serverTimestamp()
        });

        // Formateamos la fecha para que el mensaje de WhatsApp muestre la hora de Perú
        const fechaFormateada = new Date(fecha_corte).toLocaleString('es-PE', { 
            timeZone: 'America/Lima',
            day: '2-digit', month: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit', hour12: true 
        });

        res.json({
            success: true,
            usuario: randomUser,
            clave: randomPass,
            expira_en: fechaFormateada,
            partido: nombrePartido
        });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 🎯 ENDPOINT 4: EXTENDER ACCESO
app.post('/admin/extender-acceso', async (req, res) => {
    try {
        const { admin_secret, usuario_corto, horas_extra } = req.body; 
        
        if (admin_secret !== process.env.PANEL_SECRET) {
            return res.status(403).json({ success: false, error: "Acceso denegado: Clave maestra incorrecta." });
        }

        const snapshot = await db.collection('usuarios').where('usuario_corto', '==', usuario_corto).get();
        if (snapshot.empty) return res.status(404).json({ error: "Usuario no encontrado" });
        
        const doc = snapshot.docs[0];
        const data = doc.data();
        
        const tiempoActual = data.expires_at.toMillis();
        const nuevoTiempo = admin.firestore.Timestamp.fromMillis(tiempoActual + (horas_extra * 60 * 60 * 1000));

        await db.collection('usuarios').doc(doc.id).update({
            expires_at: nuevoTiempo
        });

        userCache.delete(doc.id);

        res.json({ 
            success: true, 
            mensaje: `Acceso extendido ${horas_extra} hora(s) para ${usuario_corto}` 
        });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLAZO SP PLATFORM v1.4.5 [TIME CONTROL] READY`));
