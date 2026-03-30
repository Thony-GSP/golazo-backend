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
app.use(cors()); 
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
        res.json({ stream_url: finalUrl, session_id: newSessionId });
    } catch (e) { res.status(500).json({ error: 'Error interno' }); }
});

// 🎯 ENDPOINT 2: HEARTBEAT
app.post('/check-session', heartbeatLimiter, authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const { session_id } = req.body;
    try {
        const userData = await getUserData(uid);
        const expiresAt = userData?.expires_at?.toMillis ? userData.expires_at.toMillis() : userData?.expires_at;
        if (!userData) return res.json({ valid: false, motivo: 'eliminado' });
        if (userData.session_id !== session_id) return res.json({ valid: false, motivo: 'pirateria' });
        if (expiresAt && expiresAt <= Date.now()) return res.json({ valid: false, motivo: 'tiempo_agotado' });
        res.json({ valid: true });
    } catch (e) { res.status(500).json({ valid: false }); }
});

// 🎯 ENDPOINT 3: GENERAR PASE O SOCIO
app.post('/admin/generar-pase-rapido', async (req, res) => {
    try {
        const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body; 
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false, error: "Acceso denegado." });
        const esSocio = !!email_manual;
        const emailFinal = email_manual || `${Math.floor(10000 + Math.random() * 90000)}@golazosp.net`;
        const passFinal = pass_manual || Math.floor(100000 + Math.random() * 900000).toString();
        const usuarioCorto = esSocio ? email_manual : emailFinal.split('@')[0];
        const userRecord = await admin.auth().createUser({ email: emailFinal, password: passFinal });
        const fechaExpiracion = admin.firestore.Timestamp.fromDate(new Date(fecha_corte));
        await db.collection('usuarios').doc(userRecord.uid).set({
            email: emailFinal,
            usuario_corto: usuarioCorto, 
            expires_at: fechaExpiracion,
            tipo: esSocio ? 'socio_mensual' : 'pase_ocasional',
            etiqueta: partido || 'Sin especificar', 
            creado_el: admin.firestore.FieldValue.serverTimestamp()
        });
        const fechaFormateada = new Date(fecha_corte).toLocaleString('es-PE', { 
            timeZone: 'America/Lima', day: '2-digit', month: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit', hour12: true 
        });
        res.json({ success: true, usuario: usuarioCorto, clave: passFinal, expira_en: fechaFormateada, partido: partido || 'General' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// 🎯 ENDPOINT 4: EXTENDER ACCESO
app.post('/admin/extender-acceso', async (req, res) => {
    try {
        const { admin_secret, usuario_corto, horas_extra } = req.body; 
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false, error: "Clave maestra incorrecta." });
        let snapshot = await db.collection('usuarios').where('usuario_corto', '==', usuario_corto).get();
        if (snapshot.empty) snapshot = await db.collection('usuarios').where('email', '==', usuario_corto).get();
        if (snapshot.empty) return res.status(404).json({ error: "Usuario no encontrado" });
        const doc = snapshot.docs[0];
        const data = doc.data();
        const tiempoActual = data.expires_at.toMillis();
        const nuevoTiempo = admin.firestore.Timestamp.fromMillis(tiempoActual + (parseFloat(horas_extra) * 60 * 60 * 1000));
        await db.collection('usuarios').doc(doc.id).update({ expires_at: nuevoTiempo });
        userCache.delete(doc.id);
        res.json({ success: true, mensaje: `Tiempo actualizado con éxito para ${usuario_corto}` });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// 🎯 ENDPOINT 6: LISTAR USUARIOS
app.post('/admin/listar-usuarios', async (req, res) => {
    try {
        const { admin_secret } = req.body;
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false, error: "No autorizado" });
        const snapshot = await db.collection('usuarios').orderBy('creado_el', 'desc').limit(100).get();
        const ahora = Date.now();
        const usuarios = snapshot.docs.map(doc => {
            const data = doc.data();
            const expiresAt = data.expires_at?.toMillis ? data.expires_at.toMillis() : data.expires_at;
            const tiempoRestanteMs = expiresAt - ahora;
            let tiempoTexto = "Expirado";
            if (tiempoRestanteMs > 0) {
                const dias = Math.floor(tiempoRestanteMs / 86400000);
                const horas = Math.floor((tiempoRestanteMs % 86400000) / 3600000);
                const mins = Math.floor((tiempoRestanteMs % 3600000) / 60000);
                tiempoTexto = dias > 0 ? `${dias}d ${horas}h` : `${horas}h ${mins}m`;
            }
            return { email: data.email, usuario_corto: data.usuario_corto, etiqueta: data.etiqueta, estado: tiempoRestanteMs > 0 ? "ACTIVO ✅" : "CADUCADO ❌", tiempo: tiempoTexto, esActivo: tiempoRestanteMs > 0 };
        });
        res.json({ success: true, usuarios });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

// 🎯 ENDPOINT 7: LIMPIEZA DE CADUCADOS (Versión Corregida)
app.post('/admin/limpiar-caducados', async (req, res) => {
    try {
        const { admin_secret } = req.body;
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false, error: "No autorizado" });
        const ahora = admin.firestore.Timestamp.now();
        const snapshot = await db.collection('usuarios').where('tipo', '==', 'pase_ocasional').where('expires_at', '<', ahora).get();
        if (snapshot.empty) return res.json({ success: true, mensaje: "No hay usuarios caducados para limpiar." });
        let borrados = 0;
        const promesas = snapshot.docs.map(async (doc) => {
            const data = doc.data();
            try {
                try {
                    const userAuth = await admin.auth().getUserByEmail(data.email);
                    await admin.auth().deleteUser(userAuth.uid);
                } catch (e) {}
                await db.collection('usuarios').doc(doc.id).delete();
                borrados++;
            } catch (err) {}
        });
        await Promise.all(promesas);
        res.json({ success: true, mensaje: `Limpieza terminada: ${borrados} registros eliminados.` });
    } catch (error) { res.status(500).json({ success: false, error: "Error interno del servidor." }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLAZO SP PLATFORM v1.7.1 READY`));
