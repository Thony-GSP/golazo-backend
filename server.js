const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const app = express();
app.set('trust proxy', 1);

const userCache = new Map(); 
const CACHE_TTL = 5 * 60 * 1000; 

setInterval(() => {
    const now = Date.now();
    for (const [uid, value] of userCache.entries()) {
        if (now - value.timestamp > CACHE_TTL) userCache.delete(uid);
    }
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

app.use(helmet()); 
app.use(cors()); 
app.use(express.json());

const streamLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 15 });
const heartbeatLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 150 });

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
        const hashableBase = BUNNY_SECURITY_KEY + '/stream/' + expires + 'token_path=/stream/';
        const token = crypto.createHash('sha256').update(hashableBase).digest('base64').replace(/\n/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        res.json({ stream_url: `${BUNNY_URL}/bcdn_token=${token}&expires=${expires}&token_path=%2Fstream%2F${STREAM_PATH}`, session_id: newSessionId });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

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

app.post('/admin/generar-pase-rapido', async (req, res) => {
    try {
        const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body; 
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false, error: "Denegado" });
        const esSocio = !!email_manual;
        const emailFinal = email_manual || `${Math.floor(10000 + Math.random() * 90000)}@golazosp.net`;
        const passFinal = pass_manual || Math.floor(100000 + Math.random() * 900000).toString();
        const userRecord = await admin.auth().createUser({ email: emailFinal, password: passFinal });
        const expires = admin.firestore.Timestamp.fromDate(new Date(fecha_corte));
        await db.collection('usuarios').doc(userRecord.uid).set({
            email: emailFinal, usuario_corto: esSocio ? email_manual : emailFinal.split('@')[0], 
            expires_at: expires, tipo: esSocio ? 'socio_mensual' : 'pase_ocasional', etiqueta: partido || 'General', creado_el: admin.firestore.FieldValue.serverTimestamp()
        });
        const fF = new Date(fecha_corte).toLocaleString('es-PE', { timeZone: 'America/Lima', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: true });
        res.json({ success: true, usuario: esSocio ? email_manual : emailFinal.split('@')[0], clave: passFinal, expira_en: fF, partido: partido || 'General' });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/admin/extender-acceso', async (req, res) => {
    try {
        const { admin_secret, usuario_corto, horas_extra } = req.body; 
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false });
        let snap = await db.collection('usuarios').where('usuario_corto', '==', usuario_corto).get();
        if (snap.empty) snap = await db.collection('usuarios').where('email', '==', usuario_corto).get();
        if (snap.empty) return res.status(404).json({ error: "No existe" });
        const doc = snap.docs[0];
        const nuevoT = admin.firestore.Timestamp.fromMillis(doc.data().expires_at.toMillis() + (parseFloat(horas_extra) * 3600000));
        await db.collection('usuarios').doc(doc.id).update({ expires_at: nuevoT });
        userCache.delete(doc.id);
        res.json({ success: true, mensaje: `Extendido para ${usuario_corto}` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/admin/listar-usuarios', async (req, res) => {
    try {
        const { admin_secret } = req.body;
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false });
        const snap = await db.collection('usuarios').orderBy('creado_el', 'desc').limit(100).get();
        const ahora = Date.now();
        const usuarios = snap.docs.map(doc => {
            const d = doc.data();
            const exp = d.expires_at.toMillis();
            const rest = exp - ahora;
            let tT = "Expirado";
            if (rest > 0) {
                const h = Math.floor(rest / 3600000);
                const m = Math.floor((rest % 3600000) / 60000);
                tT = `${h}h ${m}m`;
            }
            return { email: d.email, usuario_corto: d.usuario_corto, etiqueta: d.etiqueta, estado: rest > 0 ? "ACTIVO ✅" : "CADUCADO ❌", tiempo: tT, esActivo: rest > 0 };
        });
        res.json({ success: true, usuarios });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/admin/limpiar-caducados', async (req, res) => {
    try {
        const { admin_secret } = req.body;
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false });
        const ahora = admin.firestore.Timestamp.now();
        const snap = await db.collection('usuarios').where('tipo', '==', 'pase_ocasional').where('expires_at', '<', ahora).get();
        if (snap.empty) return res.json({ success: true, mensaje: "Sin caducados" });
        let b = 0;
        for (const doc of snap.docs) {
            try {
                const uAuth = await admin.auth().getUserByEmail(doc.data().email);
                await admin.auth().deleteUser(uAuth.uid);
            } catch (e) {}
            await db.collection('usuarios').doc(doc.id).delete();
            b++;
        }
        res.json({ success: true, mensaje: `Limpieza: ${b} borrados.` });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 READY`));
