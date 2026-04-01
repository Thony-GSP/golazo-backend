const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const { Telegraf, Markup } = require('telegraf');

// --- 1. CONFIGURACIÓN DE FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const auth = admin.auth();

const app = express();
app.set('trust proxy', 1);

// --- 2. CORS (CRÍTICO PARA LITESPEED Y GITHUB) ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// --- 3. CONFIGURACIÓN DE STREAMING & SEGURIDAD ---
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; // Tu Key: 0b32dff7...
const STREAM_PATH = '/stream/canal.m3u8';
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- 4. RUTA DE SEÑAL FIRMADA (ANTIPIRATERÍA POR IP) ---
app.get('/generate-stream', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: "No autorizado" });

        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const uid = decodedToken.uid;
        
        // Obtenemos la IP para el Token de Bunny (Seguridad Pro)
        const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        const userDoc = await db.collection('usuarios').doc(uid).get();
        if (!userDoc.exists) return res.status(403).json({ error: "Sin pase activo" });

        const userData = userDoc.data();
        const ahora = admin.firestore.Timestamp.now();

        // Validar expiración
        if (userData.fecha_expiracion.toMillis() < ahora.toMillis()) {
            return res.status(403).json({ error: "Sesión expirada" });
        }

        // Antipiratería: Generar nueva sesión única
        const newSessionId = crypto.randomUUID();
        await db.collection('usuarios').doc(uid).update({ session_id: newSessionId });

        // Generar Token de BunnyCDN (MD5: Key + Path + Expires + IP)
        const expires = Math.floor(Date.now() / 1000) + 14400; // 4 horas
        const hashString = BUNNY_SECURITY_KEY + STREAM_PATH + expires + userIp;
        const token = crypto.createHash('md5').update(hashString).digest('base64')
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '').replace(/\n/g, '');

        const finalUrl = `${BUNNY_URL}${STREAM_PATH}?token=${token}&expires=${expires}`;

        // Devolvemos los datos que tu OvenPlayer espera
        res.json({
            success: true,
            stream_url: finalUrl,
            session_id: newSessionId
        });

    } catch (error) {
        console.error("Error Auth:", error);
        res.status(401).json({ error: "Sesión inválida" });
    }
});

// --- 5. HEARTBEAT (CONTRA MULTI-DISPOSITIVO) ---
app.post('/check-session', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.json({ valid: false });
        
        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const { session_id } = req.body;

        const userDoc = await db.collection('usuarios').doc(decodedToken.uid).get();
        if (session_id !== userDoc.data().session_id) {
            return res.json({ valid: false, motivo: 'pirateria' });
        }
        res.json({ valid: true });
    } catch (e) {
        res.json({ valid: false });
    }
});

// --- 6. GENERAR PASE RÁPIDO (PANEL ADMIN) ---
app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        const userRandom = crypto.randomBytes(3).toString('hex');
        const emailFinal = email_manual || `${userRandom}@golazosp.net`;
        const claveFinal = pass_manual || crypto.randomBytes(4).toString('hex');

        const userRecord = await auth.createUser({
            email: emailFinal, password: claveFinal, displayName: partido
        });

        // 24 horas de margen
        const exp = new Date();
        exp.setHours(exp.getHours() + 24);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            clave: claveFinal,
            email: emailFinal,
            etiqueta: partido,
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: admin.firestore.Timestamp.now(),
            session_id: ""
        });

        res.json({ success: true, usuario: emailFinal, clave: claveFinal });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// --- 7. BOT DE TELEGRAM Y LISTADO ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const iniciarBot = async () => {
    try {
        await new Promise(r => setTimeout(r, 12000)); // 12s para evitar conflicto 409 en Render
        await bot.launch({ dropPendingUpdates: true });
        console.log("✅ Bot conectado.");
    } catch (e) { setTimeout(iniciarBot, 20000); }
};
iniciarBot();

app.post('/admin/listar-usuarios', async (req, res) => {
    const { admin_secret } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });
    const snap = await db.collection('usuarios').orderBy('creado_el', 'desc').get();
    res.json({ success: true, usuarios: snap.docs.map(d => d.data()) });
});

// Manejo de cierres
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLAZO v8.0 PRO FINAL ONLINE`));
