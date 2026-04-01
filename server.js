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

// --- 2. CORS (CRÍTICO PARA LITESPEED) ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- 3. RUTA DE SEÑAL (COMPATIBLE CON TU HTML) ---
app.get('/generate-stream', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: "No autorizado" });

        // Validamos el Token que envía tu en-vivo.html
        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const uid = decodedToken.uid;

        // Buscamos el pase en Firestore
        const userDoc = await db.collection('usuarios').doc(uid).get();
        if (!userDoc.exists) return res.status(403).json({ error: "Sin pase activo" });

        const userData = userDoc.data();
        const ahora = admin.firestore.Timestamp.now();

        // Verificamos si expiró
        if (userData.fecha_expiracion.toMillis() < ahora.toMillis()) {
            return res.status(403).json({ error: "Sesión expirada" });
        }

        // Devolvemos los datos EXACTOS que pide tu script
        res.json({
            success: true,
            stream_url: "https://golazosp-stream.b-cdn.net/live/playlist.m3u8",
            session_id: crypto.randomBytes(8).toString('hex')
        });

    } catch (error) {
        console.error("Error Auth:", error);
        res.status(401).json({ error: "Sesión inválida" });
    }
});

// --- 4. RUTA HEARTBEAT (check-session) ---
app.post('/check-session', (req, res) => {
    res.json({ valid: true }); // Mantenemos la sesión siempre viva mientras el pase exista
});

// --- 5. GENERAR PASE RÁPIDO (PANEL) ---
app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        const userRandom = crypto.randomBytes(3).toString('hex');
        const emailFinal = email_manual || `${userRandom}@golazosp.net`;
        const claveFinal = pass_manual || crypto.randomBytes(4).toString('hex');

        const userRecord = await auth.createUser({
            email: emailFinal, password: claveFinal, displayName: partido
        });

        // 24 horas de margen para evitar errores de zona horaria
        const exp = new Date();
        exp.setHours(exp.getHours() + 24);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            clave: claveFinal,
            etiqueta: partido,
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: admin.firestore.Timestamp.now()
        });

        res.json({ success: true, usuario: emailFinal, clave: claveFinal });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// --- 6. BOT Y LISTADO ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const iniciarBot = async () => {
    try {
        await new Promise(r => setTimeout(r, 5000));
        await bot.launch({ dropPendingUpdates: true });
        console.log("✅ Bot conectado.");
    } catch (e) { setTimeout(iniciarBot, 10000); }
};
iniciarBot();

app.post('/admin/listar-usuarios', async (req, res) => {
    const { admin_secret } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });
    const snap = await db.collection('usuarios').get();
    res.json({ success: true, usuarios: snap.docs.map(d => d.data()) });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 SISTEMA GOLAZO v6.1 READY`));
