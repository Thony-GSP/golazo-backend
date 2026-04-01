const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const { Telegraf, Markup } = require('telegraf');

// --- 1. FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const auth = admin.auth();

const app = express();
app.set('trust proxy', 1);

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());

// --- 2. CONFIGURACIÓN (REVISADA) ---
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; 
const STREAM_PATH = '/stream/canal.m3u8';
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- 3. GENERADOR DE TOKEN (ESTÁNDAR BUNNY) ---
function generateBunnyToken(path, securityKey, ip, duration = 14400) {
    const expires = Math.floor(Date.now() / 1000) + duration;
    // IMPORTANTE: El estándar suele ser Key + Path + Expires + IP
    const hashString = securityKey + path + expires + ip;
    const token = crypto.createHash('md5').update(hashString).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '').replace(/\n/g, '');
    
    return { token, expires };
}

app.get('/generate-stream', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: "No autorizado" });

        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const uid = decodedToken.uid;
        
        // IP Real del cliente (Crucial para el 403)
        const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

        const userDoc = await db.collection('usuarios').doc(uid).get();
        if (!userDoc.exists) return res.status(403).json({ error: "Pase inactivo" });

        const userData = userDoc.data();
        if (userData.fecha_expiracion.toMillis() < Date.now()) {
            return res.status(403).json({ error: "Pase expirado" });
        }

        const newSessionId = crypto.randomUUID();
        await db.collection('usuarios').doc(uid).update({ session_id: newSessionId });

        // Generamos el Token
        const { token, expires } = generateBunnyToken(STREAM_PATH, BUNNY_SECURITY_KEY, userIp);
        const finalUrl = `${BUNNY_URL}${STREAM_PATH}?token=${token}&expires=${expires}`;

        console.log(`✅ URL Generada para ${uid}: ${finalUrl}`);

        res.json({
            success: true,
            stream_url: finalUrl,
            session_id: newSessionId
        });

    } catch (error) {
        res.status(401).json({ error: "Sesión inválida" });
    }
});

// --- 4. HEARTBEAT ---
app.post('/check-session', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const { session_id } = req.body;

        const userDoc = await db.collection('usuarios').doc(decodedToken.uid).get();
        if (session_id !== userDoc.data().session_id) {
            return res.json({ valid: false, motivo: 'pirateria' });
        }
        res.json({ valid: true });
    } catch (e) { res.json({ valid: false }); }
});

// --- 5. PANEL ADMIN ---
app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        const userRandom = crypto.randomBytes(3).toString('hex');
        const emailFinal = email_manual || `${userRandom}@golazosp.net`;
        const claveFinal = pass_manual || crypto.randomBytes(4).toString('hex');
        const userRecord = await auth.createUser({ email: emailFinal, password: claveFinal, displayName: partido });

        const exp = new Date();
        exp.setHours(exp.getHours() + 24);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid, usuario_corto: emailFinal, clave: claveFinal,
            etiqueta: partido, fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: admin.firestore.Timestamp.now(), session_id: ""
        });

        res.json({ success: true, usuario: emailFinal, clave: claveFinal });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// --- 6. BOT TELEGRAM ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const iniciarBot = async () => {
    try {
        await new Promise(r => setTimeout(r, 12000));
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLAZO v8.1 READY`));
