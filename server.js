const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const { Telegraf, Markup } = require('telegraf');

// --- FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const auth = admin.auth();

const app = express();
app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());

const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- 📺 EL ENDPOINT QUE TU HTML NECESITA ---
app.get('/generate-stream', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ success: false, error: "No token" });

        const idToken = authHeader.split('Bearer ')[1];
        const decodedToken = await auth.verifyIdToken(idToken);
        const uid = decodedToken.uid;

        // Verificar si el pase existe y es válido en Firestore
        const userDoc = await db.collection('usuarios').doc(uid).get();
        
        if (!userDoc.exists) {
            return res.status(403).json({ success: false, error: "Pase no encontrado" });
        }

        const userData = userDoc.data();
        const ahora = admin.firestore.Timestamp.now();

        // Validar expiración
        if (userData.fecha_expiracion.toMillis() < ahora.toMillis()) {
            return res.status(403).json({ success: false, error: "Sesión expirada" });
        }

        // URL DE TU STREAMING
        res.json({
            success: true,
            stream_url: "https://golazosp-stream.b-cdn.net/live/playlist.m3u8",
            session_id: crypto.randomBytes(8).toString('hex')
        });

    } catch (error) {
        console.error("Error en stream:", error);
        res.status(401).json({ success: false, error: "Sesión inválida" });
    }
});

// --- ❤️ ENDPOINT HEARTBEAT (Para que no se cierre la sesión) ---
app.post('/check-session', async (req, res) => {
    // Por ahora, devolvemos siempre válido para que no te expulse
    res.json({ valid: true });
});

// --- 🔑 GENERAR PASE RÁPIDO (CORREGIDO) ---
app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        const userRandom = crypto.randomBytes(3).toString('hex');
        const emailFinal = email_manual || `${userRandom}@golazosp.net`;
        const claveFinal = pass_manual || crypto.randomBytes(4).toString('hex');

        const userRecord = await auth.createUser({
            email: emailFinal,
            password: claveFinal,
            displayName: partido
        });

        // 24 HORAS DE GRACIA
        const exp = new Date();
        exp.setHours(exp.getHours() + 24);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            clave: claveFinal,
            email: emailFinal,
            etiqueta: partido,
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            tipo: 'pase_individual',
            creado_el: admin.firestore.Timestamp.now()
        });

        res.json({ success: true, usuario: emailFinal, clave: claveFinal });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// --- BOT Y OTROS ENDPOINTS ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
bot.launch({ dropPendingUpdates: true });

app.post('/admin/listar-usuarios', async (req, res) => {
    const { admin_secret } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });
    const snap = await db.collection('usuarios').get();
    res.json({ success: true, usuarios: snap.docs.map(d => d.data()) });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("🚀 SISTEMA GOLAZO v6.0 READY"));
