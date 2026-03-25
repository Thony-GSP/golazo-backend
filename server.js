const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');

// 1. INICIALIZAR FIREBASE CON VARIABLES DE ENTORNO
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

// 2. CONFIGURACIÓN DESDE EL ENTORNO
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; 
const STREAM_PATH = '/stream/canal.m3u8';
const TOKEN_DURATION = 14400; // 4 horas

// MIDDLEWARE: Validar Token de Firebase
const authenticateUser = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No autorizado' });
    }
    const idToken = authHeader.split('Bearer ')[1];
    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Token inválido' });
    }
};

// 🎯 ENDPOINT 1: GENERAR STREAM
app.get('/generate-stream', authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const userDoc = await db.collection('usuarios').doc(uid).get();
        
        // Validar si existe y si el plan está activo
        if (!userDoc.exists || userDoc.data().expires_at < Date.now()) {
            return res.status(403).json({ error: 'Suscripción inactiva o expirada' });
        }

        // Generar nuevo ID de sesión
        const newSessionId = crypto.randomUUID();
        await db.collection('usuarios').doc(uid).update({ session_id: newSessionId });

        // Generar Token BunnyCDN
        const expires = Math.floor(Date.now() / 1000) + TOKEN_DURATION;
        const hashString = BUNNY_SECURITY_KEY + STREAM_PATH + expires + userIp;
        const token = crypto.createHash('md5').update(hashString).digest('base64')
            .replace(/\n/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        const finalUrl = `${BUNNY_URL}${STREAM_PATH}?token=${token}&expires=${expires}`;

        res.json({
            stream_url: finalUrl,
            session_id: newSessionId
        });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// 📡 ENDPOINT 2: HEARTBEAT (ANTI MULTI-DISPOSITIVO)
app.post('/check-session', authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const clientSessionId = req.body.session_id;

    try {
        const userDoc = await db.collection('usuarios').doc(uid).get();
        const currentDbSessionId = userDoc.data().session_id;

        if (clientSessionId !== currentDbSessionId) {
            return res.json({ valid: false, message: 'Sesión iniciada en otro dispositivo' });
        }
        res.json({ valid: true });
    } catch (error) {
        res.status(500).json({ valid: false });
    }
});

// El puerto lo asigna Render automáticamente
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend corriendo en el puerto ${PORT}`);
});