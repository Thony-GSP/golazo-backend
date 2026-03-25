const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');

// INICIALIZAR FIREBASE
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

// CONFIGURACIÓN 
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; 
const TOKEN_DURATION = 14400; // 4 horas

// MIDDLEWARE: Validar Token
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

// 🎯 ENDPOINT 1: GENERAR STREAM (ACTUALIZADO PARA HLS DIRECTORIO V2)
app.get('/generate-stream', authenticateUser, async (req, res) => {
    const uid = req.user.uid;

    try {
        const userDoc = await db.collection('usuarios').doc(uid).get();
        
        if (!userDoc.exists || userDoc.data().expires_at < Date.now()) {
            return res.status(403).json({ error: 'Suscripción inactiva o expirada' });
        }

        const newSessionId = crypto.randomUUID();
        await db.collection('usuarios').doc(uid).update({ session_id: newSessionId });

        // ✅ LÓGICA BUNNYCDN TOKEN V2 (Protege toda la carpeta)
        const expires = Math.floor(Date.now() / 1000) + TOKEN_DURATION;
        const pathAllowed = '/stream/'; 
        
        // Base matemática estricta de BunnyCDN V2
        const hashableBase = BUNNY_SECURITY_KEY + pathAllowed + expires + 'token_path=' + pathAllowed;
        
        // Encriptación SHA256
        const token = crypto.createHash('sha256').update(hashableBase).digest('base64')
            .replace(/\n/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        // Incrustar el token como un "directorio falso" para que no se pierda en los .ts
        const tokenFolder = `/bcdn_token=${token}&expires=${expires}&token_path=%2Fstream%2F`;
        const finalUrl = `${BUNNY_URL}${tokenFolder}/stream/canal.m3u8`;

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Backend corriendo en el puerto ${PORT}`);
});
