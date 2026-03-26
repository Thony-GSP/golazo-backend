const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');

// 1. INICIALIZAR FIREBASE
// Asegúrate de tener la variable de entorno FIREBASE_JSON en Render con el contenido de tu archivo .json
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(express.json());

// 2. CONFIGURACIÓN DE STREAMING
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; 
const STREAM_PATH = '/stream/canal.m3u8';
const TOKEN_DURATION = 7200; // Reducido a 2 horas (ideal para un partido)

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
        console.error("Error validando Firebase Token:", error);
        res.status(401).json({ error: 'Token inválido' });
    }
};

// 🎯 ENDPOINT 1: GENERAR STREAM (LÓGICA BLINDADA V2)
app.get('/generate-stream', authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const userIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const userDoc = await db.collection('usuarios').doc(uid).get();

        // Validar si el usuario existe y si su suscripción no ha vencido
        if (!userDoc.exists || userDoc.data().expires_at < Date.now()) {
            return res.status(403).json({ error: 'Suscripción inactiva o expirada' });
        }

        // Control de Sesión Única: Generamos un ID de sesión nuevo
        const newSessionId = crypto.randomUUID();
        await db.collection('usuarios').doc(uid).update({ session_id: newSessionId });

        // LÓGICA DE TOKEN PARA BUNNYCDN (SEGURIDAD V2)
        const expires = Math.floor(Date.now() / 1000) + TOKEN_DURATION;
        const pathAllowed = '/stream/'; // Protege la carpeta completa incluyendo los .ts
        
        // Base para el Hash SHA256 (Formato requerido por BunnyCDN para Token in Path)
        const hashableBase = BUNNY_SECURITY_KEY + pathAllowed + expires + 'token_path=' + pathAllowed;
        
        // Generación del Hash SHA256 y limpieza de caracteres para URL
        const token = crypto.createHash('sha256')
            .update(hashableBase)
            .digest('base64')
            .replace(/\n/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        // Construcción de la URL usando "Token como Carpeta"
        // Esto permite que el reproductor herede el token para cada fragmento de video (.ts)
        const tokenFolder = `/bcdn_token=${token}&expires=${expires}&token_path=%2Fstream%2F`;
        const finalUrl = `${BUNNY_URL}${tokenFolder}${STREAM_PATH}`;

        console.log(`✅ Stream generado: UID ${uid} | IP ${userIp}`);

        res.json({
            stream_url: finalUrl,
            session_id: newSessionId
        });

    } catch (error) {
        console.error("Error en generate-stream:", error);
        res.status(500).json({ error: 'Error al generar el acceso al stream' });
    }
});

// 🎯 ENDPOINT 2: VALIDAR SESIÓN (HEARTBEAT)
app.post('/check-session', authenticateUser, async (req, res) => {
    const uid = req.user.uid;
    const { session_id } = req.body;

    try {
        const userDoc = await db.collection('usuarios').doc(uid).get();

        if (userDoc.exists && userDoc.data().session_id === session_id) {
            res.json({ valid: true });
        } else {
            res.json({ valid: false });
        }
    } catch (error) {
        console.error("Error en check-session:", error);
        res.status(500).json({ error: 'Error al validar sesión' });
    }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 GOLAZO SP Backend activo en puerto ${PORT}`);
});
