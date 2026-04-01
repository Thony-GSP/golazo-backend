const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const { Telegraf, Markup } = require('telegraf');

// --- CONFIGURACIÓN DE FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const auth = admin.auth(); // Módulo de Autenticación

const app = express();
app.set('trust proxy', 1);

// --- CONFIGURACIÓN DE CORS (PARA GITHUB PAGES) ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());

// --- VARIABLES DE ENTORNO ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const MI_CHAT_ID = process.env.MI_TELEGRAM_ID;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- LÓGICA DEL BOT DE TELEGRAM ---

bot.start(async (ctx) => {
    try {
        const doc = await db.collection('config_bot').doc('textos').get();
        const t = doc.exists ? doc.data() : { promo_hoy: "¡Bienvenidos!", partidos_cartelera: "Próximamente" };
        
        const bienvenida = `👋 ¡Hola! Bienvenido a **Golazo Stream Peru** ⚽.\n\n` +
                           `🔥 **Promociones de hoy:**\n${t.promo_hoy}\n\n` +
                           `Elige tu acceso:`;

        ctx.replyWithMarkdown(bienvenida, {
            ...Markup.removeKeyboard(),
            ...Markup.inlineKeyboard([
                [Markup.button.callback('1️⃣ Partido Individual', 'ver_partidos')],
                [Markup.button.callback('2️⃣ Socio VIP Mensual 💎', 'ver_vip')],
                [Markup.button.callback('3️⃣ Oferta Especial', 'ver_oferta'), Markup.button.callback('4️⃣ Soporte 💬', 'ver_soporte')]
            ])
        });
    } catch (e) { console.error("Error en Start:", e); }
});

bot.on('photo', (ctx) => {
    ctx.reply("🚀 ¡Recibido! Un administrador verificará tu pago y enviará accesos.");
    bot.telegram.sendPhoto(MI_CHAT_ID, ctx.message.photo[ctx.message.photo.length - 1].file_id, {
        caption: `🚨 **PAGO NUEVO**\n👤 @${ctx.from.username || 'SinUser'}\n🆔 ID: ${ctx.from.id}\n💬 ${ctx.message.caption || 'Sin texto'}`
    });
});

bot.launch({ dropPendingUpdates: true });

// --- ENDPOINTS ADMINISTRATIVOS (CON FIREBASE AUTH) ---

app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        // 1. Definir credenciales (Firebase Auth requiere formato email)
        const userRandom = crypto.randomBytes(3).toString('hex');
        const emailFinal = email_manual || `${userRandom}@golazosp.net`;
        const claveFinal = pass_manual || crypto.randomBytes(4).toString('hex');

        // 2. CREAR USUARIO EN FIREBASE AUTH (Para que el login funcione)
        const userRecord = await auth.createUser({
            email: emailFinal,
            password: claveFinal,
            displayName: partido
        });

        // 3. GUARDAR DATOS EN FIRESTORE (Usando el UID del Auth)
        const nuevoAcceso = {
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            clave: claveFinal,
            email: emailFinal,
            etiqueta: partido,
            fecha_expiracion: admin.firestore.Timestamp.fromDate(new Date(fecha_corte)),
            tipo: email_manual ? 'socio_mensual' : 'pase_individual',
            creado_el: admin.firestore.Timestamp.now()
        };

        // El documento se guarda con el nombre del UID
        await db.collection('usuarios').doc(userRecord.uid).set(nuevoAcceso);

        res.json({ 
            success: true, 
            usuario: emailFinal, 
            clave: claveFinal, 
            expira_en: new Date(fecha_corte).toLocaleString('es-PE') 
        });

    } catch (error) {
        console.error("Error creando acceso:", error);
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/admin/listar-usuarios', async (req, res) => {
    const { admin_secret } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });
    try {
        const snapshot = await db.collection('usuarios').orderBy('creado_el', 'desc').get();
        const ahora = new Date();
        const lista = snapshot.docs.map(doc => {
            const d = doc.data();
            const exp = d.fecha_expiracion.toDate();
            const rest = exp - ahora;
            return {
                usuario_corto: d.usuario_corto,
                etiqueta: d.etiqueta,
                estado: rest > 0 ? "Activo" : "Caducado",
                esActivo: rest > 0,
                tiempo: rest > 0 ? (rest / 3600000).toFixed(1) + "h" : "Vencido"
            };
        });
        res.json({ success: true, usuarios: lista });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/admin/limpiar-caducados', async (req, res) => {
    const { admin_secret } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });
    
    try {
        const snapshot = await db.collection('usuarios').get();
        const ahora = new Date();
        let borrados = 0;

        for (const doc of snapshot.docs) {
            const data = doc.data();
            if (data.fecha_expiracion.toDate() < ahora) {
                // Borrar de Auth y de Firestore
                try {
                    await auth.deleteUser(doc.id); // doc.id es el UID
                } catch (e) { console.log("User no estaba en Auth o ya borrado"); }
                
                await doc.ref.delete();
                borrados++;
            }
        }
        res.json({ success: true, mensaje: `Se borraron ${borrados} pases.` });
    } catch (e) { res.status(500).json({ success: false }); }
});

app.post('/admin/update-bot', async (req, res) => {
    const { admin_secret, promo_hoy, partidos_cartelera, link_vip } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).send("No autorizado");
    await db.collection('config_bot').doc('textos').set({ promo_hoy, partidos_cartelera, link_vip });
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 SERVIDOR GOLAZO v3.8 READY (AUTH ENABLED)`));
