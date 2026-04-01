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

// --- 2. CONFIGURACIÓN DE CORS (PARA GITHUB Y LITESPEED) ---
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));

app.use(express.json());

// --- 3. VARIABLES DE ENTORNO ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const MI_CHAT_ID = process.env.MI_TELEGRAM_ID;
const ADMIN_SECRET = process.env.ADMIN_SECRET;

// --- 4. RUTA PARA EL REPRODUCTOR (BUNNYCDN) ---
// Esta ruta elimina el error 404 en la consola de tu web
app.get('/generate-stream', (req, res) => {
    const URL_FINAL = "https://golazosp-stream.b-cdn.net/live/playlist.m3u8";
    res.json({
        success: true,
        url: URL_FINAL
    });
});

// --- 5. LÓGICA DEL BOT DE TELEGRAM ---
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

bot.action('ver_partidos', async (ctx) => {
    await ctx.answerCbQuery();
    const doc = await db.collection('config_bot').doc('textos').get();
    const t = doc.data() || { partidos_cartelera: "" };
    const lineas = t.partidos_cartelera.split('\n').filter(l => l.trim() !== "");
    const botonesPartidos = lineas.length > 0 
        ? lineas.map(partido => [Markup.button.callback(`⚽ ${partido}`, 'pago_individual')])
        : [[Markup.button.callback('Consultar horarios', 'ver_soporte')]];
    ctx.replyWithMarkdown(`🏟️ **Cartelera de hoy:**`, Markup.inlineKeyboard(botonesPartidos));
});

bot.on('photo', (ctx) => {
    ctx.reply("🚀 ¡Recibido! Un administrador verificará tu pago y enviará accesos.");
    bot.telegram.sendPhoto(MI_CHAT_ID, ctx.message.photo[ctx.message.photo.length - 1].file_id, {
        caption: `🚨 **PAGO NUEVO**\n👤 @${ctx.from.username || 'SinUser'}\n🆔 ID: ${ctx.from.id}\n💬 ${ctx.message.caption || 'Sin texto'}`
    });
});

// --- 6. LANZAMIENTO DEL BOT CON MANEJO DE CONFLICTO 409 ---
const iniciarBot = async () => {
    try {
        // Pausa de seguridad para que Render cierre la instancia anterior
        await new Promise(resolve => setTimeout(resolve, 5000));
        await bot.launch({ dropPendingUpdates: true });
        console.log("✅ Bot conectado correctamente.");
    } catch (err) {
        if (err.response && err.response.error_code === 409) {
            console.log("⚠️ Conflicto 409 detectado. Reintentando en 10 segundos...");
            setTimeout(iniciarBot, 10000);
        } else {
            console.error("❌ Error al lanzar el bot:", err);
        }
    }
};
iniciarBot();

// --- 7. ENDPOINTS ADMINISTRATIVOS (PANEL) ---
app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });

    try {
        const userRandom = crypto.randomBytes(3).toString('hex');
        const emailFinal = email_manual || `${userRandom}@golazosp.net`;
        const claveFinal = pass_manual || crypto.randomBytes(4).toString('hex');

        // CREAR EN FIREBASE AUTH (Para permitir Login)
        const userRecord = await auth.createUser({
            email: emailFinal,
            password: claveFinal,
            displayName: partido
        });

        // GUARDAR EN FIRESTORE (Usando UID real)
        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            clave: claveFinal,
            email: emailFinal,
            etiqueta: partido,
            fecha_expiracion: admin.firestore.Timestamp.fromDate(new Date(fecha_corte)),
            tipo: email_manual ? 'socio_mensual' : 'pase_individual',
            creado_el: admin.firestore.Timestamp.now()
        });

        res.json({ 
            success: true, 
            usuario: emailFinal, 
            clave: claveFinal, 
            expira_en: new Date(fecha_corte).toLocaleString('es-PE') 
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/admin/listar-usuarios', async (req, res) => {
    const { admin_secret } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false });
    try {
        const snapshot = await db.collection('usuarios').orderBy('creado_el', 'desc').get();
        const lista = snapshot.docs.map(doc => doc.data());
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
            if (doc.data().fecha_expiracion.toDate() < ahora) {
                try { await auth.deleteUser(doc.id); } catch (e) {}
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

// Manejo de cierres
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 SERVIDOR GOLAZO v5.1 READY`);
    console.log(`📺 Señal vinculada: https://golazosp-stream.b-cdn.net/live/playlist.m3u8`);
});
