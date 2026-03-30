const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Telegraf, Markup } = require('telegraf');

const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const app = express();
app.set('trust proxy', 1);

app.use(helmet()); 
app.use(cors()); 
app.use(express.json());

// --- CONFIGURACIÓN DEL BOT DE TELEGRAM ---
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const MI_CHAT_ID = process.env.MI_TELEGRAM_ID;

bot.start(async (ctx) => {
    const doc = await db.collection('config_bot').doc('textos').get();
    const t = doc.exists ? doc.data() : { promo_hoy: "¡Bienvenidos!", partidos_cartelera: "Cargando..." };
    
    const bienvenida = `👋 ¡Hola! Bienvenido a **Golazo Stream Peru** ⚽. Disfruta de la mejor calidad sin cortes, estés donde estés. 🌍\n\n` +
                       `🔥 **Promociones de hoy:**\n${t.promo_hoy}\n\n` +
                       `Elige tu acceso:`;

    ctx.replyWithMarkdown(bienvenida, Markup.keyboard([
        ['1️⃣ Partido Individual', '2️⃣ Socio VIP Mensual'],
        ['3️⃣ Oferta Especial del Día', '4️⃣ Hablar con Soporte']
    ]).resize());
});

bot.hears('1️⃣ Partido Individual', async (ctx) => {
    const doc = await db.collection('config_bot').doc('textos').get();
    const t = doc.data();
    ctx.replyWithMarkdown(`⚽ **Elige el partido que quieres ver:**\n\n${t.partidos_cartelera}\n\n💰 **Precio:** S/ 5.00 / $1.50 USD\n\n👉 Realiza el pago y envía la captura aquí.`);
});

// FLUJO DE SOCIO VIP ACTUALIZADO (PAGO PRIMERO)
bot.hears('2️⃣ Socio VIP Mensual', (ctx) => {
    const vipTxt = `💎 **Socio VIP Golazo (30 días):**\n\n` +
                   `Acceso total a Liga 1 (YouTube VIP) y Torneos Internacionales (Web).\n\n` +
                   `💰 **Precio:** S/ 20.00 / $5.50 USD\n\n` +
                   `👇 **ELIGE TU MÉTODO DE PAGO:**`;

    ctx.replyWithMarkdown(vipTxt, Markup.inlineKeyboard([
        [Markup.button.callback('🇵🇪 Yape (Perú)', 'pago_yape')],
        [Markup.button.callback('🌎 PayPal / Binance (Internacional)', 'pago_extranjero')]
    ]));
});

// Acciones de pago
bot.action('pago_yape', (ctx) => {
    ctx.replyWithMarkdown(`💳 **PAGO POR YAPE:**\n\n` +
                   `Número: **987 456 932**\n` +
                   `A nombre de: **Thony**\n\n` +
                   `🚀 **PASO FINAL:** Envía la captura del pago y **ESCRIBE TU CORREO** aquí mismo para activar tu cuenta.`);
});

bot.action('pago_extranjero', (ctx) => {
    ctx.replyWithMarkdown(`🌐 **PAGO INTERNACIONAL:**\n\n` +
                   `🔹 **PayPal:** [Haz clic aquí para pagar](https://paypal.me/thonytech)\n` +
                   `🔹 **Binance Pay ID:** \`735707066\`\n\n` +
                   `🚀 **PASO FINAL:** Envía la captura del pago y **ESCRIBE TU CORREO** aquí mismo para activar tu cuenta.`);
});

bot.on('photo', (ctx) => {
    ctx.reply("🚀 ¡Recibido! El administrador verificará el depósito y te enviará tus accesos de inmediato.");
    bot.telegram.sendPhoto(MI_CHAT_ID, ctx.message.photo[ctx.message.photo.length - 1].file_id, {
        caption: `🚨 **¡NUEVO PAGO RECIBIDO!**\n👤 Cliente: @${ctx.from.username || 'SinUser'}\n🆔 ID: ${ctx.from.id}\n💬 Mensaje: ${ctx.message.caption || 'Sin texto'}`
    });
});

bot.launch();

// --- ENDPOINTS DE USUARIO (BUNNY CDN) ---
const BUNNY_URL = 'https://stream.golazosp.net'; 
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY; 
const STREAM_PATH = '/stream/canal.m3u8';

// (Aquí se mantiene tu lógica de generate-stream y check-session que ya tienes)

// --- ENDPOINTS DE ADMIN ---
app.post('/admin/update-bot', async (req, res) => {
    const { admin_secret, promo_hoy, partidos_cartelera, link_vip } = req.body;
    if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false });
    await db.collection('config_bot').doc('textos').set({ promo_hoy, partidos_cartelera, link_vip }, { merge: true });
    res.json({ success: true });
});

app.post('/admin/generar-pase-rapido', async (req, res) => {
    try {
        const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body; 
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false });
        const esSocio = !!email_manual;
        const emailFinal = email_manual || `${Math.floor(10000 + Math.random() * 90000)}@golazosp.net`;
        const passFinal = pass_manual || Math.floor(100000 + Math.random() * 900000).toString();
        const userRecord = await admin.auth().createUser({ email: emailFinal, password: passFinal });
        const expires = admin.firestore.Timestamp.fromDate(new Date(fecha_corte));
        await db.collection('usuarios').doc(userRecord.uid).set({
            email: emailFinal, usuario_corto: esSocio ? email_manual : emailFinal.split('@')[0], 
            expires_at: expires, tipo: esSocio ? 'socio_mensual' : 'pase_ocasional', etiqueta: partido || 'General', creado_el: admin.firestore.FieldValue.serverTimestamp()
        });
        const fF = new Date(fecha_corte).toLocaleString('es-PE', { timeZone: 'America/Lima' });
        res.json({ success: true, usuario: esSocio ? email_manual : emailFinal.split('@')[0], clave: passFinal, expira_en: fF });
    } catch (error) { res.status(500).json({ success: false, error: error.message }); }
});

app.post('/admin/listar-usuarios', async (req, res) => {
    try {
        const { admin_secret } = req.body;
        if (admin_secret !== process.env.PANEL_SECRET) return res.status(403).json({ success: false });
        const snap = await db.collection('usuarios').orderBy('creado_el', 'desc').limit(100).get();
        const ahora = Date.now();
        const usuarios = snap.docs.map(doc => {
            const d = doc.data();
            const rest = d.expires_at.toMillis() - ahora;
            let tT = "Expirado";
            if (rest > 0) {
                const h = Math.floor(rest / 3600000);
                const m = Math.floor((rest % 3600000) / 60000);
                tT = `${h}h ${m}m`;
            }
            return { 
                email: d.email, 
                usuario_corto: d.usuario_corto, 
                etiqueta: d.etiqueta, 
                estado: rest > 0 ? "ACTIVO ✅" : "CADUCADO ❌", 
                tiempo: tT, 
                esActivo: rest > 0,
                tipo: d.tipo,
                rest: rest
            };
        });
        res.json({ success: true, usuarios });
    } catch (e) { res.status(500).json({ success: false }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 SERVIDOR GOLAZO v2.8 READY`));
