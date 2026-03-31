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

const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
const MI_CHAT_ID = process.env.MI_TELEGRAM_ID;

// --- LÓGICA DEL BOT MODERNA ---

bot.start(async (ctx) => {
    const doc = await db.collection('config_bot').doc('textos').get();
    const t = doc.exists ? doc.data() : { promo_hoy: "¡Bienvenidos!", partidos_cartelera: "Próximamente" };
    
    const bienvenida = `👋 ¡Hola! Bienvenido a **Golazo Stream Peru** ⚽. Disfruta de la mejor calidad sin cortes, estés donde estés. 🌍\n\n` +
                       `🔥 **Promociones de hoy:**\n${t.promo_hoy}\n\n` +
                       `Elige tu acceso:`;

    // Markup.removeKeyboard() borra los botones de abajo permanentemente
    ctx.replyWithMarkdown(bienvenida, {
        ...Markup.removeKeyboard(),
        ...Markup.inlineKeyboard([
            [Markup.button.callback('1️⃣ Partido Individual', 'ver_partidos')],
            [Markup.button.callback('2️⃣ Socio VIP Mensual 💎', 'ver_vip')],
            [Markup.button.callback('3️⃣ Oferta Especial', 'ver_oferta'), Markup.button.callback('4️⃣ Soporte 💬', 'ver_soporte')]
        ])
    });
});

// BOTONES DE PARTIDOS DINÁMICOS
bot.action('ver_partidos', async (ctx) => {
    await ctx.answerCbQuery();
    const doc = await db.collection('config_bot').doc('textos').get();
    const t = doc.data();
    
    // Convertimos tu texto del panel en botones individuales
    // Separamos el texto por saltos de línea (un botón por cada partido)
    const lineas = t.partidos_cartelera.split('\n').filter(l => l.trim() !== "");
    const botonesPartidos = lineas.map(partido => [Markup.button.callback(`⚽ ${partido}`, 'pago_individual')]);

    ctx.replyWithMarkdown(`🏟️ **Cartelera de hoy:**\nSelecciona el partido que deseas ver para proceder al pago:`, 
        Markup.inlineKeyboard(botonesPartidos)
    );
});

// FLUJO DE PAGO INDIVIDUAL
bot.action('pago_individual', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`✅ **Excelente elección.** El acceso para este partido es de **S/ 5.00 / $1.50 USD**.\n\n👇 **ELIGE TU MÉTODO DE PAGO:**`,
        Markup.inlineKeyboard([
            [Markup.button.callback('🇵🇪 Yape (Perú)', 'pago_yape')],
            [Markup.button.callback('🌎 PayPal / Binance', 'pago_extranjero')]
        ])
    );
});

bot.action('ver_vip', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`💎 **Socio VIP Golazo (30 días):**\n\nAcceso total a Liga 1 (YouTube VIP) y Torneos Internacionales (Web).\n💰 **S/ 20.00 / $5.50 USD**\n\n👇 **PAGA AQUÍ:**`,
        Markup.inlineKeyboard([
            [Markup.button.callback('🇵🇪 Yape (Perú)', 'pago_yape')],
            [Markup.button.callback('🌎 PayPal / Binance', 'pago_extranjero')]
        ])
    );
});

// MÉTODOS DE PAGO
bot.action('pago_yape', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`💳 **PAGO POR YAPE:**\n\nNúmero: **987 456 932**\nA nombre de: **Thony**\n\n🚀 **PASO FINAL:** Envía la captura del pago por aquí. Si compraste VIP, adjunta tu correo.`);
});

bot.action('pago_extranjero', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`🌐 **PAGO INTERNACIONAL:**\n\n🔹 **PayPal:** [Pagar ahora](https://paypal.me/thonytech)\n🔹 **Binance ID:** \`735707066\`\n\n🚀 **PASO FINAL:** Envía la captura del pago por aquí. Si compraste VIP, adjunta tu correo.`);
});

bot.action('ver_soporte', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`💬 **SOPORTE GOLAZO SP:**\n¿Problemas? Escribe a: @ThonyGeek`);
});

bot.on('photo', (ctx) => {
    ctx.reply("🚀 ¡Recibido! Un administrador verificará tu pago y te enviará los accesos de inmediato.");
    bot.telegram.sendPhoto(MI_CHAT_ID, ctx.message.photo[ctx.message.photo.length - 1].file_id, {
        caption: `🚨 **¡NUEVO PAGO!**\n👤 Cliente: @${ctx.from.username || 'SinUser'}\n🆔 ID: ${ctx.from.id}\n💬 Mensaje: ${ctx.message.caption || 'Sin texto'}`
    });
});

bot.launch();

// --- RESTO DE TUS ENDPOINTS (ADMIN Y BUNNY) ---
// (Mantenemos tus endpoints /admin/update-bot, generar-pase, etc., sin cambios)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 SERVIDOR GOLAZO v3.5 READY`));
