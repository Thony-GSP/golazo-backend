const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const { Telegraf, Markup } = require('telegraf');

// --- CONFIGURACIÓN DE FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

const app = express();
app.set('trust proxy', 1);

// --- CONFIGURACIÓN DE SEGURIDAD Y CORS (CRÍTICO PARA EL PANEL) ---
app.use(helmet({
    contentSecurityPolicy: false, // Permite que el panel conecte sin bloqueos de política
}));

app.use(cors({
    origin: '*', // Permite peticiones desde tu panel en GitHub Pages
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
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

bot.action(['pago_individual', 'ver_vip'], async (ctx) => {
    await ctx.answerCbQuery();
    const esVip = ctx.match === 'ver_vip';
    const texto = esVip ? `💎 **Socio VIP (30 días):** S/ 20.00` : `✅ **Pase Individual:** S/ 5.00`;
    ctx.replyWithMarkdown(`${texto}\n\n👇 **ELIGE TU MÉTODO DE PAGO:**`,
        Markup.inlineKeyboard([
            [Markup.button.callback('🇵🇪 Yape (Perú)', 'pago_yape')],
            [Markup.button.callback('🌎 PayPal / Binance', 'pago_extranjero')]
        ])
    );
});

bot.action('pago_yape', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`💳 **PAGO POR YAPE:**\n\nNúmero: **987 456 932**\nNombre: **Thony**\n\n🚀 Envía captura por aquí.`);
});

bot.action('pago_extranjero', async (ctx) => {
    await ctx.answerCbQuery();
    ctx.replyWithMarkdown(`🌐 **PAGO INTERNACIONAL:**\n\n🔹 **PayPal:** [Pagar](https://paypal.me/thonytech)\n🔹 **Binance ID:** \`735707066\`\n\n🚀 Envía captura por aquí.`);
});

bot.on('photo', (ctx) => {
    ctx.reply("🚀 ¡Recibido! Un administrador verificará tu pago y te enviará los accesos.");
    bot.telegram.sendPhoto(MI_CHAT_ID, ctx.message.photo[ctx.message.photo.length - 1].file_id, {
        caption: `🚨 **PAGO NUEVO**\n👤 @${ctx.from.username || 'SinUser'}\n🆔 ID: ${ctx.from.id}\n💬 ${ctx.message.caption || 'Sin texto'}`
    });
});

// Lanzar bot con limpieza de actualizaciones pendientes
bot.launch({ dropPendingUpdates: true });

// --- ENDPOINTS ADMINISTRATIVOS (CONEXIÓN CON EL PANEL) ---

app.post('/admin/update-bot', async (req, res) => {
    const { admin_secret, promo_hoy, partidos_cartelera, link_vip } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).send("No autorizado");
    try {
        await db.collection('config_bot').doc('textos').set({ promo_hoy, partidos_cartelera, link_vip });
        res.json({ success: true });
    } catch (e) { res.status(500).send(e.message); }
});

app.post('/admin/generar-pase-rapido', async (req, res) => {
    const { admin_secret, fecha_corte, partido, email_manual, pass_manual } = req.body;
    if (admin_secret !== ADMIN_SECRET) return res.status(403).json({ success: false, message: "Secret incorrecto" });

    try {
        const usuario = email_manual || `user_${crypto.randomBytes(3).toString('hex')}`;
        const clave = pass_manual || crypto.randomBytes(4).toString('hex');
        
        const nuevoAcceso = {
            usuario_corto: usuario,
            clave: clave,
            email: email_manual || "Pase Rápido",
            etiqueta: partido,
            fecha_expiracion: admin.firestore.Timestamp.fromDate(new Date(fecha_corte)),
            tipo: email_manual ? 'socio_mensual' : 'pase_individual',
            creado_el: admin.firestore.Timestamp.now()
        };

        await db.collection('usuarios').doc(usuario).set(nuevoAcceso);
        res.json({ success: true, usuario, clave, expira_en: new Date(fecha_corte).toLocaleString('es-PE') });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
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
                email: d.email,
                etiqueta: d.etiqueta,
                estado: rest > 0 ? "Activo" : "Caducado",
                esActivo: rest > 0,
                tiempo: rest > 0 ? (rest / 3600000).toFixed(1) + "h restantes" : "Vencido",
                tipo: d.tipo
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
            if (doc.data().fecha_expiracion.toDate() < ahora) {
                await doc.ref.delete();
                borrados++;
            }
        }
        res.json({ success: true, mensaje: `Se borraron ${borrados} pases caducados.` });
    } catch (e) { res.status(500).json({ success: false }); }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 SERVIDOR GOLAZO v3.5 READY`));
