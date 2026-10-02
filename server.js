const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const net = require('net');
const https = require('https');
const http = require('http');
const dns = require('dns');
const { monitorEventLoopDelay } = require('perf_hooks');

// Versión visible en GET / y en el registro de arranque (identifica el despliegue).
const VERSION_BACKEND = "FASE 10.18 - B13 integrado";

// --- 1. FIREBASE ---
const serviceAccount = JSON.parse(process.env.FIREBASE_JSON);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const auth = admin.auth();

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// --- 2. CORS RESTRINGIDO FINAL ---
const allowedOrigins = [
    'https://golazosp.net',
    'https://www.golazosp.net',
    'https://zonagolazo.net',
    'https://www.zonagolazo.net',
    'https://thony-gsp.github.io'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) {
            return callback(null, true);
        }

        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }

        console.warn(`❌ CORS bloqueado para origin: ${origin}`);
        return callback(null, false);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    // El navegador puede leer cuándo reintentar y la versión del catálogo.
    exposedHeaders: ['Retry-After', 'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset', 'X-Stream-Config-Version'],
    // Recuerda el permiso CORS 10 min: el latido deja de ir precedido de un OPTIONS.
    maxAge: parseInt(process.env.CORS_MAX_AGE_SECONDS || "600", 10),
    credentials: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.use(express.json());

// Las respuestas contienen sesiones, URLs firmadas y configuración en vivo.
// Ningún navegador, proxy o CDN debe reutilizarlas entre solicitudes.
app.use((req, res, next) => {
    res.set({
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Surrogate-Control': 'no-store'
    });
    res.vary('Origin');
    res.vary('Authorization');
    next();
});

// --- 2.1 DIAGNÓSTICO: IP DEL ESPECTADOR, VERSIONES Y MÉTRICAS ---
// En Render todo el tráfico entra por Cloudflare y por un proxy interno. Cloudflare
// escribe CF-Connecting-IP con la IP que se conectó; un cliente no puede fijarla a
// través de Cloudflare. Si faltara, se usa la primera IP de X-Forwarded-For y, en
// último caso, req.ip. En esta etapa solo se muestra en /diag/ip y en los registros.
function ipCliente(req) {
    if (String(process.env.IP_CLIENTE_ORIGEN || "auto").trim().toLowerCase() !== "express") {
        const cf = String(req.headers['cf-connecting-ip'] || '').trim();
        if (net.isIP(cf)) return cf;
        const primera = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
        if (net.isIP(primera)) return primera;
    }
    return req.ip || (req.socket && req.socket.remoteAddress) || 'desconocida';
}

// Clave de límite: la IPv4 completa o el bloque /64 de una IPv6 (un mismo abonado
// puede usar muchas direcciones de su bloque IPv6).
function claveIp(ip) {
    let valor = String(ip || '').trim();
    const zona = valor.indexOf('%');
    if (zona >= 0) valor = valor.slice(0, zona);
    if (/^::ffff:/i.test(valor) && net.isIPv4(valor.slice(7))) return valor.slice(7);
    if (!net.isIPv6(valor)) return valor;
    const aGrupos = (texto) => {
        if (!texto) return [];
        const grupos = texto.split(':');
        const ultimo = grupos[grupos.length - 1];
        if (ultimo.includes('.')) {
            const o = ultimo.split('.').map(Number);
            grupos.splice(grupos.length - 1, 1, ((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16));
        }
        return grupos;
    };
    const partes = valor.split('::');
    const izquierda = aGrupos(partes[0]);
    const derecha = partes.length > 1 ? aGrupos(partes[1]) : [];
    const ceros = partes.length > 1 ? new Array(Math.max(0, 8 - izquierda.length - derecha.length)).fill('0') : [];
    const grupos = izquierda.concat(ceros, derecha);
    return grupos.slice(0, 4).map(g => parseInt(g || '0', 16).toString(16)).join(':') + '::/64';
}

function versionDePaquete(nombre) {
    try {
        const rutas = require('path');
        let dir = rutas.dirname(require.resolve(nombre));
        for (let i = 0; i < 6; i++) {
            const archivo = rutas.join(dir, 'package.json');
            if (fs.existsSync(archivo)) {
                const datos = JSON.parse(fs.readFileSync(archivo, 'utf8'));
                if (datos.name === nombre) return String(datos.version || 'desconocida');
            }
            const padre = rutas.dirname(dir);
            if (padre === dir) break;
            dir = padre;
        }
    } catch (_) {}
    return 'desconocida';
}

const VERSIONES_DEPENDENCIAS = {
    node: process.version,
    express: versionDePaquete('express'),
    'express-rate-limit': versionDePaquete('express-rate-limit'),
    cors: versionDePaquete('cors'),
    'firebase-admin': versionDePaquete('firebase-admin')
};

// Registro de rechazos por límite: como máximo una línea cada 10 s por limitador.
// La respuesta es la misma que daba express-rate-limit (estado 429 y el mismo cuerpo).
const rechazosPorLimitador = {};
const ultimoAvisoLimitador = {};

function manejadorLimite(nombre, mensaje) {
    return (req, res) => {
        rechazosPorLimitador[nombre] = (rechazosPorLimitador[nombre] || 0) + 1;
        const ahora = Date.now();
        if (!ultimoAvisoLimitador[nombre] || ahora - ultimoAvisoLimitador[nombre] >= 10000) {
            ultimoAvisoLimitador[nombre] = ahora;
            console.warn(
                `LIMITE 429 [${nombre}] ruta=${req.path} ip_express=${req.ip} ip_real=${ipCliente(req)} ` +
                `rechazos_desde_arranque=${rechazosPorLimitador[nombre]}`
            );
        }
        res.status(429);
        if (!res.writableEnded) res.send(mensaje);
    };
}

// Métricas por minuto: solo cuentan y escriben una línea en los registros de Render.
// "espectadores" son las sesiones distintas con un latido válido en ese minuto.
function crearMetricas() {
    return {
        latidos: 0, sesiones: new Set(), pirateria: 0, expirado: 0, revocado: 0,
        generate: 0, nuevas: 0, reanudadas: 0, tomas: 0, conflictos: 0,
        liberadas: 0, ingresos: 0, ingresosFallidos: 0, r429: 0, r5xx: 0, total: 0,
        // B10: resúmenes de experiencia (/qoe) recibidos en el minuto.
        qoe: { n: 0, arranques: [], rebuffers: 0, rebufferMs: 0, errores: 0, minutos: 0 }
    };
}

let metricasMinuto = crearMetricas();

function registrarMetrica(req, res) {
    const m = metricasMinuto;
    const cuerpo = res.locals.golazoCuerpo || {};
    const estado = res.statusCode;
    m.total++;
    if (estado === 429) m.r429++;
    if (estado >= 500) m.r5xx++;

    if (req.path === '/check-session') {
        m.latidos++;
        if (cuerpo.valid === true && req.body && req.body.session_id) {
            m.sesiones.add(String(req.body.session_id).slice(0, 64));
        }
        if (cuerpo.motivo === 'pirateria') m.pirateria++;
        if (cuerpo.motivo === 'expirado') m.expirado++;
        if (cuerpo.motivo === 'revocado') m.revocado++;
    } else if (req.path === '/generate-stream') {
        m.generate++;
        if (estado === 409) m.conflictos++;
        if (cuerpo.success === true) {
            if (cuerpo.reused_session) m.reanudadas++;
            else m.nuevas++;
            if (cuerpo.takeover) m.tomas++;
        }
    } else if (req.path === '/release-session') {
        if (cuerpo.released === true) m.liberadas++;
    } else if (req.path === '/auth/quick-login') {
        m.ingresos++;
        if (estado === 401) m.ingresosFallidos++;
    }
}

app.use((req, res, next) => {
    const jsonOriginal = res.json;
    res.json = function (cuerpo) {
        res.locals.golazoCuerpo = cuerpo;
        return jsonOriginal.call(this, cuerpo);
    };
    res.on('finish', () => {
        try {
            registrarMetrica(req, res);
        } catch (_) {}
    });
    next();
});

// Historial de los últimos 60 minutos para el tablero del panel (B10). Solo en memoria: se reinicia
// con cada despliegue o reinicio del servicio.
const HISTORIAL_METRICAS_MAX = 60;
const historialMetricas = [];
let inicioMinutoMetricas = Date.now();

// Retardo del bucle de eventos: si sube, el servidor está saturado (responde tarde a todos).
const retardoBucle = typeof monitorEventLoopDelay === 'function' ? monitorEventLoopDelay({ resolution: 20 }) : null;
if (retardoBucle) retardoBucle.enable();
let retardoUltimoMinuto = null;

function medianaDe(valores) {
    if (!valores.length) return null;
    const orden = [...valores].sort((a, b) => a - b);
    const mitad = Math.floor(orden.length / 2);
    return orden.length % 2 ? orden[mitad] : Math.round((orden[mitad - 1] + orden[mitad]) / 2);
}

function resumirQoe(q) {
    return {
        reportes: q.n,
        arranque_mediana_ms: medianaDe(q.arranques),
        rebuffers: q.rebuffers,
        rebuffer_s: Math.round(q.rebufferMs / 1000),
        errores: q.errores,
        minutos: Math.round(q.minutos * 10) / 10
    };
}

function resumirMetricas(m, inicio) {
    return {
        inicio_ms: inicio,
        espectadores: m.sesiones.size, latidos: m.latidos, pirateria: m.pirateria, expirado: m.expirado,
        revocado: m.revocado, generate: m.generate, nuevas: m.nuevas, reanudadas: m.reanudadas, tomas: m.tomas,
        conflictos: m.conflictos, liberadas: m.liberadas, ingresos: m.ingresos, ingresos_fallidos: m.ingresosFallidos,
        r429: m.r429, r5xx: m.r5xx, total: m.total, qoe: resumirQoe(m.qoe)
    };
}

const temporizadorMetricas = setInterval(() => {
    const m = metricasMinuto;
    const inicio = inicioMinutoMetricas;
    metricasMinuto = crearMetricas();
    inicioMinutoMetricas = Date.now();
    const resumen = resumirMetricas(m, inicio);
    if (retardoBucle) {
        // El monitor mide el intervalo completo (20 ms de muestreo incluidos): se informa solo la demora.
        const demora = (ns) => Math.max(0, Math.round((ns - 20e6) / 1e5) / 10);
        retardoUltimoMinuto = {
            p50_ms: demora(retardoBucle.percentile(50)),
            p99_ms: demora(retardoBucle.percentile(99)),
            max_ms: demora(retardoBucle.max)
        };
        retardoBucle.reset();
        resumen.retardo_p99_ms = retardoUltimoMinuto.p99_ms;
    }
    historialMetricas.push(resumen);
    if (historialMetricas.length > HISTORIAL_METRICAS_MAX) historialMetricas.shift();
    try { alCerrarMinuto(resumen); } catch (_) {}
    if (!m.total) return;
    console.log(
        `METRICAS 1 min | espectadores=${m.sesiones.size} | latidos=${m.latidos} pirateria=${m.pirateria} ` +
        `expirado=${m.expirado} revocado=${m.revocado} | generate=${m.generate} nuevas=${m.nuevas} ` +
        `reanudadas=${m.reanudadas} tomas=${m.tomas} 409=${m.conflictos} | liberadas=${m.liberadas} | ` +
        `ingresos=${m.ingresos} fallidos=${m.ingresosFallidos} | 429=${m.r429} 5xx=${m.r5xx}`
    );
}, 60 * 1000);
if (temporizadorMetricas.unref) temporizadorMetricas.unref();

// --- 3. RATE LIMITS CONFIGURABLES ---
const GENERAL_RATE_LIMIT_MAX = parseInt(process.env.GENERAL_RATE_LIMIT_MAX || "120", 10);
const ADMIN_RATE_LIMIT_MAX = parseInt(process.env.ADMIN_RATE_LIMIT_MAX || "20", 10);
const CREATE_PASS_RATE_LIMIT_MAX = parseInt(process.env.CREATE_PASS_RATE_LIMIT_MAX || "100", 10);
const QUICK_LOGIN_RATE_LIMIT_MAX = parseInt(process.env.QUICK_LOGIN_RATE_LIMIT_MAX || "12", 10);
// Rutas de reproducción: tope por IP y tope por usuario. El tope por IP solo cuenta las
// solicitudes rechazadas por identidad (400, 401, 403: token falso, cuenta sin pase), de
// modo que los espectadores legítimos detrás de una misma IP pública (CGNAT) nunca lo
// consumen; frena inundaciones con tokens inválidos. Un espectador genera unas 3,5
// solicitudes por minuto: 40 por usuario dejan margen para reintentos.
const AUTH_IP_RATE_LIMIT_MAX = parseInt(process.env.AUTH_IP_RATE_LIMIT_MAX || "1200", 10);
const STREAM_UID_RATE_LIMIT_MAX = parseInt(process.env.STREAM_UID_RATE_LIMIT_MAX || "40", 10);
// Ingreso con código: tope total por IP (aciertos y fallos) contra inundaciones y aviso
// en el registro si los fallos de todo el sitio superan este número en un minuto.
const QUICK_LOGIN_FLOOD_MAX = parseInt(process.env.QUICK_LOGIN_FLOOD_MAX || "300", 10);
const QUICK_LOGIN_ALERT_PER_MIN = parseInt(process.env.QUICK_LOGIN_ALERT_PER_MIN || "30", 10);
// Segundo freno contra la adivinación: fallos por IP en una hora. Con 12 por minuto un
// atacante probaría 720 códigos por hora desde una sola IP; con este tope, 60.
const QUICK_LOGIN_FAILS_PER_HOUR = parseInt(process.env.QUICK_LOGIN_FAILS_PER_HOUR || "60", 10);

const RUTAS_REPRODUCCION = new Set(['/generate-stream', '/check-session', '/release-session']);
const RUTAS_CON_LIMITE_PROPIO = new Set(['/generate-stream', '/check-session', '/release-session', '/auth/quick-login', '/qoe']);
const claveLimitePorIp = (req) => claveIp(ipCliente(req));

const MENSAJE_LIMITE_GENERAL = {
    success: false,
    code: "RATE_LIMIT",
    error: "Demasiadas solicitudes."
};

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: GENERAL_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skip: (req) => req.method === 'OPTIONS' || req.path === '/health' || RUTAS_CON_LIMITE_PROPIO.has(req.path),
    message: MENSAJE_LIMITE_GENERAL,
    handler: manejadorLimite("general", MENSAJE_LIMITE_GENERAL)
});

const MENSAJE_LIMITE_STREAM = {
    success: false,
    code: "STREAM_RATE_LIMIT",
    error: "Demasiadas solicitudes de stream."
};

// Respuestas que cuentan como "rechazo por identidad" en los topes por IP.
const esRechazoDeIdentidad = (res) => res.statusCode === 400 || res.statusCode === 401 || res.statusCode === 403;

const limiteIpReproduccion = rateLimit({
    windowMs: 60 * 1000,
    max: AUTH_IP_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skipSuccessfulRequests: true,
    requestWasSuccessful: (req, res) => !esRechazoDeIdentidad(res),
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_STREAM,
    handler: manejadorLimite("reproduccion-ip", MENSAJE_LIMITE_STREAM)
});

const limiteUidReproduccion = rateLimit({
    windowMs: 60 * 1000,
    max: STREAM_UID_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => 'uid:' + req.golazoUid,
    skip: (req) => req.method === 'OPTIONS' || !req.golazoUid,
    message: MENSAJE_LIMITE_STREAM,
    handler: manejadorLimite("reproduccion-uid", MENSAJE_LIMITE_STREAM)
});

const MENSAJE_LIMITE_ADMIN = {
    success: false,
    code: "ADMIN_RATE_LIMIT",
    error: "Demasiadas solicitudes administrativas."
};

const adminLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: ADMIN_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_ADMIN,
    handler: manejadorLimite("admin", MENSAJE_LIMITE_ADMIN)
});

const MENSAJE_LIMITE_CREAR_PASE = {
    success: false,
    code: "CREATE_PASS_RATE_LIMIT",
    error: "Demasiadas solicitudes de creación de pases."
};

const createPassLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: CREATE_PASS_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_CREAR_PASE,
    handler: manejadorLimite("crear-pase", MENSAJE_LIMITE_CREAR_PASE)
});

const MENSAJE_LIMITE_INGRESO = {
    success: false,
    code: "QUICK_LOGIN_RATE_LIMIT",
    error: "Demasiados intentos de código. Intenta nuevamente en un momento."
};

// Solo cuentan los códigos rechazados (400, 401, 403): una red compartida con muchos
// espectadores que escriben su código correcto ya no se bloquea, y un fallo pasajero del
// servidor (5xx) no se cobra como intento fallido.
const quickLoginLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: QUICK_LOGIN_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skipSuccessfulRequests: true,
    requestWasSuccessful: (req, res) => !esRechazoDeIdentidad(res),
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_INGRESO,
    handler: manejadorLimite("ingreso", MENSAJE_LIMITE_INGRESO)
});

const quickLoginHourlyLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: QUICK_LOGIN_FAILS_PER_HOUR,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skipSuccessfulRequests: true,
    requestWasSuccessful: (req, res) => !esRechazoDeIdentidad(res),
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_INGRESO,
    handler: manejadorLimite("ingreso-hora", MENSAJE_LIMITE_INGRESO)
});

const quickLoginFloodLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: QUICK_LOGIN_FLOOD_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_INGRESO,
    handler: manejadorLimite("ingreso-total", MENSAJE_LIMITE_INGRESO)
});

// Identifica al usuario (ID token verificado) antes del tope por usuario. Si el token
// falta o no es válido, no se identifica y la ruta responde 401 como siempre.
async function identificarUsuario(req, res, next) {
    try {
        const cabecera = req.headers.authorization || "";
        const token = cabecera.startsWith("Bearer ")
            ? cabecera.replace("Bearer ", "").trim()
            : String((req.body && req.body.id_token) || "").trim();
        if (token) {
            req.golazoToken = token;
            const decodificado = await auth.verifyIdToken(token);
            req.golazoUid = decodificado.uid;
            req.golazoDecodificado = decodificado;
        }
    } catch (error) {
        req.golazoErrorToken = error;
    }
    next();
}

// La ruta reutiliza la verificación ya hecha para este mismo token en esta solicitud
// (misma garantía, sin repetir la verificación criptográfica, tampoco si falló).
async function verificarIdToken(req, token) {
    if (req.golazoToken === token) {
        if (req.golazoDecodificado) return req.golazoDecodificado;
        if (req.golazoErrorToken) throw req.golazoErrorToken;
    }
    return auth.verifyIdToken(token);
}

const limitesReproduccion = [limiteIpReproduccion, identificarUsuario, limiteUidReproduccion];

// Aviso si llegan solicitudes sin CF-Connecting-IP: en Render todas pasan por Cloudflare,
// así que su ausencia indica un cambio de topología que conviene revisar con /diag/ip.
let solicitudesSinCf = 0;
let ultimoAvisoSinCf = 0;

app.use((req, res, next) => {
    if (!req.headers['cf-connecting-ip'] && req.method !== 'OPTIONS') {
        solicitudesSinCf++;
        const ahora = Date.now();
        if (ahora - ultimoAvisoSinCf >= 10 * 60 * 1000) {
            ultimoAvisoSinCf = ahora;
            console.warn(
                `AVISO IP: llegan solicitudes sin CF-Connecting-IP (${solicitudesSinCf} desde el arranque; ` +
                `ruta=${req.path}). Revise /diag/ip: los límites usan la primera IP de X-Forwarded-For.`
            );
        }
    }
    next();
});

// Aviso de adivinación distribuida de códigos: cuenta los fallos de todo el sitio.
let fallosIngresoMinuto = { inicio: Date.now(), total: 0, redes: new Set(), avisado: false };

app.use('/auth/quick-login', (req, res, next) => {
    res.on('finish', () => {
        if (res.statusCode !== 401) return;
        const ahora = Date.now();
        if (ahora - fallosIngresoMinuto.inicio >= 60 * 1000) {
            fallosIngresoMinuto = { inicio: ahora, total: 0, redes: new Set(), avisado: false };
        }
        fallosIngresoMinuto.total++;
        if (fallosIngresoMinuto.redes.size < 5000) fallosIngresoMinuto.redes.add(claveLimitePorIp(req));
        if (!fallosIngresoMinuto.avisado && fallosIngresoMinuto.total >= QUICK_LOGIN_ALERT_PER_MIN) {
            fallosIngresoMinuto.avisado = true;
            console.warn(
                `ALERTA ingreso: ${fallosIngresoMinuto.total} intentos fallidos de código en menos de un minuto ` +
                `desde ${fallosIngresoMinuto.redes.size} redes distintas (posible adivinación de códigos).`
            );
            // B11: el mismo aviso por Telegram, si está activado.
            enviarAlerta(`Posible adivinación de códigos: ${fallosIngresoMinuto.total} intentos fallidos en menos de un minuto desde ${fallosIngresoMinuto.redes.size} redes distintas.`);
        }
    });
    next();
});

app.use(generalLimiter);

// --- 4. CONFIGURACIÓN ---
const BUNNY_CDN_URL = 'https://stream.golazosp.net';
const BUNNY_SECURITY_KEY = process.env.BUNNY_KEY.trim();
const STREAM_PATH = '/stream/master.m3u8';

// Selector de fuente de stream.
// Valores permitidos:
// iframe   = usa el reproductor aislado de player-latam-hd.site.
// external = usa la señal HLS directa de live.site.pe.
// bunny    = usa Bunny CDN con token firmado.
const STREAM_MODE_DEFAULT = String(process.env.STREAM_MODE || "bunny").trim().toLowerCase();
const EXTERNAL_STREAM_URL_DEFAULT = String(
    process.env.EXTERNAL_STREAM_URL || "https://live.site.pe/live/golazosp.m3u8"
).trim();
const IFRAME_PLAYER_URL_DEFAULT = String(
    process.env.IFRAME_PLAYER_URL ||
    "https://player-latam-hd.site/index.php?prov=la14hd&stream=sv24je.html&v=5"
).trim();
const STREAM_FALLBACK_ORDER_DEFAULT = ["iframe", "external", "bunny"];

// Cache para no leer Firestore en cada /generate-stream.
const STREAM_CONFIG_CACHE_TTL_MS = parseInt(
    process.env.STREAM_CONFIG_CACHE_TTL_MS || "5000",
    10
);

const MAX_TRANSMISSIONS = 10;
const MAX_OPTIONS_PER_TRANSMISSION = 5;

let cachedStreamConfig = null;
let cachedStreamConfigExpiresAt = 0;

// Resistencia de la configuración: una sola lectura en curso compartida, refresco
// forzado (refresh_config=1) como máximo cada 2 s y, si Firestore falla, se conserva
// la última configuración válida en lugar de cambiar a la transmisión por defecto.
const STREAM_CONFIG_FORCE_MIN_INTERVAL_MS = parseInt(
    process.env.STREAM_CONFIG_FORCE_MIN_INTERVAL_MS || "2000",
    10
);
let ultimaLecturaConfigAt = 0;
let ultimaConfigValida = null;
// Origen de la última lectura: "firestore", "ultima_valida" o "respaldo" (B9: el panel solo edita lo leído de Firestore).
let ultimoOrigenConfig = "";
let generacionConfig = 0;
let lecturaConfigEnCurso = null;

// Los códigos antiguos pueden estar firmados con la clave anterior de Bunny.
// Cuando se configura un secreto nuevo, se aceptan esos códigos y su hash se
// actualiza después de un ingreso correcto. Si también se rota BUNNY_KEY,
// QUICK_CODE_LEGACY_SECRET debe conservar el valor con el que se firmaron.
const QUICK_CODE_SECRET = (process.env.QUICK_CODE_SECRET || process.env.BUNNY_KEY || "").trim();
const QUICK_CODE_LEGACY_SECRET = (
    process.env.QUICK_CODE_LEGACY_SECRET ||
    (process.env.QUICK_CODE_SECRET ? process.env.BUNNY_KEY : "") ||
    ""
).trim();

// URL pública de la web para generar links rápidos
const APP_BASE_URL = process.env.APP_BASE_URL || "https://golazosp.net";

// --- 4.1 OPTIMIZACIÓN DE ESCALA ---
const HEARTBEAT_WRITE_MIN_INTERVAL_MS = parseInt(
    process.env.HEARTBEAT_WRITE_MIN_INTERVAL_MS || "90000",
    10
);

const ACTIVE_SESSION_WINDOW_MS = parseInt(
    process.env.ACTIVE_SESSION_WINDOW_MS || "150000",
    10
);

const BUNNY_TOKEN_DURATION_SECONDS = parseInt(
    process.env.BUNNY_TOKEN_DURATION_SECONDS || "600",
    10
);

// Tomas de control (CONTINUAR AQUÍ): 0 = sin tope (solo se cuentan y registran).
// Con un número, por ejemplo 6, el séptimo traspaso de la última hora recibe 429
// TAKEOVER_LIMIT y el cliente reintenta más tarde. Retomar el mismo equipo no cuenta.
const TAKEOVER_MAX_PER_HOUR = Math.min(50, Math.max(0, parseInt(process.env.TAKEOVER_MAX_PER_HOUR || "0", 10) || 0));
// El registro guarda al menos tope + 1 marcas de tiempo, para poder contar la última hora.
const TAKEOVER_LOG_MAX = Math.max(10, TAKEOVER_MAX_PER_HOUR + 1);

const BUNNY_CAST_TOKEN_DURATION_SECONDS = parseInt(
    process.env.BUNNY_CAST_TOKEN_DURATION_SECONDS || "14400",
    10
);

// --- 5. HEALTH CHECK ---
// Render puede comprobar este endpoint sin depender de Firestore ni de Bunny.
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));

app.get('/', (req, res) => {
    res.json({
        success: true,
        service: "Golazo Stream Backend",
        status: "online",
        version: VERSION_BACKEND,
        stream_mode_default: STREAM_MODE_DEFAULT,
        // B9: minutos de gracia de la limpieza de vencidos (el panel los muestra al confirmar).
        limpieza_gracia_min: CLEANUP_GRACE_MINUTES
    });
});

// --- 5.1 DIAGNÓSTICO PROTEGIDO ---
// Existe solo si la variable DIAG_KEY tiene 16 caracteres o más. Se abre como
// /diag/ip?k=CLAVE. Con otra clave responde igual que una ruta inexistente.
// Muestra la IP con que el servidor ve a quien consulta y las versiones instaladas.
const DIAG_KEY = String(process.env.DIAG_KEY || "").trim();

if (DIAG_KEY.length >= 16) {
    app.get('/diag/ip', (req, res, next) => {
        const recibida = crypto.createHash('sha256').update(String(req.query.k || req.headers['x-diag-key'] || '')).digest();
        const esperada = crypto.createHash('sha256').update(DIAG_KEY).digest();
        if (!crypto.timingSafeEqual(recibida, esperada)) return next();

        return res.json({
            version: VERSION_BACKEND,
            ip_express: req.ip || null,
            ip_socket: (req.socket && req.socket.remoteAddress) || null,
            x_forwarded_for: req.headers['x-forwarded-for'] || null,
            cf_connecting_ip: req.headers['cf-connecting-ip'] || null,
            true_client_ip: req.headers['true-client-ip'] || null,
            x_real_ip: req.headers['x-real-ip'] || null,
            ip_para_limites: ipCliente(req),
            clave_de_limite: claveIp(ipCliente(req)),
            trust_proxy: app.get('trust proxy'),
            versiones: VERSIONES_DEPENDENCIAS,
            rechazos_429_desde_arranque: rechazosPorLimitador,
            segundos_encendido: Math.round(process.uptime())
        });
    });
}

// --- 6. HELPERS GENERALES ---
function getTimestampMillis(value) {
    return value && typeof value.toMillis === "function"
        ? value.toMillis()
        : 0;
}

function shouldWriteHeartbeat(userData, now, minIntervalMs = HEARTBEAT_WRITE_MIN_INTERVAL_MS) {
    const lastHeartbeatMillis = getTimestampMillis(userData.last_heartbeat);

    if (!lastHeartbeatMillis) return true;
    return now - lastHeartbeatMillis >= minIntervalMs;
}

function nowTimestamp() {
    return admin.firestore.Timestamp.now();
}

function normalizeClientId(value) {
    const normalized = String(value || "").trim();

    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(normalized)) {
        return "";
    }

    return normalized;
}

async function verifyUserRequest(req) {
    const authHeader = req.headers.authorization || "";
    const tokenFromHeader = authHeader.startsWith("Bearer ")
        ? authHeader.replace("Bearer ", "").trim()
        : "";
    const tokenFromBody = String(req.body?.id_token || "").trim();
    const idToken = tokenFromHeader || tokenFromBody;

    if (!idToken) return null;

    try {
        return await verificarIdToken(req, idToken);
    } catch (_) {
        return null;
    }
}

function normalizeStreamSource(value) {
    const source = String(value || "").trim().toLowerCase();

    if (source === "iframe") return "iframe";
    if (source === "external" || source === "hls") return "external";
    if (source === "bunny") return "bunny";

    return "bunny";
}

function normalizeFallbackOrder(value, primarySource = "iframe") {
    const rawOrder = Array.isArray(value)
        ? value
        : String(value || "").split(",");
    const validSources = new Set(["iframe", "external", "bunny"]);
    const normalized = [];

    [primarySource, ...rawOrder, ...STREAM_FALLBACK_ORDER_DEFAULT].forEach((item) => {
        const source = String(item || "").trim().toLowerCase();
        if (validSources.has(source) && !normalized.includes(source)) {
            normalized.push(source);
        }
    });

    return normalized;
}

function isValidHttpUrl(value) {
    try {
        const url = new URL(String(value || "").trim());
        return url.protocol === "http:" || url.protocol === "https:";
    } catch (_) {
        return false;
    }
}

function normalizeCatalogId(value, fallback = "") {
    const normalized = String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 64);

    return normalized || fallback;
}

function normalizeDisplayText(value, maxLength = 80) {
    return String(value || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, maxLength);
}

function createCatalogId(prefix) {
    return `${prefix}-${crypto.randomBytes(6).toString("hex")}`;
}

function normalizeBunnyPath(value) {
    let path = String(value || STREAM_PATH).trim();

    if (isValidHttpUrl(path)) {
        try {
            path = new URL(path).pathname;
        } catch (_) {
            return "";
        }
    }

    if (!path.startsWith("/")) path = `/${path}`;
    if (!path.startsWith("/stream/") || path.includes("..")) return "";
    if (!/\.m3u8$/i.test(path)) return "";

    return path;
}

function normalizeTransmissionCatalog(rawTransmissions, strict = false) {
    const errors = [];
    const transmissions = [];
    const transmissionIds = new Set();
    const input = Array.isArray(rawTransmissions)
        ? rawTransmissions.slice(0, MAX_TRANSMISSIONS)
        : [];

    input.forEach((rawTransmission, transmissionIndex) => {
        if (!rawTransmission || typeof rawTransmission !== "object") {
            if (strict) errors.push(`Transmisión ${transmissionIndex + 1}: formato inválido.`);
            return;
        }

        let transmissionId = normalizeCatalogId(
            rawTransmission.id,
            `transmision-${transmissionIndex + 1}`
        );
        if (transmissionIds.has(transmissionId)) {
            transmissionId = strict
                ? createCatalogId("transmision")
                : `${transmissionId}-${transmissionIndex + 1}`;
        }
        transmissionIds.add(transmissionId);

        const name = normalizeDisplayText(
            rawTransmission.name || rawTransmission.title,
            80
        );
        const channel = normalizeDisplayText(rawTransmission.channel, 80);
        const visible = rawTransmission.visible !== false;
        const options = [];
        const optionIds = new Set();
        const rawOptions = Array.isArray(rawTransmission.options)
            ? rawTransmission.options.slice(0, MAX_OPTIONS_PER_TRANSMISSION)
            : [];

        if (!name && strict) {
            errors.push(`Transmisión ${transmissionIndex + 1}: falta el nombre visible.`);
        }

        if (
            Array.isArray(rawTransmission.options) &&
            rawTransmission.options.length > MAX_OPTIONS_PER_TRANSMISSION
        ) {
            errors.push(
                `${name || `Transmisión ${transmissionIndex + 1}`}: ` +
                `solo se permiten ${MAX_OPTIONS_PER_TRANSMISSION} opciones.`
            );
        }

        rawOptions.forEach((rawOption, optionIndex) => {
            if (!rawOption || typeof rawOption !== "object") {
                if (strict) errors.push(`${name || `Transmisión ${transmissionIndex + 1}`}: opción inválida.`);
                return;
            }

            let optionId = normalizeCatalogId(
                rawOption.id,
                `opcion-${optionIndex + 1}`
            );
            if (optionIds.has(optionId)) {
                optionId = strict
                    ? createCatalogId("opcion")
                    : `${optionId}-${optionIndex + 1}`;
            }
            optionIds.add(optionId);

            const rawSourceType = String(
                rawOption.source_type || rawOption.type || ""
            ).trim().toLowerCase();

            if (!["iframe", "external", "hls", "bunny"].includes(rawSourceType)) {
                if (strict) errors.push(
                    `${name || transmissionId} / Opción ${optionIndex + 1}: tipo de fuente inválido.`
                );
                return;
            }

            const sourceType = normalizeStreamSource(rawSourceType);
            const label = normalizeDisplayText(
                rawOption.label || `Opción ${optionIndex + 1}`,
                40
            );
            const enabled = rawOption.enabled !== false && rawOption.visible !== false;
            const option = {
                id: optionId,
                label,
                source_type: sourceType,
                enabled
            };

            if (sourceType === "bunny") {
                option.path = normalizeBunnyPath(rawOption.path || rawOption.url);
                if (!option.path) {
                    if (strict) errors.push(`${name || transmissionId} / ${label}: ruta Bunny inválida.`);
                    return;
                }
            } else {
                option.url = String(rawOption.url || "").trim();
                if (!isValidHttpUrl(option.url)) {
                    if (strict) errors.push(`${name || transmissionId} / ${label}: URL inválida.`);
                    return;
                }
            }

            options.push(option);
        });

        if (!options.length && strict) {
            errors.push(`${name || `Transmisión ${transmissionIndex + 1}`}: agrega al menos una opción válida.`);
        }

        const requestedDefaultOptionId = normalizeCatalogId(
            rawTransmission.default_option_id
        );
        const firstEnabledOption = options.find(option => option.enabled) || options[0];
        const defaultOption = options.find(
            option => option.id === requestedDefaultOptionId && option.enabled
        ) || firstEnabledOption;

        if (name && options.length) {
            transmissions.push({
                id: transmissionId,
                name,
                channel,
                visible,
                default_option_id: defaultOption?.id || "",
                options
            });
        }
    });

    if (Array.isArray(rawTransmissions) && rawTransmissions.length > MAX_TRANSMISSIONS) {
        errors.push(`Solo se permiten ${MAX_TRANSMISSIONS} transmisiones.`);
    }

    return { transmissions, errors };
}

function createStreamConfigVersion(config) {
    const stableConfig = {
        default_transmission_id: String(config.default_transmission_id || ""),
        transmissions: config.transmissions || [],
        active_source: String(config.active_source || ""),
        external_url: String(config.external_url || ""),
        iframe_url: String(config.iframe_url || ""),
        fallback_order: config.fallback_order || []
    };

    return crypto
        .createHash("sha256")
        .update(JSON.stringify(stableConfig))
        .digest("hex")
        .slice(0, 16);
}

function createLegacyTransmission(config) {
    const activeSource = normalizeStreamSource(config.active_source);
    const option = {
        id: "opcion-1",
        label: "Opción 1",
        source_type: activeSource,
        enabled: true
    };

    if (activeSource === "iframe") option.url = config.iframe_url;
    if (activeSource === "external") option.url = config.external_url;
    if (activeSource === "bunny") option.path = STREAM_PATH;

    return {
        id: "transmision-principal",
        name: "Transmisión principal",
        channel: "",
        visible: true,
        default_option_id: option.id,
        options: [option]
    };
}

// Lee la fuente activa desde Firestore.
// Ruta Firestore recomendada:
// collection: config
// document: stream
async function getActiveStreamConfig(forceRefresh = false) {
    const now = Date.now();
    const cacheVigente = cachedStreamConfig && now < cachedStreamConfigExpiresAt;

    if (cacheVigente && (!forceRefresh || now - ultimaLecturaConfigAt < STREAM_CONFIG_FORCE_MIN_INTERVAL_MS)) {
        return cachedStreamConfig;
    }

    if (lecturaConfigEnCurso && lecturaConfigEnCurso.generacion === generacionConfig) {
        return lecturaConfigEnCurso.promesa;
    }

    const generacion = generacionConfig;
    const promesa = leerStreamConfig(generacion).finally(() => {
        if (lecturaConfigEnCurso && lecturaConfigEnCurso.promesa === promesa) {
            lecturaConfigEnCurso = null;
        }
    });
    lecturaConfigEnCurso = { generacion, promesa };
    return promesa;
}

// Tras un cambio desde el panel: las lecturas anteriores ya no llenan la caché.
function invalidarStreamConfig() {
    generacionConfig++;
    cachedStreamConfig = null;
    cachedStreamConfigExpiresAt = 0;
    ultimaLecturaConfigAt = 0;
}

async function leerStreamConfig(generacion) {
    const now = Date.now();
    const vigente = () => generacion === generacionConfig;

    let config = {
        schema_version: 1,
        active_source: normalizeStreamSource(STREAM_MODE_DEFAULT),
        external_url: EXTERNAL_STREAM_URL_DEFAULT,
        iframe_url: IFRAME_PLAYER_URL_DEFAULT,
        fallback_order: normalizeFallbackOrder(null, normalizeStreamSource(STREAM_MODE_DEFAULT)),
        default_transmission_id: "",
        transmissions: []
    };

    try {
        const doc = await db.collection("config").doc("stream").get();

        if (doc.exists) {
            const data = doc.data() || {};

            config = {
                schema_version: Number(data.schema_version || 1),
                active_source: normalizeStreamSource(data.active_source || STREAM_MODE_DEFAULT),
                external_url: String(data.external_url || EXTERNAL_STREAM_URL_DEFAULT).trim(),
                iframe_url: String(data.iframe_url || IFRAME_PLAYER_URL_DEFAULT).trim(),
                fallback_order: normalizeFallbackOrder(
                    data.fallback_order,
                    normalizeStreamSource(data.active_source || STREAM_MODE_DEFAULT)
                ),
                default_transmission_id: normalizeCatalogId(data.default_transmission_id),
                transmissions: []
            };

            if (Array.isArray(data.transmissions)) {
                config.schema_version = 2;
                config.transmissions = normalizeTransmissionCatalog(
                    data.transmissions,
                    false
                ).transmissions;
            }
        }

        if (!isValidHttpUrl(config.external_url)) {
            console.warn("⚠️ external_url inválida. Se restauró el valor predeterminado.");
            config.external_url = EXTERNAL_STREAM_URL_DEFAULT;
            if (config.active_source === "external") config.active_source = "bunny";
        }

        if (!isValidHttpUrl(config.iframe_url)) {
            console.warn("⚠️ iframe_url inválida. Se restauró el valor predeterminado.");
            config.iframe_url = IFRAME_PLAYER_URL_DEFAULT;
            if (config.active_source === "iframe") config.active_source = "bunny";
        }

        config.fallback_order = normalizeFallbackOrder(
            config.fallback_order,
            config.active_source
        );

        if (config.schema_version < 2) {
            config.transmissions = [createLegacyTransmission(config)];
            config.default_transmission_id = config.transmissions[0].id;
        } else {
            const visibleTransmissions = config.transmissions.filter(transmission =>
                transmission.visible && transmission.options.some(option => option.enabled)
            );

            if (!visibleTransmissions.some(
                transmission => transmission.id === config.default_transmission_id
            )) {
                config.default_transmission_id = visibleTransmissions[0]?.id || "";
            }
        }

        config.version = createStreamConfigVersion(config);

        if (vigente()) {
            cachedStreamConfig = config;
            cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;
            ultimaLecturaConfigAt = Date.now();
            ultimaConfigValida = config;
        }

        ultimoOrigenConfig = "firestore";
        return config;

    } catch (error) {
        console.error("❌ Error leyendo config stream desde Firestore:", error.message);

        if (ultimaConfigValida) {
            console.warn(`Se mantiene la última configuración válida (versión ${ultimaConfigValida.version}).`);
            ultimoOrigenConfig = "ultima_valida";
            if (vigente()) {
                cachedStreamConfig = ultimaConfigValida;
                cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;
                ultimaLecturaConfigAt = Date.now();
            }
            return ultimaConfigValida;
        }

        config.transmissions = [createLegacyTransmission(config)];
        config.default_transmission_id = config.transmissions[0].id;
        config.version = createStreamConfigVersion(config);
        ultimoOrigenConfig = "respaldo";

        if (vigente()) {
            cachedStreamConfig = config;
            cachedStreamConfigExpiresAt = now + STREAM_CONFIG_CACHE_TTL_MS;
            ultimaLecturaConfigAt = Date.now();
        }

        return config;
    }
}

// --- 7. GENERADOR DE TOKEN BUNNY PARA DIRECTORIOS ---
function base64Url(buffer) {
    return buffer.toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
        .replace(/\n/g, "");
}

function generateBunnyTokenForStream(path, securityKey, duration = 120) {
    const expires = Math.floor(Date.now() / 1000) + duration;

    const tokenPath = "/stream/";
    const signaturePath = tokenPath;
    const signingData = `token_path=${tokenPath}`;
    const userIp = "";

    const message = `${signaturePath}${expires}${signingData}${userIp}`;

    const token = "HS256-" + base64Url(
        crypto.createHmac("sha256", securityKey)
            .update(message)
            .digest()
    );

    const encodedTokenPath = encodeURIComponent(tokenPath);

    return {
        token,
        expires,
        token_path: tokenPath,
        url: `${BUNNY_CDN_URL}/bcdn_token=${token}&expires=${expires}&token_path=${encodedTokenPath}${path}`
    };
}

function materializeTransmissionCatalog(config, tokenDuration) {
    const transmissions = (config.transmissions || [])
        .filter(transmission => transmission.visible)
        .map(transmission => {
            const options = transmission.options
                .filter(option => option.enabled)
                .map(option => {
                    if (option.source_type === "bunny") {
                        const signed = generateBunnyTokenForStream(
                            option.path,
                            BUNNY_SECURITY_KEY,
                            tokenDuration
                        );

                        return {
                            id: option.id,
                            label: option.label,
                            source_type: "bunny",
                            type: "hls",
                            url: signed.url,
                            expires: signed.expires
                        };
                    }

                    return {
                        id: option.id,
                        label: option.label,
                        source_type: option.source_type,
                        type: option.source_type === "iframe" ? "iframe" : "hls",
                        url: option.url
                    };
                });

            if (!options.length) return null;

            const defaultOption = options.find(
                option => option.id === transmission.default_option_id
            ) || options[0];

            return {
                id: transmission.id,
                name: transmission.name,
                channel: transmission.channel,
                default_option_id: defaultOption.id,
                options
            };
        })
        .filter(Boolean);

    const defaultTransmission = transmissions.find(
        transmission => transmission.id === config.default_transmission_id
    ) || transmissions[0] || null;

    return {
        transmissions,
        default_transmission_id: defaultTransmission?.id || ""
    };
}

// --- 8. MIDDLEWARE ADMIN ESTRICTO ---
// Errores que sí significan «token inválido» (401). Cualquier otro error al verificar es de Google o de la red.
const ERRORES_DE_TOKEN_ADMIN = new Set([
    "auth/argument-error", "auth/invalid-argument", "auth/id-token-expired", "auth/invalid-id-token",
    "auth/user-not-found", "auth/id-token-revoked", "auth/user-disabled"
]);

// Registro de acciones de los administradores (B9): quién hizo qué y cuándo. Una escritura por acción;
// si falla, la acción no se detiene (queda la línea ADMIN en los registros de Render).
// expira_en permite activar en Firestore una política de TTL que borre las entradas antiguas (opcional).
const REGISTRO_ADMIN_DIAS = Math.max(1, parseInt(process.env.ADMIN_LOG_RETENTION_DAYS || "365", 10) || 365);
function registrarAccionAdmin(req, accion, resumen, detalle = {}) {
    const autor = req.golazoAdmin || {};
    const entrada = {
        accion,
        resumen: String(resumen || "").slice(0, 300),
        detalle,
        actor_uid: autor.uid || "",
        actor_email: autor.email || "",
        ip: ipCliente(req),
        en: nowTimestamp(),
        expira_en: admin.firestore.Timestamp.fromMillis(Date.now() + REGISTRO_ADMIN_DIAS * 24 * 60 * 60 * 1000)
    };
    console.log(`ADMIN ${accion} | ${entrada.actor_email || entrada.actor_uid || "sin autor"} | ${entrada.resumen}`);
    db.collection('registro_admin').add(entrada).catch(error => {
        console.error("❌ No se pudo guardar el registro de la acción:", error.message);
    });
}

async function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            success: false,
            message: "Falta token de administrador"
        });
    }

    const idToken = authHeader.replace("Bearer ", "").trim();

    try {
        // checkRevoked: una sesión de administrador revocada (o una cuenta deshabilitada) deja de operar
        // de inmediato, sin esperar a que venza su token de una hora.
        const decodedToken = await auth.verifyIdToken(idToken, true);

        if (decodedToken.admin === true) {
            req.golazoAdmin = { uid: decodedToken.uid, email: decodedToken.email || "" };
            // B10: un ingreso nuevo (otra vez usuario y contraseña) queda en el registro y, si están activadas, avisa por Telegram.
            notarIngresoAdmin(req, decodedToken);
            return next();
        }

        return res.status(403).json({
            success: false,
            message: "Permisos denegados. No eres administrador."
        });

    } catch (error) {
        console.error("❌ Token admin inválido:", error.message);

        if (error.code === "auth/id-token-revoked" || error.code === "auth/user-disabled") {
            return res.status(401).json({
                success: false,
                code: "ADMIN_SESSION_REVOKED",
                message: "La sesión de administrador fue revocada. Vuelva a ingresar."
            });
        }

        // Comprobar la revocación consulta a Google en cada solicitud. Si Google no responde (red, cuota,
        // error interno), no es un token inválido: 503 para que el panel reintente sin cerrar la sesión.
        if (!ERRORES_DE_TOKEN_ADMIN.has(error.code)) {
            return res.status(503).json({
                success: false,
                code: "ADMIN_CHECK_UNAVAILABLE",
                message: "No se pudo verificar la sesión con Google en este momento. Reintente en unos segundos."
            });
        }

        return res.status(401).json({
            success: false,
            message: "Token de administrador inválido o expirado"
        });
    }
}

// --- 9. EXTRAER IP y USER-AGENT ---
function getClientData(req) {
    const ip = ipCliente(req);

    const userAgent = req.headers['user-agent'] || 'Desconocido';

    return { ip, userAgent };
}


// --- 9.1 GESTIÓN DE ACCESOS Y ANALÍTICA ---
function formatPeruDateKey(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return "sin-fecha";

    return new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Lima',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
    }).format(date);
}

function buildEventId(label, dateValue) {
    const normalizedLabel = normalizeDisplayText(label || "Sin etiqueta", 80).toLowerCase();
    const dateKey = formatPeruDateKey(dateValue);

    return crypto
        .createHash('sha256')
        .update(`${normalizedLabel}|${dateKey}`)
        .digest('hex')
        .slice(0, 16);
}

function getUserEventId(data) {
    if (data?.event_id) return String(data.event_id);

    const label = normalizeDisplayText(data?.etiqueta || "Sin etiqueta", 80).toLowerCase();
    return `legacy-${crypto.createHash('sha256').update(label).digest('hex').slice(0, 12)}`;
}

function summarizeUserAgent(userAgent) {
    if (!userAgent || userAgent === "Sin registro") return "Sin registro";

    const ua = String(userAgent).toLowerCase();

    if (ua.includes("tizen")) return "Samsung TV";
    if (ua.includes("webos")) return "LG Smart TV";
    if (ua.includes("android tv")) return "Android TV";
    if (ua.includes("aft") || ua.includes("fire tv")) return "Fire TV";
    if (ua.includes("roku")) return "Roku TV";
    if (ua.includes("smart-tv") || ua.includes("smarttv") || ua.includes("hbbtv")) return "Smart TV";
    if (ua.includes("iphone")) return "iPhone";
    if (ua.includes("ipad")) return "iPad";
    if (ua.includes("android")) return "Android";
    if (ua.includes("windows")) return "Windows";
    if (ua.includes("mac os")) return "Mac";
    if (ua.includes("edg")) return "Edge";
    if (ua.includes("chrome")) return "Chrome";
    if (ua.includes("firefox")) return "Firefox";
    if (ua.includes("safari") && !ua.includes("chrome")) return "Safari";

    return "Navegador";
}

function isRevokedUser(data) {
    return data?.last_status === "revoked_by_admin" ||
        String(data?.session_id || "").startsWith("revoked_");
}

function isUserWatchingNow(data, now = Date.now()) {
    const expiraMillis = getTimestampMillis(data?.fecha_expiracion);
    const lastHeartbeatMillis = getTimestampMillis(data?.last_heartbeat);
    const sessionId = String(data?.session_id || "");
    const status = String(data?.last_status || "");

    if (!expiraMillis || expiraMillis <= now) return false;
    if (!lastHeartbeatMillis || now - lastHeartbeatMillis >= ACTIVE_SESSION_WINDOW_MS) return false;
    if (!sessionId || sessionId.startsWith("revoked_")) return false;
    if (["expired", "revoked_by_admin", "released"].includes(status)) return false;

    return true;
}

function userNeverEntered(data) {
    return !data?.last_quick_login_at &&
        !data?.last_heartbeat &&
        !data?.session_started_at;
}

function serializeExtensionHistory(history) {
    if (!Array.isArray(history)) return [];

    return history.map(item => ({
        at_ms: getTimestampMillis(item?.at),
        mode: item?.mode || "add",
        minutes: Number.isFinite(Number(item?.minutes)) ? Number(item.minutes) : null,
        old_expiration_ms: getTimestampMillis(item?.old_expiration),
        new_expiration_ms: getTimestampMillis(item?.new_expiration),
        old_label: item?.old_label || "",
        new_label: item?.new_label || ""
    }));
}

async function syncEventPeaks(eventSummaries) {
    if (!eventSummaries.length) return eventSummaries;

    const refs = eventSummaries.map(item => db.collection('event_stats').doc(item.event_id));
    const snaps = await db.getAll(...refs);
    const batch = db.batch();
    let needsCommit = false;

    snaps.forEach((snap, index) => {
        const summary = eventSummaries[index];
        const storedPeak = snap.exists ? Number(snap.data()?.peak_concurrent || 0) : 0;
        const finalPeak = Math.max(storedPeak, summary.viendo_ahora);
        summary.peak_concurrent = finalPeak;

        if (!snap.exists || finalPeak > storedPeak) {
            batch.set(refs[index], {
                event_id: summary.event_id,
                etiqueta: summary.etiqueta,
                peak_concurrent: finalPeak,
                updated_at: nowTimestamp()
            }, { merge: true });
            needsCommit = true;
        }
    });

    if (needsCommit) await batch.commit();
    return eventSummaries;
}

// --- 10. CÓDIGO RÁPIDO DE ACCESO ---
function normalizarCodigoRapido(value) {
    return String(value || "")
        .replace(/\D/g, "")
        .trim();
}

function hashQuickCode(code) {
    if (!QUICK_CODE_SECRET) {
        throw new Error("Falta QUICK_CODE_SECRET o BUNNY_KEY para firmar códigos rápidos.");
    }

    return hashQuickCodeWithSecret(code, QUICK_CODE_SECRET);
}

function hashQuickCodeWithSecret(code, secret) {
    return crypto
        .createHmac("sha256", secret)
        .update(String(code).trim())
        .digest("hex");
}

async function findQuickCodeHash(hash) {
    return db.collection("usuarios")
        .where("quick_code_hash", "==", hash)
        .limit(1)
        .get();
}

function generarCodigoSeisDigitos() {
    return crypto.randomInt(100000, 1000000).toString();
}

async function generarCodigoRapidoUnico(maxIntentos = 20) {
    for (let i = 0; i < maxIntentos; i++) {
        const codigo = generarCodigoSeisDigitos();
        const hash = hashQuickCode(codigo);

        const snap = await findQuickCodeHash(hash);

        if (!snap.empty) continue;

        // Evita reutilizar un código activo que todavía usa el hash antiguo.
        if (QUICK_CODE_LEGACY_SECRET && QUICK_CODE_LEGACY_SECRET !== QUICK_CODE_SECRET) {
            const legacyHash = hashQuickCodeWithSecret(codigo, QUICK_CODE_LEGACY_SECRET);
            const legacySnap = await findQuickCodeHash(legacyHash);
            if (!legacySnap.empty) continue;
        }

        // Un código ya vendido y archivado no se vuelve a asignar: su comprador anterior
        // puede conservarlo (mensaje, enlace ?c=) y entraría con el pase del nuevo comprador.
        const archivado = await db.collection("historial_accesos")
            .where("usuario_corto", "==", `${codigo}@golazosp.net`)
            .limit(1)
            .get();

        if (archivado.empty) {
            return { codigo, hash };
        }
    }

    throw new Error("No se pudo generar un código rápido único.");
}

function generarPasswordInternoSeguro() {
    return crypto.randomBytes(24).toString("base64url");
}

// --- 11. LOGIN RÁPIDO POR CÓDIGO ---
app.post('/auth/quick-login', quickLoginFloodLimiter, quickLoginLimiter, quickLoginHourlyLimiter, async (req, res) => {
    try {
        const codigo = normalizarCodigoRapido(req.body?.codigo);

        if (!/^\d{6}$/.test(codigo)) {
            return res.status(400).json({
                success: false,
                code: "INVALID_CODE",
                error: "Código inválido."
            });
        }

        const codeHash = hashQuickCode(codigo);

        let snap = await findQuickCodeHash(codeHash);
        let legacyMatch = false;

        if (snap.empty && QUICK_CODE_LEGACY_SECRET && QUICK_CODE_LEGACY_SECRET !== QUICK_CODE_SECRET) {
            snap = await findQuickCodeHash(hashQuickCodeWithSecret(codigo, QUICK_CODE_LEGACY_SECRET));
            legacyMatch = !snap.empty;
        }

        if (snap.empty) {
            return res.status(401).json({
                success: false,
                code: "CODE_NOT_FOUND",
                error: "Código incorrecto."
            });
        }

        const doc = snap.docs[0];
        const uid = doc.id;
        const userData = doc.data();

        if (!userData.fecha_expiracion || typeof userData.fecha_expiracion.toMillis !== "function") {
            return res.status(403).json({
                success: false,
                code: "NO_EXPIRATION",
                error: "Pase sin expiración."
            });
        }

        const expiraMillis = userData.fecha_expiracion.toMillis();
        const ahora = Date.now();

        if (expiraMillis <= ahora) {
            if (userData.last_status !== "expired") {
                await doc.ref.update({
                    last_status: "expired",
                    last_heartbeat: nowTimestamp()
                });
            }

            return res.status(403).json({
                success: false,
                code: "PASS_EXPIRED",
                error: "El pase ha caducado."
            });
        }

        if (
            userData.last_status === "revoked_by_admin" ||
            String(userData.session_id || "").startsWith("revoked_")
        ) {
            return res.status(403).json({
                success: false,
                code: "SESSION_REVOKED",
                error: "Pase revocado por administración."
            });
        }

        const { ip, userAgent } = getClientData(req);

        const customToken = await auth.createCustomToken(uid, {
            login_mode: "quick_code",
            tipo_acceso: "partido"
        });

        await doc.ref.update({
            last_login_method: "quick_code",
            last_quick_login_at: nowTimestamp(),
            last_ip: ip,
            last_user_agent: userAgent,
            ...(legacyMatch ? { quick_code_hash: codeHash } : {})
        });

        return res.json({
            success: true,
            customToken,
            expires_at: expiraMillis
        });

    } catch (error) {
        console.error("❌ Error en /auth/quick-login:", error);

        return res.status(500).json({
            success: false,
            code: "SERVER_ERROR",
            error: "Error del servidor."
        });
    }
});

// --- 12. GENERATE STREAM OPTIMIZADO + SELECTOR BUNNY/EXTERNAL ---
app.get('/generate-stream', ...limitesReproduccion, async (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                code: "NO_AUTH"
            });
        }

        const idToken = authHeader.replace("Bearer ", "").trim();

        let decodedToken;
        try {
            decodedToken = await verificarIdToken(req, idToken);
        } catch (authError) {
            return res.status(401).json({
                success: false,
                code: "INVALID_AUTH"
            });
        }

        const uid = decodedToken.uid;
        const requestedSessionId = normalizeClientId(req.query.session_id);
        const deviceId = normalizeClientId(req.query.device_id);
        const pageId = normalizeClientId(req.query.page_id);
        const takeoverRequested = req.query.takeover === "1";
        const forceConfigRefresh = req.query.refresh_config === "1";
        const castRequested = req.query.cast === "1";

        // Los clientes reales (en-directo, tv) siempre envían ambos identificadores.
        // Sin ellos, un cliente modificado podría renovar la sesión de otro equipo sin
        // desplazarlo (dos equipos a la vez con un código).
        if (!deviceId || !pageId) {
            return res.status(400).json({
                success: false,
                code: "MISSING_CLIENT_ID",
                error: "Faltan los identificadores del dispositivo."
            });
        }

        const userRef = db.collection('usuarios').doc(uid);
        const ahora = Date.now();
        const { ip, userAgent } = getClientData(req);

        let decision;

        await db.runTransaction(async transaction => {
            const userDoc = await transaction.get(userRef);

            if (!userDoc.exists) {
                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "PASS_INACTIVE"
                    }
                };
                return;
            }

            const userData = userDoc.data() || {};

            if (!userData.fecha_expiracion || typeof userData.fecha_expiracion.toMillis !== "function") {
                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "NO_EXPIRATION"
                    }
                };
                return;
            }

            const expiraMillis = userData.fecha_expiracion.toMillis();
            const segundosRestantesPase = Math.floor((expiraMillis - ahora) / 1000);

            if (segundosRestantesPase <= 0) {
                if (userData.last_status !== "expired") {
                    transaction.update(userRef, {
                        last_status: "expired",
                        last_heartbeat: nowTimestamp(),
                        last_ip: ip,
                        last_user_agent: userAgent
                    });
                }

                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "PASS_EXPIRED",
                        error: "Pase expirado"
                    }
                };
                return;
            }

            if (
                userData.last_status === "revoked_by_admin" ||
                String(userData.session_id || "").startsWith("revoked_")
            ) {
                decision = {
                    ok: false,
                    status: 403,
                    body: {
                        success: false,
                        code: "SESSION_REVOKED",
                        error: "Sesión revocada por administración"
                    }
                };
                return;
            }

            const lastHeartbeatMillis = getTimestampMillis(userData.last_heartbeat);
            const sesionActivaReciente = Boolean(
                userData.session_id &&
                !String(userData.session_id).startsWith("revoked_") &&
                userData.last_status !== "expired" &&
                userData.last_status !== "revoked_by_admin" &&
                lastHeartbeatMillis &&
                ahora - lastHeartbeatMillis < ACTIVE_SESSION_WINDOW_MS
            );

            // El session_id solo sirve desde el equipo que lo creó: otro equipo con el
            // mismo session_id debe confirmar el traspaso (CONTINUAR AQUÍ).
            const mismaSesion = Boolean(
                requestedSessionId &&
                requestedSessionId === userData.session_id &&
                (!userData.active_device_id || userData.active_device_id === deviceId)
            );

            // Caso clave anti-409:
            // Si el navegador dispara dos generate-stream casi juntos, el segundo
            // puede llegar sin session_id porque el frontend aún no alcanzó a guardarlo.
            // Si viene del mismo device_id y el mismo page_id activos, se trata como
            // la misma página y se devuelve la sesión existente, no un 409.
            const mismaPaginaActiva = Boolean(
                !requestedSessionId &&
                sesionActivaReciente &&
                deviceId &&
                pageId &&
                userData.active_device_id === deviceId &&
                userData.active_page_id === pageId
            );

            const sesionReutilizable = mismaSesion || mismaPaginaActiva;

            // Toma de control efectiva: hay otra sesión activa, de otro equipo, y el
            // usuario confirmó CONTINUAR AQUÍ.
            const esTomaEfectiva = Boolean(
                sesionActivaReciente &&
                !sesionReutilizable &&
                takeoverRequested &&
                !(deviceId && userData.active_device_id === deviceId)
            );
            const historialTomas = Array.isArray(userData.takeover_log)
                ? userData.takeover_log.filter(t => Number.isFinite(t))
                : [];
            const tomasUltimaHora = historialTomas.filter(t => ahora - t < 60 * 60 * 1000);

            if (esTomaEfectiva && TAKEOVER_MAX_PER_HOUR > 0 && tomasUltimaHora.length >= TAKEOVER_MAX_PER_HOUR) {
                const reintentarEn = Math.max(
                    1,
                    Math.ceil((Math.min(...tomasUltimaHora) + 60 * 60 * 1000 - ahora) / 1000)
                );
                decision = {
                    ok: false,
                    status: 429,
                    retryAfter: reintentarEn,
                    body: {
                        success: false,
                        code: "TAKEOVER_LIMIT",
                        error: "Demasiados cambios de dispositivo en la última hora.",
                        retry_after_s: reintentarEn
                    }
                };
                return;
            }

            // Un session_id inventado, antiguo o una página distinta no debe saltarse
            // el bloqueo, salvo que el usuario pulse CONTINUAR AQUÍ / takeover=1.
            if (sesionActivaReciente && !sesionReutilizable && !takeoverRequested) {
                decision = {
                    ok: false,
                    status: 409,
                    body: {
                        success: false,
                        code: "SESSION_ALREADY_ACTIVE",
                        error: "Ya existe una sesión activa para este usuario.",
                        can_takeover: true
                    }
                };
                return;
            }

            let sessionIdFinal = userData.session_id || "";
            let createdNewSession = false;

            if (!sesionReutilizable) {
                sessionIdFinal = crypto.randomUUID();
                createdNewSession = true;

                const nuevaSesion = {
                    session_id: sessionIdFinal,
                    session_started_at: nowTimestamp(),
                    last_heartbeat: nowTimestamp(),
                    last_status: takeoverRequested ? "stream_takeover" : "stream_started",
                    last_ip: ip,
                    last_user_agent: userAgent,
                    active_device_id: deviceId,
                    active_page_id: pageId,
                    last_takeover_at: takeoverRequested ? nowTimestamp() : null
                };

                if (esTomaEfectiva) {
                    nuevaSesion.takeover_count = Number(userData.takeover_count || 0) + 1;
                    nuevaSesion.takeover_log = historialTomas
                        .filter(t => ahora - t < 24 * 60 * 60 * 1000)
                        .concat(ahora)
                        .slice(-TAKEOVER_LOG_MAX);
                    nuevaSesion.last_takeover_device = summarizeUserAgent(userAgent);
                }

                transaction.update(userRef, nuevaSesion);
            } else {
                const sessionPatch = {};

                // Actualizar page_id en cada carga evita que el cierre de una página
                // anterior libere accidentalmente una sesión recién reanudada.
                if (pageId && pageId !== userData.active_page_id) {
                    sessionPatch.active_page_id = pageId;
                }

                if (deviceId && deviceId !== userData.active_device_id) {
                    sessionPatch.active_device_id = deviceId;
                }

                if (shouldWriteHeartbeat(userData, ahora)) {
                    sessionPatch.last_heartbeat = nowTimestamp();
                    sessionPatch.last_status = mismaPaginaActiva
                        ? "stream_reattached"
                        : "stream_renewed";
                    sessionPatch.last_ip = ip;
                    sessionPatch.last_user_agent = userAgent;
                }

                if (Object.keys(sessionPatch).length) {
                    transaction.update(userRef, sessionPatch);
                }
            }

            decision = {
                ok: true,
                sessionIdFinal,
                expiraMillis,
                segundosRestantesPase,
                reusedSession: sesionReutilizable,
                reattachedSamePage: mismaPaginaActiva,
                takeoverApplied: takeoverRequested && createdNewSession,
                createdNewSession,
                tomaEfectiva: esTomaEfectiva,
                tomasUltimaHora: tomasUltimaHora.length + (esTomaEfectiva ? 1 : 0)
            };
        });

        if (!decision || !decision.ok) {
            const status = decision?.status || 500;
            const body = decision?.body || {
                success: false,
                code: "SERVER_ERROR"
            };
            if (decision?.retryAfter) res.set('Retry-After', String(decision.retryAfter));
            if (body.code === "TAKEOVER_LIMIT") {
                console.warn(`TOMA DE CONTROL RECHAZADA uid=${uid} tope=${TAKEOVER_MAX_PER_HOUR}/h reintentar_en=${decision.retryAfter}s`);
            }
            return res.status(status).json(body);
        }

        if (decision.tomaEfectiva) {
            console.log(`TOMA DE CONTROL uid=${uid} tomas_ultima_hora=${decision.tomasUltimaHora} dispositivo=${summarizeUserAgent(userAgent)}`);
        }

        const tokenDuration = Math.min(
            castRequested
                ? BUNNY_CAST_TOKEN_DURATION_SECONDS
                : BUNNY_TOKEN_DURATION_SECONDS,
            decision.segundosRestantesPase
        );

        // Catálogo dinámico para los clientes nuevos. También se mantienen los
        // campos legacy hasta terminar la migración de en-directo.html y tv.html.
        const streamConfig = await getActiveStreamConfig(forceConfigRefresh);
        const playbackCatalog = materializeTransmissionCatalog(
            streamConfig,
            tokenDuration
        );
        const signed = generateBunnyTokenForStream(
            STREAM_PATH,
            BUNNY_SECURITY_KEY,
            tokenDuration
        );
        const sources = {
            iframe: {
                type: "iframe",
                url: streamConfig.iframe_url
            },
            external: {
                type: "hls",
                url: streamConfig.external_url
            },
            bunny: {
                type: "hls",
                url: signed.url
            }
        };
        const fallbackOrder = normalizeFallbackOrder(
            streamConfig.fallback_order,
            streamConfig.active_source
        );
        const legacyHlsSource = fallbackOrder.find((source) => sources[source]?.type === "hls") || "bunny";
        const finalUrl = sources[legacyHlsSource].url;
        const bunnyExpires = signed.expires;

        console.log(
            `✅ Stream [${decision.reusedSession ? 'RENOVADO' : 'NUEVO'}] | uid=${uid} | transmisiones=${playbackCatalog.transmissions.length} | legacy=${legacyHlsSource} | duration=${tokenDuration}s | cast=${castRequested ? '1' : '0'} | reattach=${decision.reattachedSamePage ? '1' : '0'} | takeover=${decision.takeoverApplied ? '1' : '0'}`
        );

        res.set('X-Stream-Config-Version', streamConfig.version);

        return res.json({
            success: true,
            stream_url: finalUrl,
            stream_source: legacyHlsSource,
            primary_source: streamConfig.active_source,
            fallback_order: fallbackOrder,
            sources,
            schema_version: 2,
            transmissions: playbackCatalog.transmissions,
            default_transmission_id: playbackCatalog.default_transmission_id,
            stream_config_version: streamConfig.version,
            session_id: decision.sessionIdFinal,
            reused_session: decision.reusedSession,
            reattached_same_page: decision.reattachedSamePage,
            takeover: decision.takeoverApplied,
            bunny_expires: bunnyExpires,
            cast_token: castRequested,
            pase_expira: decision.expiraMillis
        });

    } catch (error) {
        console.error("❌ Error en /generate-stream:", error);

        return res.status(500).json({
            success: false,
            code: "SERVER_ERROR"
        });
    }
});

// Los avisos de cierre (navigator.sendBeacon) pueden llegar como text/plain: así no
// requieren una verificación CORS previa, que algunos navegadores no completan al cerrar.
const leerTextoPlano = express.text({ type: 'text/plain', limit: '8kb' });

function beaconComoJson(req, res, next) {
    if (typeof req.body === 'string') {
        try {
            req.body = JSON.parse(req.body);
        } catch (_) {
            req.body = {};
        }
    }
    next();
}

// Libera únicamente la página que creó el bloqueo. Acepta el ID token en el
// body para que pagehide pueda usar navigator.sendBeacon en TVs y móviles.
app.post('/release-session', leerTextoPlano, beaconComoJson, ...limitesReproduccion, async (req, res) => {
    try {
        const decodedToken = await verifyUserRequest(req);

        if (!decodedToken) {
            return res.status(401).json({ success: false, code: "NO_AUTH" });
        }

        const sessionId = normalizeClientId(req.body?.session_id);
        const pageId = normalizeClientId(req.body?.page_id);

        if (!sessionId || !pageId) {
            return res.status(400).json({ success: false, code: "INVALID_RELEASE" });
        }

        const userRef = db.collection('usuarios').doc(decodedToken.uid);
        let released = false;

        await db.runTransaction(async transaction => {
            const snap = await transaction.get(userRef);
            if (!snap.exists) return;

            const data = snap.data();

            if (data.session_id !== sessionId || data.active_page_id !== pageId) {
                return;
            }

            transaction.update(userRef, {
                session_id: "",
                active_device_id: "",
                active_page_id: "",
                last_status: "released",
                session_released_at: nowTimestamp()
            });

            released = true;
        });

        return res.json({ success: true, released });

    } catch (error) {
        console.error("Error en /release-session:", error);
        return res.status(500).json({ success: false, code: "SERVER_ERROR" });
    }
});

// --- 12.1 RESUMEN DE EXPERIENCIA (QoE) ---
// Los reproductores envían al ocultarse un resumen (arranque, congelamientos, errores).
// Se escribe una línea "QOE {...}" en los registros de Render, sin IP ni datos personales.
// Si una red envía demasiados, los sobrantes se descartan en silencio (204).
const QOE_RATE_LIMIT_MAX = parseInt(process.env.QOE_RATE_LIMIT_MAX || "30", 10);

const qoeLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: QOE_RATE_LIMIT_MAX,
    standardHeaders: false,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skip: (req) => req.method === 'OPTIONS',
    handler: (req, res) => res.status(204).end()
});

app.post('/qoe', qoeLimiter, express.text({ type: 'text/plain', limit: '4kb' }), (req, res) => {
    try {
        const d = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
        const numero = (v) => (v === null || v === undefined || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
        const texto = (v, max) => String(v === null || v === undefined ? '' : v).replace(/[^\w .,:/-]/g, '').slice(0, max);
        const resumenQoe = {
            fecha: new Date(Date.now()).toISOString(),
            id: texto(d.id, 24),
            dispositivo: texto(d.dispositivo, 10),
            red: texto(d.red, 32),
            arranqueMs: numero(d.arranqueMs),
            rebuffers: numero(d.rebuffers),
            rebufferMs: numero(d.rebufferMs),
            errores: numero(d.errores),
            reintentos: numero(d.reintentos),
            relevosToken: numero(d.relevosToken),
            perfil: texto(d.perfil, 12),
            minutos: numero(d.minutos)
        };
        console.log('QOE ' + JSON.stringify(resumenQoe));
        acumularQoe(resumenQoe);
    } catch (_) {
        // Un resumen mal formado se ignora sin afectar a nadie.
    }
    res.status(204).end();
});

// --- 13. CHECK SESSION OPTIMIZADO ---
app.post('/check-session', ...limitesReproduccion, async (req, res) => {
    try {
        const authHeader = req.headers.authorization || "";

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                valid: false,
                motivo: "no_auth"
            });
        }

        const idToken = authHeader.replace("Bearer ", "").trim();

        let decodedToken;
        try {
            decodedToken = await verificarIdToken(req, idToken);
        } catch (e) {
            return res.status(401).json({
                valid: false,
                motivo: "no_auth"
            });
        }

        const sessionId = normalizeClientId(req.body?.session_id);
        const pageId = normalizeClientId(req.body?.page_id);

        if (!sessionId) {
            return res.status(400).json({
                valid: false,
                motivo: "missing_session"
            });
        }

        const uid = decodedToken.uid;

        const userRef = db.collection('usuarios').doc(uid);
        const userDoc = await userRef.get();

        if (!userDoc.exists) {
            return res.status(403).json({
                valid: false,
                motivo: "pase_inactivo"
            });
        }

        const userData = userDoc.data();

        if (!userData.fecha_expiracion || typeof userData.fecha_expiracion.toMillis !== "function") {
            return res.status(403).json({
                valid: false,
                motivo: "pase_sin_expiracion"
            });
        }

        const expiraMillis = userData.fecha_expiracion.toMillis();
        const ahora = Date.now();

        const { ip, userAgent } = getClientData(req);

        if (expiraMillis <= ahora) {
            if (userData.last_status !== "expired") {
                await userRef.update({
                    last_heartbeat: nowTimestamp(),
                    last_status: "expired",
                    last_ip: ip,
                    last_user_agent: userAgent
                });
            }

            return res.json({
                valid: false,
                motivo: "expirado"
            });
        }

        if (
            userData.last_status === "revoked_by_admin" ||
            String(userData.session_id || "").startsWith("revoked_")
        ) {
            if (userData.last_status !== "revoked_by_admin") {
                await userRef.update({
                    last_heartbeat: nowTimestamp(),
                    last_status: "revoked_by_admin",
                    last_ip: ip,
                    last_user_agent: userAgent
                });
            }

            return res.json({
                valid: false,
                motivo: "revocado"
            });
        }

        if (
            sessionId !== userData.session_id ||
            !pageId ||
            (userData.active_page_id && pageId !== userData.active_page_id)
        ) {
            return res.json({
                valid: false,
                motivo: "pirateria"
            });
        }

        if (shouldWriteHeartbeat(userData, ahora)) {
            await userRef.update({
                last_heartbeat: nowTimestamp(),
                last_status: "active",
                last_ip: ip,
                last_user_agent: userAgent
            });
        }

        const streamConfig = await getActiveStreamConfig();

        res.set('X-Stream-Config-Version', streamConfig.version);

        return res.json({
            valid: true,
            motivo: "ok",
            pase_expira: expiraMillis,
            default_transmission_id: streamConfig.default_transmission_id,
            stream_config_version: streamConfig.version
        });

    } catch (e) {
        console.error("❌ Error en /check-session:", e);

        return res.status(500).json({
            valid: false,
            motivo: "server_error"
        });
    }
});

// --- 14. PANEL ADMIN: GENERAR PASE ---
app.post('/admin/generar-pase-rapido', createPassLimiter, verifyAdmin, async (req, res) => {
    const { partido, email_manual, pass_manual, fecha_corte } = req.body;

    try {
        if (!partido) {
            return res.status(400).json({
                success: false,
                code: "MISSING_MATCH",
                message: "Falta el partido o etiqueta del pase."
            });
        }

        if (String(partido).length > 80) {
            return res.status(400).json({
                success: false,
                code: "MATCH_TOO_LONG",
                message: "El nombre del partido admite hasta 80 caracteres."
            });
        }

        const exp = fecha_corte
            ? new Date(fecha_corte)
            : new Date(Date.now() + 24 * 60 * 60 * 1000);

        if (Number.isNaN(exp.getTime())) {
            return res.status(400).json({
                success: false,
                code: "INVALID_DATE",
                message: "Fecha de corte inválida."
            });
        }

        if (exp.getTime() <= Date.now()) {
            return res.status(400).json({
                success: false,
                code: "INVALID_DATE",
                message: "La fecha de corte ya pasó. Revisa el día y la hora."
            });
        }

        const esSocioVip = Boolean(email_manual);

        if (esSocioVip) {
            const emailFinal = String(email_manual).trim().toLowerCase();

            if (!emailFinal.includes("@")) {
                return res.status(400).json({
                    success: false,
                    code: "INVALID_EMAIL",
                    message: "Email VIP inválido."
                });
            }

            // 8 cifras al azar criptográfico (se pueden escribir con el control remoto).
            const claveFinal = pass_manual || crypto.randomInt(10000000, 100000000).toString();

            let userRecord;
            try {
                userRecord = await auth.createUser({
                    email: emailFinal,
                    password: claveFinal,
                    displayName: partido
                });
            } catch (errorAlta) {
                if (errorAlta.code === "auth/email-already-exists") {
                    return res.status(409).json({
                        success: false,
                        code: "EMAIL_EXISTS",
                        message: "Ese correo ya tiene una cuenta. Para renovar al socio, use «Extender» en la tabla del panel."
                    });
                }
                throw errorAlta;
            }

            await db.collection('usuarios').doc(userRecord.uid).set({
                uid: userRecord.uid,
                usuario_corto: emailFinal,
                etiqueta: partido,
                tipo_acceso: "vip",
                login_mode: "email_password",
                event_id: null,
                event_name: partido,
                fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
                creado_el: nowTimestamp(),
                session_id: "",
                extension_count: 0,
                extension_history: [],
                password_stored: false,
                last_status: "created"
            });

            registrarAccionAdmin(req, "crear_vip", `${emailFinal} · vence ${FORMATO_FECHA_HORA_LIMA.format(exp)}`, { uid: userRecord.uid });

            return res.json({
                success: true,
                tipo_acceso: "vip",
                usuario: emailFinal,
                clave: claveFinal
            });
        }

        let userRecord = null;
        let codigo = null;
        let codeHash = null;
        let emailFinal = null;
        let claveInterna = null;

        for (let intento = 0; intento < 20; intento++) {
            const generado = await generarCodigoRapidoUnico();

            codigo = generado.codigo;
            codeHash = generado.hash;
            emailFinal = `${codigo}@golazosp.net`;
            claveInterna = generarPasswordInternoSeguro();

            try {
                userRecord = await auth.createUser({
                    email: emailFinal,
                    password: claveInterna,
                    displayName: partido
                });

                break;

            } catch (e) {
                if (e.code === "auth/email-already-exists") {
                    continue;
                }

                throw e;
            }
        }

        if (!userRecord) {
            throw new Error("No se pudo crear usuario para código rápido.");
        }

        const linkRapido = `${APP_BASE_URL}/?c=${encodeURIComponent(codigo)}`;
        const eventId = buildEventId(partido, exp);
        const eventDateKey = formatPeruDateKey(exp);

        await db.collection('usuarios').doc(userRecord.uid).set({
            uid: userRecord.uid,
            usuario_corto: emailFinal,
            etiqueta: partido,
            tipo_acceso: "partido",
            login_mode: "quick_code",
            event_id: eventId,
            event_name: partido,
            event_date_key: eventDateKey,
            quick_code_hash: codeHash,
            quick_code_created_at: nowTimestamp(),
            fecha_expiracion: admin.firestore.Timestamp.fromDate(exp),
            creado_el: nowTimestamp(),
            session_id: "",
            extension_count: 0,
            extension_history: [],
            password_stored: false,
            last_status: "created"
        });

        registrarAccionAdmin(req, "crear_pase", `${String(partido).slice(0, 80)} · vence ${FORMATO_FECHA_HORA_LIMA.format(exp)}`, { uid: userRecord.uid, event_id: eventId });

        return res.json({
            success: true,
            tipo_acceso: "partido",
            codigo,
            link_rapido: linkRapido,
            usuario: emailFinal,
            clave: null
        });

    } catch (e) {
        console.error("❌ Error creando pase:", e);

        return res.status(500).json({
            success: false,
            code: "CREATE_PASS_ERROR",
            message: e.message
        });
    }
});

// --- 15. PANEL ADMIN: REVOCAR SESIÓN MANUALMENTE ---
app.post('/admin/revocar-sesion', adminLimiter, verifyAdmin, async (req, res) => {
    const { uid } = req.body;

    if (!uid) {
        return res.status(400).json({
            success: false,
            message: "Falta UID"
        });
    }

    try {
        await db.collection('usuarios').doc(uid).update({
            session_id: "revoked_" + Date.now(),
            last_status: "revoked_by_admin",
            last_heartbeat: nowTimestamp()
        });

        registrarAccionAdmin(req, "revocar", `pase ${String(uid).slice(0, 40)}`, { uid });

        return res.json({
            success: true,
            message: "Sesión revocada exitosamente. El usuario será expulsado pronto."
        });

    } catch (e) {
        console.error("❌ Error revocando sesión:", e);

        return res.status(500).json({
            success: false,
            message: "Error al revocar sesión"
        });
    }
});

// --- 15.1 PANEL ADMIN: VER CONFIG STREAM ---
app.post('/admin/ver-config-stream', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        // El panel recibe la configuración leída en este momento de Firestore. Si Firestore no responde,
        // no se le entrega la de respaldo: guardarla reemplazaría las transmisiones reales para todos.
        invalidarStreamConfig();
        const config = await getActiveStreamConfig(true);

        if (ultimoOrigenConfig !== "firestore") {
            return res.status(503).json({
                success: false,
                code: "CONFIG_UNAVAILABLE",
                message: "Firestore no respondió al leer la configuración. Reintente en unos segundos (no se muestra la de respaldo para no reemplazar la real)."
            });
        }

        return res.json({
            success: true,
            config,
            cache_ttl_ms: STREAM_CONFIG_CACHE_TTL_MS
        });

    } catch (e) {
        console.error("❌ Error viendo config stream:", e);

        return res.status(500).json({
            success: false,
            message: "Error viendo config stream."
        });
    }
});

// --- 15.2 PANEL ADMIN: ACTUALIZAR CONFIG STREAM ---
app.post('/admin/actualizar-config-stream', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        let currentConfig = await getActiveStreamConfig();

        if (Array.isArray(req.body?.transmissions)) {
            // Concurrencia: si el panel informa la versión que editó y la guardada ya es otra, otro
            // administrador la cambió mientras tanto; guardar ahora borraría su cambio.
            const versionEsperada = String(req.body?.expected_version || "").trim();
            if (versionEsperada) {
                invalidarStreamConfig();
                currentConfig = await getActiveStreamConfig(true);
                if (ultimoOrigenConfig !== "firestore") {
                    return res.status(503).json({
                        success: false,
                        code: "CONFIG_UNAVAILABLE",
                        message: "Firestore no respondió; no se guardó nada. Reintente en unos segundos."
                    });
                }
                if (currentConfig.version !== versionEsperada) {
                    return res.status(409).json({
                        success: false,
                        code: "CONFIG_CHANGED",
                        message: "Otro administrador cambió la configuración. Recárguela antes de guardar.",
                        current_version: currentConfig.version
                    });
                }
            }

            const normalizedCatalog = normalizeTransmissionCatalog(
                req.body.transmissions,
                true
            );

            if (normalizedCatalog.errors.length) {
                return res.status(400).json({
                    success: false,
                    code: "INVALID_TRANSMISSION_CATALOG",
                    message: normalizedCatalog.errors[0],
                    errors: normalizedCatalog.errors
                });
            }

            // Un catálogo vacío dejaría a todos los espectadores sin señal: solo llega así cuando el panel
            // no pudo cargar la configuración. Para ocultar las transmisiones se desmarca «Visible».
            if (!normalizedCatalog.transmissions.length) {
                return res.status(400).json({
                    success: false,
                    code: "EMPTY_CATALOG",
                    message: "No se guarda un catálogo sin transmisiones. Recargue la configuración; para ocultarlas, desmarque «Visible en la web»."
                });
            }

            const publicTransmissions = normalizedCatalog.transmissions.filter(
                transmission =>
                    transmission.visible &&
                    transmission.options.some(option => option.enabled)
            );
            const requestedDefaultId = normalizeCatalogId(
                req.body.default_transmission_id
            );
            const defaultTransmission = publicTransmissions.find(
                transmission => transmission.id === requestedDefaultId
            ) || publicTransmissions[0] || null;

            const payload = {
                schema_version: 2,
                transmissions: normalizedCatalog.transmissions,
                default_transmission_id: defaultTransmission?.id || "",
                updated_at: nowTimestamp()
            };

            await db.collection("config").doc("stream").set(payload, { merge: true });

            invalidarStreamConfig();

            const savedConfig = await getActiveStreamConfig(true);

            console.log(
                `✅ Catálogo actualizado | versión ${currentConfig.version || 'inicial'} -> ${savedConfig.version}`
            );
            registrarAccionAdmin(
                req,
                "configurar",
                `${publicTransmissions.length} transmisión(es) visible(s) · versión ${currentConfig.version || 'inicial'} → ${savedConfig.version}`,
                { anterior: currentConfig.version || "", nueva: savedConfig.version, visibles: publicTransmissions.length }
            );

            return res.json({
                success: true,
                message: `${publicTransmissions.length} transmisión(es) activa(s).`,
                previous_stream_config_version: currentConfig.version || "",
                stream_config_version: savedConfig.version,
                config: savedConfig
            });
        }

        const activeSource = normalizeStreamSource(
            req.body?.active_source || currentConfig.active_source
        );
        const externalUrl = String(
            req.body?.external_url || currentConfig.external_url || EXTERNAL_STREAM_URL_DEFAULT
        ).trim();
        const iframeUrl = String(
            req.body?.iframe_url || currentConfig.iframe_url || IFRAME_PLAYER_URL_DEFAULT
        ).trim();
        const fallbackOrder = normalizeFallbackOrder(
            req.body?.fallback_order || currentConfig.fallback_order,
            activeSource
        );

        if (!isValidHttpUrl(externalUrl)) {
            return res.status(400).json({
                success: false,
                message: "external_url inválida."
            });
        }

        if (!isValidHttpUrl(iframeUrl)) {
            return res.status(400).json({
                success: false,
                message: "iframe_url inválida."
            });
        }

        const payload = {
            active_source: activeSource,
            external_url: externalUrl,
            iframe_url: iframeUrl,
            fallback_order: fallbackOrder,
            updated_at: nowTimestamp()
        };

        await db.collection("config").doc("stream").set(payload, { merge: true });

        invalidarStreamConfig();

        return res.json({
            success: true,
            message: `Fuente de stream actualizada a: ${activeSource}`,
            config: payload
        });

    } catch (e) {
        console.error("❌ Error actualizando config stream:", e);

        return res.status(500).json({
            success: false,
            message: "Error actualizando config stream."
        });
    }
});

// --- 16. PANEL ADMIN: LIMPIAR CADUCADOS + ARCHIVO HISTÓRICO ---
// Por lotes: hasta CLEANUP_BATCH_SIZE pases por pulsación (400 por defecto). Primero se
// archivan todos en un lote, luego se eliminan las cuentas de Auth en una sola llamada y
// al final se borran, en otro lote, solo los pases cuya cuenta se eliminó. Si algo falla,
// volver a pulsar completa lo pendiente (cada paso puede repetirse sin daño).
// Margen (B9): los vencidos hace menos de CLEANUP_GRACE_MINUTES (180 por omisión; 0 lo desactiva) se
// conservan por si el partido sigue en tiempo suplementario y hay que extenderlos: un pase borrado no
// se puede recuperar.
const CLEANUP_GRACE_MINUTES = Math.max(0, parseInt(process.env.CLEANUP_GRACE_MINUTES || "180", 10) || 0);
const CLEANUP_GRACE_TEXTO = CLEANUP_GRACE_MINUTES % 60 === 0 ? `${CLEANUP_GRACE_MINUTES / 60} h` : `${CLEANUP_GRACE_MINUTES} min`;
const CLEANUP_BATCH_SIZE = Math.min(400, Math.max(10, parseInt(process.env.CLEANUP_BATCH_SIZE || "400", 10) || 400));

function datosDeArchivo(doc) {
    const data = doc.data() || {};

    // Se conserva solo información operativa útil. No se archivan
    // códigos hash, session_id, IP ni user-agent completo.
    return {
        uid: data.uid || doc.id,
        usuario_corto: data.usuario_corto || "-",
        etiqueta: data.etiqueta || "-",
        tipo_acceso: data.tipo_acceso || "manual",
        login_mode: data.login_mode || "-",
        event_id: data.event_id || getUserEventId(data),
        event_name: data.event_name || data.etiqueta || "-",
        event_date_key: data.event_date_key || null,
        fecha_expiracion: data.fecha_expiracion || null,
        creado_el: data.creado_el || null,
        last_status: data.last_status || "-",
        last_connection_at: data.last_heartbeat || null,
        tuvo_ingreso: !userNeverEntered(data),
        dispositivo: summarizeUserAgent(data.last_user_agent || "Sin registro"),
        extension_count: Number(data.extension_count || 0),
        extension_history: Array.isArray(data.extension_history) ? data.extension_history.slice(-20) : [],
        last_extension_at: data.last_extension_at || null,
        last_extension_minutes: Number.isFinite(Number(data.last_extension_minutes))
            ? Number(data.last_extension_minutes)
            : null,
        archivado_el: nowTimestamp(),
        archive_reason: "expired_cleanup"
    };
}

async function eliminarCuentasAuth(uids) {
    const fallidos = new Set();

    if (typeof auth.deleteUsers === 'function') {
        const resultado = await auth.deleteUsers(uids);
        (resultado.errors || []).forEach(item => {
            fallidos.add(item.index);
            console.error("❌ Error eliminando cuenta de Auth:", uids[item.index], item.error && item.error.message);
        });
        return fallidos;
    }

    for (let i = 0; i < uids.length; i++) {
        try {
            await auth.deleteUser(uids[i]);
        } catch (authError) {
            if (authError.code !== 'auth/user-not-found') {
                fallidos.add(i);
                console.error("❌ Error eliminando cuenta de Auth:", uids[i], authError.message);
            }
        }
    }
    return fallidos;
}

app.post('/admin/limpiar-caducados', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const ahora = nowTimestamp();

        const limiteLimpieza = admin.firestore.Timestamp.fromMillis(Date.now() - CLEANUP_GRACE_MINUTES * 60 * 1000);

        const vencidosSnap = await db.collection('usuarios')
            .where('fecha_expiracion', '<', limiteLimpieza)
            .limit(CLEANUP_BATCH_SIZE + 1)
            .get();

        // Cuántos se conservan: se cuenta solo en la primera parte (el panel envía continuacion en las siguientes).
        let conservadosRecientes = 0;
        if (CLEANUP_GRACE_MINUTES > 0 && req.body?.continuacion !== true) {
            const recientes = await db.collection('usuarios')
                .where('fecha_expiracion', '>=', limiteLimpieza)
                .where('fecha_expiracion', '<', ahora)
                .limit(1000)
                .get();
            conservadosRecientes = recientes.size;
        }

        if (vencidosSnap.empty) {
            return res.json({
                success: true,
                mensaje: conservadosRecientes
                    ? `✅ No hay vencidos para limpiar. ${conservadosRecientes} vencido(s) hace menos de ${CLEANUP_GRACE_TEXTO} se conservan para poder extenderlos.`
                    : "✅ No hay usuarios vencidos.",
                conservados_recientes: conservadosRecientes
            });
        }

        const docs = vencidosSnap.docs.slice(0, CLEANUP_BATCH_SIZE);
        const quedanMas = vencidosSnap.docs.length > CLEANUP_BATCH_SIZE;

        const loteArchivo = db.batch();
        docs.forEach(doc => {
            loteArchivo.set(db.collection('historial_accesos').doc(doc.id), datosDeArchivo(doc), { merge: true });
        });
        await loteArchivo.commit();
        const archivados = docs.length;

        const fallidos = await eliminarCuentasAuth(docs.map(doc => doc.id));

        const loteBorrado = db.batch();
        let borrados = 0;
        docs.forEach((doc, index) => {
            if (fallidos.has(index)) return;
            loteBorrado.delete(doc.ref);
            borrados++;
        });
        if (borrados) await loteBorrado.commit();

        const errores = fallidos.size;

        registrarAccionAdmin(req, "limpiar", `${borrados} eliminados · ${archivados} archivados${conservadosRecientes ? ` · ${conservadosRecientes} recientes conservados` : ''}`,
            { borrados, archivados, errores, conservados_recientes: conservadosRecientes });

        return res.json({
            success: true,
            mensaje: `🧹 ${borrados} pases eliminados · ${archivados} archivados${errores ? ` · ${errores} con error` : ''}` +
                `${conservadosRecientes ? ` · ${conservadosRecientes} vencidos hace menos de ${CLEANUP_GRACE_TEXTO} se conservan` : ''}` +
                `${quedanMas ? ' · Quedan más: vuelva a pulsar para continuar' : ''}.`,
            borrados,
            archivados,
            errores,
            conservados_recientes: conservadosRecientes,
            quedan_mas: quedanMas
        });

    } catch (e) {
        console.error("❌ Error limpiando caducados:", e);

        return res.status(500).json({
            success: false,
            mensaje: "Error al limpiar usuarios caducados."
        });
    }
});

// --- 17. GESTIÓN ADMINISTRATIVA DE ACCESOS ---
app.post('/admin/extender-accesos', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const rawUids = Array.isArray(req.body?.uids) ? req.body.uids : [];
        const uids = [...new Set(rawUids.map(uid => String(uid || '').trim()).filter(Boolean))];
        const mode = req.body?.mode === 'set' ? 'set' : 'add';
        const minutes = Number(req.body?.minutes);
        const newLabel = normalizeDisplayText(req.body?.new_label || '', 80);
        const requestedExpiration = req.body?.new_expiration ? new Date(req.body.new_expiration) : null;

        if (!uids.length || uids.length > 300) {
            return res.status(400).json({
                success: false,
                message: "Selecciona entre 1 y 300 usuarios."
            });
        }

        if (mode === 'add' && (!Number.isFinite(minutes) || minutes < 1 || minutes > 10080)) {
            return res.status(400).json({
                success: false,
                message: "Los minutos deben estar entre 1 y 10080."
            });
        }

        if (mode === 'set' && (!requestedExpiration || Number.isNaN(requestedExpiration.getTime()) || requestedExpiration.getTime() <= Date.now())) {
            return res.status(400).json({
                success: false,
                message: "La nueva fecha de expiración debe ser futura y válida."
            });
        }

        const refs = uids.map(uid => db.collection('usuarios').doc(uid));
        const snaps = await db.getAll(...refs);
        const batch = db.batch();
        const nowMillis = Date.now();
        const extensionAt = nowTimestamp();
        const results = [];
        let updated = 0;

        snaps.forEach((snap, index) => {
            if (!snap.exists) {
                results.push({ uid: uids[index], success: false, reason: 'not_found' });
                return;
            }

            const data = snap.data() || {};
            const currentExpirationMillis = getTimestampMillis(data.fecha_expiracion);
            const targetMillis = mode === 'set'
                ? requestedExpiration.getTime()
                : Math.max(currentExpirationMillis || 0, nowMillis) + Math.round(minutes * 60 * 1000);

            const targetExpiration = admin.firestore.Timestamp.fromMillis(targetMillis);
            const previousLabel = normalizeDisplayText(data.etiqueta || "Sin etiqueta", 80);
            const targetLabel = newLabel || previousLabel;
            const labelChanged = Boolean(newLabel && newLabel !== previousLabel);
            const targetEventId = labelChanged
                ? buildEventId(targetLabel, new Date(targetMillis))
                : (data.event_id || getUserEventId(data));

            const history = Array.isArray(data.extension_history)
                ? data.extension_history.slice(-19)
                : [];

            history.push({
                at: extensionAt,
                mode,
                minutes: mode === 'add' ? Math.round(minutes) : null,
                old_expiration: currentExpirationMillis
                    ? admin.firestore.Timestamp.fromMillis(currentExpirationMillis)
                    : null,
                new_expiration: targetExpiration,
                old_label: previousLabel,
                new_label: targetLabel
            });

            const patch = {
                fecha_expiracion: targetExpiration,
                etiqueta: targetLabel,
                event_name: targetLabel,
                event_id: targetEventId,
                event_date_key: formatPeruDateKey(new Date(targetMillis)),
                extension_count: Number(data.extension_count || 0) + 1,
                extension_history: history,
                last_extension_at: extensionAt,
                last_extension_minutes: mode === 'add' ? Math.round(minutes) : null
            };

            if (data.last_status === 'expired') {
                patch.last_status = 'extended';
                patch.session_id = '';
                patch.active_device_id = '';
                patch.active_page_id = '';
            }

            batch.update(refs[index], patch);
            updated++;
            results.push({
                uid: uids[index],
                success: true,
                new_expiration_ms: targetMillis,
                etiqueta: targetLabel
            });
        });

        if (updated) await batch.commit();

        registrarAccionAdmin(
            req,
            "extender",
            `${updated} acceso(s) · ${mode === 'add' ? `+${Math.round(minutes)} min` : `hasta ${FORMATO_FECHA_HORA_LIMA.format(requestedExpiration)}`}${newLabel ? ` · partido: ${newLabel}` : ''}`,
            { total: updated, modo: mode, uids: uids.slice(0, 20) }
        );

        return res.json({
            success: true,
            updated,
            requested: uids.length,
            results,
            message: `✅ ${updated} acceso(s) extendido(s).`
        });

    } catch (e) {
        console.error("❌ Error extendiendo accesos:", e);
        return res.status(500).json({
            success: false,
            message: "Error extendiendo accesos."
        });
    }
});

app.post('/admin/revocar-multiples', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const rawUids = Array.isArray(req.body?.uids) ? req.body.uids : [];
        const uids = [...new Set(rawUids.map(uid => String(uid || '').trim()).filter(Boolean))];

        if (!uids.length || uids.length > 300) {
            return res.status(400).json({
                success: false,
                message: "Selecciona entre 1 y 300 usuarios."
            });
        }

        const refs = uids.map(uid => db.collection('usuarios').doc(uid));
        const snaps = await db.getAll(...refs);
        const batch = db.batch();
        let updated = 0;
        const revokedAt = nowTimestamp();

        snaps.forEach((snap, index) => {
            if (!snap.exists) return;
            batch.update(refs[index], {
                session_id: "revoked_" + Date.now() + "_" + index,
                last_status: "revoked_by_admin",
                last_heartbeat: revokedAt
            });
            updated++;
        });

        if (updated) await batch.commit();

        registrarAccionAdmin(req, "revocar_varios", `${updated} sesión(es) revocada(s)`, { total: updated, uids: uids.slice(0, 20) });

        return res.json({
            success: true,
            updated,
            message: `✅ ${updated} sesión(es) revocada(s).`
        });
    } catch (e) {
        console.error("❌ Error revocando múltiples sesiones:", e);
        return res.status(500).json({
            success: false,
            message: "Error revocando sesiones."
        });
    }
});

app.post('/admin/historial-usuario', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const uid = String(req.body?.uid || '').trim();
        if (!uid) {
            return res.status(400).json({ success: false, message: "Falta UID." });
        }

        let snap = await db.collection('usuarios').doc(uid).get();
        let archived = false;

        if (!snap.exists) {
            snap = await db.collection('historial_accesos').doc(uid).get();
            archived = true;
        }

        if (!snap.exists) {
            return res.status(404).json({ success: false, message: "Usuario no encontrado." });
        }

        const data = snap.data() || {};
        return res.json({
            success: true,
            archived,
            usuario: {
                uid: data.uid || uid,
                usuario_corto: data.usuario_corto || "-",
                etiqueta: data.etiqueta || "-",
                tipo_acceso: data.tipo_acceso || "manual",
                creado_ms: getTimestampMillis(data.creado_el),
                expira_ms: getTimestampMillis(data.fecha_expiracion),
                extension_count: Number(data.extension_count || 0),
                extension_history: serializeExtensionHistory(data.extension_history)
            }
        });
    } catch (e) {
        console.error("❌ Error consultando historial de usuario:", e);
        return res.status(500).json({ success: false, message: "Error consultando historial." });
    }
});

app.post('/admin/listar-historial', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const snap = await db.collection('historial_accesos')
            .orderBy('archivado_el', 'desc')
            .limit(100)
            .get();

        const items = snap.docs.map(doc => {
            const data = doc.data() || {};
            return {
                uid: data.uid || doc.id,
                usuario_corto: data.usuario_corto || "-",
                etiqueta: data.etiqueta || "-",
                tipo_acceso: data.tipo_acceso || "manual",
                creado_ms: getTimestampMillis(data.creado_el),
                expira_ms: getTimestampMillis(data.fecha_expiracion),
                archivado_ms: getTimestampMillis(data.archivado_el),
                extension_count: Number(data.extension_count || 0),
                last_status: data.last_status || "-"
            };
        });

        return res.json({ success: true, items });
    } catch (e) {
        console.error("❌ Error listando historial archivado:", e);
        return res.status(500).json({ success: false, message: "Error cargando historial archivado." });
    }
});

// --- 17.0 PANEL ADMIN: REGISTRO DE ACCIONES (B9) ---
app.post('/admin/registro', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const limite = Math.min(200, Math.max(1, parseInt(req.body?.limite, 10) || 100));
        const snap = await db.collection('registro_admin')
            .orderBy('en', 'desc')
            .limit(limite)
            .get();

        const items = snap.docs.map(doc => {
            const d = doc.data() || {};
            return {
                accion: d.accion || "-",
                resumen: d.resumen || "",
                actor_email: d.actor_email || "",
                actor_uid: d.actor_uid || "",
                en_ms: getTimestampMillis(d.en)
            };
        });

        return res.json({ success: true, items });
    } catch (e) {
        console.error("❌ Error leyendo el registro de acciones:", e);
        return res.status(500).json({ success: false, message: "Error leyendo el registro de acciones." });
    }
});

// --- 17.1 PANEL ADMIN: LISTAR USUARIOS + DASHBOARD EN VIVO ---
// Formateadores creados una sola vez: producen el mismo texto que toLocaleTimeString y
// toLocaleString con estas opciones, sin volver a construirlos para cada pase.
const FORMATO_HORA_LIMA = new Intl.DateTimeFormat('es-PE', {
    timeZone: 'America/Lima',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric'
});

const FORMATO_FECHA_HORA_LIMA = new Intl.DateTimeFormat('es-PE', {
    timeZone: 'America/Lima',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
});

app.post('/admin/listar-usuarios', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const snap = await db.collection('usuarios')
            .orderBy('creado_el', 'desc')
            .get();

        const now = Date.now();
        const resumen = {
            total: 0,
            vigentes: 0,
            viendo_ahora: 0,
            desconectados: 0,
            vencidos: 0,
            revocados: 0,
            nunca_ingresaron: 0,
            pases_rapidos: 0,
            vip: 0,
            tomas_frecuentes: 0,
            dispositivos: {}
        };

        const eventMap = new Map();

        const usuariosFormateados = snap.docs.map(d => {
            const data = d.data() || {};
            const expiraMillis = getTimestampMillis(data.fecha_expiracion);
            const fechaVigente = Boolean(expiraMillis && expiraMillis > now);
            const revocado = isRevokedUser(data);
            const esActivo = fechaVigente && !revocado;
            const viendoAhora = isUserWatchingNow(data, now);
            const nuncaIngreso = userNeverEntered(data);
            const tipoAcceso = data.tipo_acceso || (data.login_mode === "quick_code" ? "partido" : "manual");
            const dispositivo = summarizeUserAgent(data.last_user_agent || "Sin registro");
            const eventId = getUserEventId(data);

            resumen.total++;
            if (esActivo) resumen.vigentes++;
            if (!fechaVigente) resumen.vencidos++;
            if (revocado) resumen.revocados++;
            if (viendoAhora) resumen.viendo_ahora++;
            if (esActivo && !viendoAhora) resumen.desconectados++;
            if (nuncaIngreso) resumen.nunca_ingresaron++;
            if (tipoAcceso === 'partido' || data.login_mode === 'quick_code') resumen.pases_rapidos++;
            if (tipoAcceso === 'vip' || data.login_mode === 'email_password') resumen.vip++;

            if (viendoAhora) {
                resumen.dispositivos[dispositivo] = (resumen.dispositivos[dispositivo] || 0) + 1;
            }

            if (tipoAcceso === 'partido' || data.login_mode === 'quick_code') {
                if (!eventMap.has(eventId)) {
                    eventMap.set(eventId, {
                        event_id: eventId,
                        etiqueta: data.etiqueta || "Sin etiqueta",
                        total: 0,
                        vigentes: 0,
                        viendo_ahora: 0,
                        nunca_ingresaron: 0,
                        revocados: 0,
                        peak_concurrent: 0
                    });
                }

                const eventSummary = eventMap.get(eventId);
                eventSummary.total++;
                if (esActivo) eventSummary.vigentes++;
                if (viendoAhora) eventSummary.viendo_ahora++;
                if (nuncaIngreso) eventSummary.nunca_ingresaron++;
                if (revocado) eventSummary.revocados++;
            }

            let ultimaConexion = "-";
            if (data.last_heartbeat) {
                ultimaConexion = FORMATO_HORA_LIMA.format(new Date(data.last_heartbeat.toMillis()));
            }

            let estado = 'VENCIDO';
            if (revocado) estado = 'REVOCADO';
            else if (esActivo) estado = viendoAhora ? 'EN VIVO' : 'ACTIVO';

            const registroTomas = Array.isArray(data.takeover_log) ? data.takeover_log.filter(t => Number.isFinite(t)) : [];
            const tomasUltimaHora = registroTomas.filter(t => now - t < 60 * 60 * 1000).length;
            if (tomasUltimaHora >= 4) resumen.tomas_frecuentes++;

            return {
                uid: data.uid || d.id,
                usuario_corto: data.usuario_corto || "-",
                codigo: String(data.usuario_corto || '').split('@')[0] || "-",
                etiqueta: data.etiqueta || "-",
                event_id: eventId,
                tipo_acceso: tipoAcceso,
                login_mode: data.login_mode || "-",
                tiene_codigo_rapido: Boolean(data.quick_code_hash),
                estado,
                esActivo,
                fecha_vigente: fechaVigente,
                revocado,
                viendo_ahora: viendoAhora,
                nunca_ingreso: nuncaIngreso,
                dispositivo,
                expira_ms: expiraMillis,
                creado_ms: getTimestampMillis(data.creado_el),
                last_heartbeat_ms: getTimestampMillis(data.last_heartbeat),
                tiempo: expiraMillis ? FORMATO_FECHA_HORA_LIMA.format(new Date(expiraMillis)) : "-",
                ultima_conexion: ultimaConexion,
                last_status: data.last_status || "-",
                last_ip: data.last_ip || "Sin registro",
                last_user_agent: String(data.last_user_agent || "Sin registro").slice(0, 300),
                password_stored: data.password_stored === false ? false : true,
                extension_count: Number(data.extension_count || 0),
                last_extension_ms: getTimestampMillis(data.last_extension_at),
                last_extension_minutes: Number.isFinite(Number(data.last_extension_minutes))
                    ? Number(data.last_extension_minutes)
                    : null,
                takeover_count: Number(data.takeover_count || 0),
                tomas_ultima_hora: tomasUltimaHora,
                last_takeover_ms: getTimestampMillis(data.last_takeover_at)
            };
        });

        const eventos = await syncEventPeaks([...eventMap.values()]);
        eventos.sort((a, b) => b.vigentes - a.vigentes || b.total - a.total);

        return res.json({
            success: true,
            usuarios: usuariosFormateados,
            resumen,
            eventos,
            active_session_window_ms: ACTIVE_SESSION_WINDOW_MS,
            generated_at: now
        });

    } catch (e) {
        console.error("❌ Error listando usuarios:", e);

        return res.status(500).json({
            success: false,
            message: "Error listando usuarios."
        });
    }
});

// --- 17.3 HERRAMIENTAS DE OPERACIÓN (B10) ---
// Origen: sección 7 de la auditoría técnica del 16-09 («qué debería mostrar un panel profesional de
// streaming») y herramientas de atención al cliente. Todo es de solo lectura salvo las acciones
// explícitas del administrador (liberar, restaurar, nueva clave VIP), que quedan en registro_admin.

// 17.3.1 Solicitudes salientes. Solo HTTP(S), con tiempo y tamaño máximos. Hacia direcciones que escribe
// un administrador (una fuente externa) solo se consulta a IP públicas: el servidor no debe poder usarse
// para leer su propia red interna (falsificación de solicitudes del lado del servidor, SSRF).
function ipv4ANumero(ip) {
    const p = String(ip).split('.').map(Number);
    return (((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3]) >>> 0;
}

const REDES_V4_RESERVADAS = [
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
    ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
    ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
].map(([red, bits]) => [ipv4ANumero(red) >>> (32 - bits), bits]);

function ipv4EsPublica(ip) {
    const n = ipv4ANumero(ip);
    return !REDES_V4_RESERVADAS.some(([prefijo, bits]) => (n >>> (32 - bits)) === prefijo);
}

function gruposIpv6(valor) {
    const aGrupos = (texto) => {
        if (!texto) return [];
        const grupos = texto.split(':');
        const ultimo = grupos[grupos.length - 1];
        if (ultimo.includes('.')) {
            const o = ultimo.split('.').map(Number);
            grupos.splice(grupos.length - 1, 1, ((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16));
        }
        return grupos;
    };
    const partes = valor.split('::');
    const izquierda = aGrupos(partes[0]);
    const derecha = partes.length > 1 ? aGrupos(partes[1]) : [];
    const ceros = partes.length > 1 ? new Array(Math.max(0, 8 - izquierda.length - derecha.length)).fill('0') : [];
    return izquierda.concat(ceros, derecha).map(g => parseInt(g || '0', 16));
}

function ipEsPublica(ip) {
    let valor = String(ip || '').trim().replace(/^\[|\]$/g, '');
    const zona = valor.indexOf('%');
    if (zona >= 0) valor = valor.slice(0, zona);
    if (net.isIPv4(valor)) return ipv4EsPublica(valor);
    if (!net.isIPv6(valor)) return false;
    const g = gruposIpv6(valor);
    if (g.length !== 8 || g.some(x => !Number.isFinite(x))) return false;
    const v4 = () => `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
    if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) return ipv4EsPublica(v4());           // ::ffff:a.b.c.d
    if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every(x => x === 0)) return ipv4EsPublica(v4()); // NAT64
    if (g.slice(0, 6).every(x => x === 0)) return false;          // ::, ::1 y ::a.b.c.d
    if ((g[0] & 0xfe00) === 0xfc00) return false;                 // fc00::/7 privadas
    if ((g[0] & 0xffc0) === 0xfe80) return false;                 // fe80::/10 enlace local
    if ((g[0] & 0xff00) === 0xff00) return false;                 // ff00::/8 multidifusión
    if (g[0] === 0x2001 && g[1] === 0x0db8) return false;         // 2001:db8::/32 documentación
    if (g[0] === 0x0100 && g.slice(1, 4).every(x => x === 0)) return false; // 100::/64 descarte
    if (g.slice(0, 4).every(x => x === 0) && g[4] === 0xffff && g[5] === 0) return false; // ::ffff:0:0/96 traducidas
    if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return false;    // 64:ff9b:1::/48 NAT64 local
    if (g[0] === 0x2002) return false;                                 // 2002::/16 6to4
    if (g[0] === 0x2001 && g[1] === 0) return false;                   // 2001::/32 Teredo
    if ((g[0] & 0xffc0) === 0xfec0) return false;                      // fec0::/10 sitio (obsoleto)
    return true;
}

// Resolución de nombres que rechaza las direcciones no públicas. Se usa también al conectar, así el
// nombre no puede cambiar de dirección entre la comprobación y la conexión.
function buscarSoloPublicas(nombre, opciones, callback) {
    if (typeof opciones === 'function') { callback = opciones; opciones = {}; }
    const familia = opciones && Number(opciones.family) ? Number(opciones.family) : 0;
    dns.lookup(nombre, { all: true, family: familia }, (error, direcciones) => {
        if (error) return callback(error);
        const lista = Array.isArray(direcciones) ? direcciones : [];
        if (!lista.length) {
            const e = new Error('sin direcciones');
            e.code = 'ENOTFOUND';
            return callback(e);
        }
        if (!lista.every(d => ipEsPublica(d.address))) {
            const e = new Error('dirección no pública');
            e.code = 'EGOLAZO_RED_PRIVADA';
            return callback(e);
        }
        if (opciones && opciones.all) return callback(null, lista);
        return callback(null, lista[0].address, lista[0].family);
    });
}

const agenteSalienteHttps = new https.Agent({ keepAlive: false, maxSockets: 16 });
const agenteSalienteHttp = new http.Agent({ keepAlive: false, maxSockets: 16 });

function solicitudSaliente(direccion, op = {}) {
    const {
        metodo = 'GET', cabeceras = {}, cuerpo = null, timeoutMs = 4000, maxBytes = 512 * 1024,
        soloPublicas = true, redirecciones = 2
    } = op;
    const inicio = Date.now();
    return new Promise((resolve) => {
        let url;
        try { url = new URL(String(direccion)); } catch (_) { return resolve({ ok: false, error: 'url', ms: 0 }); }
        if (url.protocol !== 'https:' && url.protocol !== 'http:') return resolve({ ok: false, error: 'url', ms: 0 });
        const host = url.hostname.replace(/^\[|\]$/g, '');
        if (soloPublicas && net.isIP(host) && !ipEsPublica(host)) return resolve({ ok: false, error: 'red_privada', ms: 0 });
        const esHttps = url.protocol === 'https:';
        let terminado = false;
        let reloj = null;
        let solicitud = null;
        const terminar = (r) => {
            if (terminado) return;
            terminado = true;
            if (reloj) clearTimeout(reloj);
            resolve({ ms: Date.now() - inicio, urlFinal: url.toString(), ...r });
        };
        const datos = cuerpo === null ? null : Buffer.from(typeof cuerpo === 'string' ? cuerpo : JSON.stringify(cuerpo));
        const h = { 'user-agent': 'GolazoServidor/1.0', ...cabeceras };
        if (datos) h['content-length'] = String(datos.length);
        try {
            solicitud = (esHttps ? https : http).request({
                protocol: url.protocol, hostname: host, port: url.port || undefined,
                path: url.pathname + url.search, method: metodo, headers: h,
                agent: esHttps ? agenteSalienteHttps : agenteSalienteHttp,
                lookup: soloPublicas ? buscarSoloPublicas : undefined
            }, (respuesta) => {
                const estado = respuesta.statusCode || 0;
                if ([301, 302, 303, 307, 308].includes(estado) && respuesta.headers.location && redirecciones > 0) {
                    // Se cierra la respuesta de la redirección: un cuerpo sin fin no debe quedar descargándose.
                    try { respuesta.destroy(); } catch (_) {}
                    let siguiente;
                    try { siguiente = new URL(respuesta.headers.location, url).toString(); } catch (_) {
                        return terminar({ ok: false, status: estado, error: 'redireccion' });
                    }
                    if (terminado) return;
                    terminado = true;
                    if (reloj) clearTimeout(reloj);
                    const restante = Math.max(500, timeoutMs - (Date.now() - inicio));
                    return solicitudSaliente(siguiente, { ...op, metodo: estado === 303 ? 'GET' : metodo, timeoutMs: restante, redirecciones: redirecciones - 1 })
                        .then(r => resolve({ ...r, ms: Date.now() - inicio, redirigida: true }));
                }
                const trozos = [];
                let total = 0;
                respuesta.on('data', (trozo) => {
                    if (terminado) return;
                    total += trozo.length;
                    if (total > maxBytes) {
                        trozos.push(trozo.slice(0, Math.max(0, trozo.length - (total - maxBytes))));
                        terminar({ ok: estado >= 200 && estado < 300, status: estado, headers: respuesta.headers, texto: Buffer.concat(trozos).toString('utf8'), cortada: true });
                        try { respuesta.destroy(); } catch (_) {}
                        return;
                    }
                    trozos.push(trozo);
                });
                respuesta.on('end', () => terminar({ ok: estado >= 200 && estado < 300, status: estado, headers: respuesta.headers, texto: Buffer.concat(trozos).toString('utf8'), cortada: false }));
                respuesta.on('error', () => terminar({ ok: false, status: estado, error: 'conexion' }));
            });
        } catch (_) {
            return terminar({ ok: false, error: 'conexion' });
        }
        reloj = setTimeout(() => {
            terminar({ ok: false, error: 'tiempo' });
            try { solicitud.destroy(); } catch (_) {}
        }, timeoutMs);
        solicitud.on('error', (e) => {
            const codigo = e && e.code;
            terminar({
                ok: false,
                error: codigo === 'EGOLAZO_RED_PRIVADA' ? 'red_privada'
                    : (codigo === 'ENOTFOUND' || codigo === 'EAI_AGAIN' || codigo === 'ENODATA') ? 'dns' : 'conexion'
            });
        });
        if (datos) solicitud.write(datos);
        solicitud.end();
    });
}

// 17.3.2 Avisos por Telegram (opcional). Se activan con ALERTAS_TELEGRAM=on y usan las variables que ya
// existen en Render (TELEGRAM_BOT_TOKEN y MI_TELEGRAM_ID). El token nunca se escribe en los registros.
const ALERTAS_TELEGRAM_PEDIDAS = String(process.env.ALERTAS_TELEGRAM || "").trim().toLowerCase() === "on";
const TELEGRAM_BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || "").trim();
const TELEGRAM_CHAT_ID = String(process.env.MI_TELEGRAM_ID || "").trim();
const ALERTAS_TELEGRAM = ALERTAS_TELEGRAM_PEDIDAS &&
    /^\d{5,}:[A-Za-z0-9_-]{30,}$/.test(TELEGRAM_BOT_TOKEN) && /^-?\d{3,20}$/.test(TELEGRAM_CHAT_ID);
if (ALERTAS_TELEGRAM_PEDIDAS && !ALERTAS_TELEGRAM) {
    console.warn("AVISO alertas: ALERTAS_TELEGRAM=on, pero falta TELEGRAM_BOT_TOKEN o MI_TELEGRAM_ID con un valor válido: no se enviarán avisos.");
}

const estadoAlertas = { enviadas: 0, fallidas: 0, descartadas: 0, ultimo_error: "", ultima_ms: 0, recientes: [] };
const colaAlertas = [];
const alertasRecientes = new Map();
let enviandoAlertas = false;

function configuracionAlertas() {
    if (ALERTAS_TELEGRAM) return "telegram";
    return ALERTAS_TELEGRAM_PEDIDAS ? "incompleta" : "desactivadas";
}

function anotarAlerta(texto, entregada) {
    estadoAlertas.recientes.unshift({ en_ms: Date.now(), texto: texto.slice(0, 300), entregada });
    if (estadoAlertas.recientes.length > 10) estadoAlertas.recientes.length = 10;
}

async function entregarAlerta(texto) {
    const r = await solicitudSaliente(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        metodo: 'POST', timeoutMs: 6000, maxBytes: 64 * 1024, soloPublicas: false, redirecciones: 0,
        cabeceras: { 'content-type': 'application/json' },
        cuerpo: { chat_id: TELEGRAM_CHAT_ID, text: texto.slice(0, 3500), disable_web_page_preview: true }
    });
    let respuesta = null;
    try { respuesta = JSON.parse(r.texto || "null"); } catch (_) {}
    if (r.ok && respuesta && respuesta.ok === true) {
        estadoAlertas.enviadas++;
        estadoAlertas.ultima_ms = Date.now();
        anotarAlerta(texto, true);
        return true;
    }
    anotarAlerta(texto, false);
    estadoAlertas.fallidas++;
    estadoAlertas.ultimo_error = r.error ? `sin respuesta (${r.error})` : `Telegram respondió ${r.status || "?"}${respuesta && respuesta.description ? `: ${String(respuesta.description).slice(0, 120)}` : ""}`;
    console.warn(`AVISO alertas: no se pudo enviar el mensaje (${estadoAlertas.ultimo_error}).`);
    return false;
}

async function procesarColaAlertas() {
    if (enviandoAlertas) return;
    enviandoAlertas = true;
    try {
        while (colaAlertas.length) {
            const item = colaAlertas.shift();
            const entregada = await entregarAlerta(item.texto);
            item.resolver(entregada);
            // Telegram admite un mensaje por segundo en un mismo chat.
            if (colaAlertas.length) await new Promise(r => setTimeout(r, 1100));
        }
    } finally {
        enviandoAlertas = false;
    }
}

// Devuelve una promesa que se resuelve con true si el mensaje llegó a Telegram. Nunca lanza.
function enviarAlerta(texto, { forzar = false } = {}) {
    if (!ALERTAS_TELEGRAM) return Promise.resolve(false);
    const mensaje = `GOLAZO · ${String(texto || "").replace(/\s+/g, " ").trim()}`;
    const ahora = Date.now();
    for (const [t, ms] of alertasRecientes) if (ahora - ms > 60000) alertasRecientes.delete(t);
    if (!forzar && alertasRecientes.has(mensaje)) {
        estadoAlertas.descartadas++;
        return Promise.resolve(false);
    }
    if (colaAlertas.length >= 20) {
        estadoAlertas.descartadas++;
        return Promise.resolve(false);
    }
    alertasRecientes.set(mensaje, ahora);
    return new Promise((resolver) => {
        colaAlertas.push({ texto: mensaje, resolver });
        procesarColaAlertas().catch(() => {});
    });
}

// 17.3.3 Ingresos de administradores: cada ingreso nuevo (usuario y contraseña, no la renovación horaria
// del token) queda en registro_admin con su IP y equipo, y se avisa por Telegram si está activado.
// Se recuerdan los últimos 20 ingresos de cada administrador (también en estado_admin, para no repetir el
// aviso tras un reinicio): una sesión iniciada antes que la última conocida también avisa.
const INGRESOS_ADMIN_RECORDADOS = 20;
const ingresosAdminVistos = new Map();     // uid -> Set de auth_time ya avisados
const ingresosAdminEnCurso = new Map();    // `${uid}:${auth_time}` -> tarea

function recordarIngresosAdmin(uid, lista) {
    ingresosAdminVistos.set(uid, new Set([...lista].sort((a, b) => b - a).slice(0, INGRESOS_ADMIN_RECORDADOS)));
}

function notarIngresoAdmin(req, token) {
    const uid = String(token && token.uid || "");
    const authTime = Number(token && token.auth_time) || 0;
    if (!uid || !authTime) return;
    const vistos = ingresosAdminVistos.get(uid);
    if (vistos && vistos.has(authTime)) return;
    const claveIngreso = `${uid}:${authTime}`;
    if (ingresosAdminEnCurso.has(claveIngreso)) return;
    const tarea = (async () => {
        const ref = db.collection('estado_admin').doc(uid);
        let guardados = [];
        try {
            const snap = await ref.get();
            const d = snap.exists ? snap.data() || {} : {};
            guardados = Array.isArray(d.auth_times) ? d.auth_times.map(Number).filter(Number.isFinite) : [];
            if (!guardados.length && Number(d.ultimo_auth_time)) guardados = [Number(d.ultimo_auth_time)];
        } catch (_) {
            // Si Firestore falla se registra igual: mejor un aviso repetido que un ingreso sin aviso.
        }
        const conocidos = new Set(guardados.concat(vistos ? [...vistos] : []));
        if (conocidos.has(authTime)) {
            recordarIngresosAdmin(uid, conocidos);
            return;
        }
        conocidos.add(authTime);
        recordarIngresosAdmin(uid, conocidos);
        const ultimos = [...ingresosAdminVistos.get(uid)];
        try {
            await ref.set({ auth_times: ultimos, ultimo_auth_time: Math.max(...ultimos), email: token.email || "", visto_en: nowTimestamp() }, { merge: true });
        } catch (error) {
            console.error("❌ No se pudo guardar el último ingreso del administrador:", error.message);
        }
        const equipo = summarizeUserAgent(req.headers['user-agent'] || "Sin registro");
        const ip = ipCliente(req);
        registrarAccionAdmin(req, "ingreso", `Ingreso al panel desde ${equipo} · IP ${ip}`, { auth_time: authTime, equipo });
        enviarAlerta(`Ingreso al panel de administración: ${token.email || uid}, desde ${equipo}, IP ${ip}, ${FORMATO_FECHA_HORA_LIMA.format(new Date())} (hora de Lima). Si no fue usted, cambie la contraseña y revoque la sesión.`);
    })().catch(() => {}).finally(() => ingresosAdminEnCurso.delete(claveIngreso));
    ingresosAdminEnCurso.set(claveIngreso, tarea);
}

// 17.3.4 Verificación de la señal: pide la lista HLS a la CDN como un espectador (URL firmada de 2 min)
// y el comienzo del último segmento. «En vivo» significa que la lista avanza entre dos lecturas.
const SENAL_CACHE_MS = Math.min(15000, Math.max(2000, parseInt(process.env.SENAL_CACHE_MS || "8000", 10) || 8000));
const SENAL_TIMEOUT_MS = Math.min(10000, Math.max(1000, parseInt(process.env.SENAL_TIMEOUT_MS || "4000", 10) || 4000));
const SENAL_MAX_VERIFICADAS = 6;
const estadoSenal = new Map();

function analizarListaHls(texto) {
    const lineas = String(texto || "").split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (!lineas.length || lineas[0].replace(/^﻿/, "") !== "#EXTM3U") return null;
    const r = { version: null, objetivo_s: null, secuencia: 0, segmentos: 0, duracion_s: 0, ultima_duracion_s: null, ultimo_segmento: "", fin: false, maestra: false, variantes: [] };
    let esperandoSegmento = false;
    let esperandoVariante = false;
    let duracion = null;
    lineas.slice(1).forEach(linea => {
        if (linea.startsWith("#EXT-X-VERSION:")) r.version = Number(linea.slice(15)) || null;
        else if (linea.startsWith("#EXT-X-TARGETDURATION:")) r.objetivo_s = Number(linea.slice(22)) || null;
        else if (linea.startsWith("#EXT-X-MEDIA-SEQUENCE:")) r.secuencia = Number(linea.slice(22)) || 0;
        else if (linea.startsWith("#EXT-X-ENDLIST")) r.fin = true;
        else if (linea.startsWith("#EXT-X-STREAM-INF")) { r.maestra = true; esperandoVariante = true; }
        else if (linea.startsWith("#EXTINF:")) { duracion = parseFloat(linea.slice(8)); esperandoSegmento = true; }
        else if (!linea.startsWith("#")) {
            if (esperandoVariante) { r.variantes.push(linea); esperandoVariante = false; }
            else if (esperandoSegmento) {
                r.segmentos++;
                if (Number.isFinite(duracion)) { r.duracion_s += duracion; r.ultima_duracion_s = duracion; }
                r.ultimo_segmento = linea;
                esperandoSegmento = false;
            }
        }
    });
    r.duracion_s = Math.round(r.duracion_s * 10) / 10;
    return r;
}

function nombreCorto(uri) {
    return String(uri || "").split("?")[0].split("/").pop().slice(0, 80);
}

async function muestrearLista(url, cabeceras) {
    const lectura = await solicitudSaliente(url, { cabeceras, timeoutMs: SENAL_TIMEOUT_MS, maxBytes: 512 * 1024 });
    const muestra = { http: lectura.status || null, ms: lectura.ms, error: lectura.error || null, lista: null, segmento: null, maestra: false, variantes: 0 };
    if (lectura.error || !lectura.ok) return muestra;
    let lista = analizarListaHls(lectura.texto);
    let urlLista = lectura.urlFinal || url;
    if (!lista) { muestra.error = "no_lista"; return muestra; }
    if (lista.maestra) {
        muestra.maestra = true;
        muestra.variantes = lista.variantes.length;
        if (!lista.variantes.length) { muestra.error = "maestra_vacia"; return muestra; }
        let urlVariante;
        try { urlVariante = new URL(lista.variantes[0], urlLista).toString(); } catch (_) { muestra.error = "no_lista"; return muestra; }
        const variante = await solicitudSaliente(urlVariante, { cabeceras, timeoutMs: SENAL_TIMEOUT_MS, maxBytes: 512 * 1024 });
        muestra.http = variante.status || null;
        muestra.ms += variante.ms;
        if (variante.error || !variante.ok) { muestra.error = variante.error || null; return muestra; }
        lista = analizarListaHls(variante.texto);
        urlLista = variante.urlFinal || urlVariante;
        if (!lista || lista.maestra) { muestra.error = "no_lista"; return muestra; }
    }
    muestra.lista = lista;
    if (lista.segmentos && lista.ultimo_segmento) {
        let urlSegmento = null;
        try { urlSegmento = new URL(lista.ultimo_segmento, urlLista).toString(); } catch (_) {}
        if (urlSegmento) {
            const seg = await solicitudSaliente(urlSegmento, { cabeceras: { ...cabeceras, range: "bytes=0-1023" }, timeoutMs: SENAL_TIMEOUT_MS, maxBytes: 2048 });
            muestra.segmento = { http: seg.status || null, ms: seg.ms, error: seg.error || null };
        }
    }
    return muestra;
}

function clasificarSenal(clave, muestra, ahora, { umbralMs = 0 } = {}) {
    const previo = estadoSenal.get(clave) || {};
    const reciente = previo.vistoEn && ahora - previo.vistoEn <= 120000;
    const base = { http: muestra.http, ms: muestra.ms, verificado_en: ahora, lista: null, segmento: muestra.segmento, maestra: muestra.maestra, variantes: muestra.variantes };
    const conError = (motivo) => {
        estadoSenal.set(clave, { ...(estadoSenal.get(clave) || {}), ultimaMuestraEn: ahora });
        return { ...base, estado: "ERROR", motivo, avanzo_hace_s: reciente && previo.avanzoEn ? Math.round((ahora - previo.avanzoEn) / 1000) : null };
    };
    if (muestra.error === "tiempo") return conError(`Sin respuesta en ${Math.round(SENAL_TIMEOUT_MS / 1000)} s.`);
    if (muestra.error === "red_privada") return conError("La dirección apunta a una red privada o reservada: el servidor no la consulta.");
    if (muestra.error === "dns") return conError("No se encontró el dominio de la señal (DNS).");
    if (muestra.error === "conexion" || muestra.error === "url") return conError("No se pudo conectar con la CDN o con el servidor de la señal.");
    if (muestra.http === 403) return conError("La CDN rechazó el acceso (403). En Bunny, BUNNY_KEY debe coincidir con la clave de «Token authentication» y no debe haber una restricción de referer o de país que excluya al servidor.");
    if (muestra.http === 404) return conError("La lista no existe (404): OBS no está transmitiendo a esa ruta, o la ruta configurada no es la correcta.");
    if (muestra.http >= 500) return conError(`La CDN o el origen fallaron (código ${muestra.http}).`);
    if (muestra.http && (muestra.http < 200 || muestra.http >= 300)) return conError(`Respuesta inesperada (código ${muestra.http}).`);
    if (muestra.error === "no_lista") return conError("La respuesta no es una lista HLS (puede ser una página de error o un reproductor).");
    if (muestra.error === "maestra_vacia") return conError("La lista maestra no nombra ninguna variante.");
    if (muestra.error) return conError("No se pudo leer la lista.");

    const lista = muestra.lista;
    base.lista = {
        version: lista.version, objetivo_s: lista.objetivo_s, secuencia: lista.secuencia, segmentos: lista.segmentos,
        duracion_s: lista.duracion_s, ultimo_segmento: nombreCorto(lista.ultimo_segmento)
    };
    // En el tablero, «detenida» tras 15 s sin avanzar (o 3 duraciones de segmento); en la prueba del editor, el umbral es menor.
    const umbral = umbralMs || Math.max(15000, 3 * Math.max(1000, (lista.objetivo_s || 2) * 1000));
    const avanzo = Boolean(reciente && (lista.secuencia > (previo.secuencia || 0) ||
        (lista.ultimo_segmento && previo.ultimoUri && lista.ultimo_segmento !== previo.ultimoUri)));
    const nuevo = {
        secuencia: lista.secuencia,
        ultimoUri: lista.ultimo_segmento,
        vistoEn: ahora,
        avanzoEn: avanzo ? ahora : (reciente ? previo.avanzoEn || null : null),
        primeraEn: reciente && previo.primeraEn ? previo.primeraEn : ahora,
        ultimaMuestraEn: ahora
    };
    estadoSenal.set(clave, { ...(estadoSenal.get(clave) || {}), ...nuevo });
    const hace = nuevo.avanzoEn ? Math.round((ahora - nuevo.avanzoEn) / 1000) : null;
    base.avanzo_hace_s = hace;
    if (lista.fin) return { ...base, estado: "DETENIDA", motivo: "La lista indica que la transmisión terminó (EXT-X-ENDLIST)." };
    if (!lista.segmentos) return { ...base, estado: "DETENIDA", motivo: "La lista no tiene segmentos." };
    if (muestra.segmento && muestra.segmento.error) return { ...base, estado: "ERROR", motivo: "La lista responde, pero el último segmento no llegó." };
    if (muestra.segmento && muestra.segmento.http && (muestra.segmento.http < 200 || muestra.segmento.http >= 300)) {
        return { ...base, estado: "ERROR", motivo: `La lista responde, pero el último segmento no (código ${muestra.segmento.http}).` };
    }
    if (nuevo.avanzoEn && ahora - nuevo.avanzoEn <= umbral) {
        return { ...base, estado: "EN_VIVO", motivo: hace <= 1 ? "La lista avanza: hay un segmento nuevo." : `La lista avanza: último segmento nuevo hace ${hace} s.` };
    }
    if (ahora - nuevo.primeraEn >= umbral) {
        return { ...base, estado: "DETENIDA", motivo: `La lista no avanza desde hace ${Math.round((ahora - (nuevo.avanzoEn || nuevo.primeraEn)) / 1000)} s: OBS pudo detenerse o el origen dejó de producir segmentos.` };
    }
    return { ...base, estado: "SIN_COMPARAR", motivo: "Primera lectura de la lista: en unos segundos se confirma si avanza." };
}

function describirOpcion(opcion) {
    const d = { clave: opcion.clave, id: opcion.id || "", tipo: opcion.tipo, etiqueta: opcion.etiqueta || "", transmision: opcion.transmision || "", principal: Boolean(opcion.principal) };
    if (opcion.tipo === "bunny") d.ruta = opcion.ruta;
    if (opcion.url) {
        try { d.host = new URL(opcion.url).host; } catch (_) { d.host = ""; }
    }
    return d;
}

function urlYCabecerasDe(opcion) {
    if (opcion.tipo === "bunny") {
        const base = String(APP_BASE_URL || "https://golazosp.net").replace(/\/+$/, "");
        return {
            url: generateBunnyTokenForStream(opcion.ruta, BUNNY_SECURITY_KEY, 120).url,
            cabeceras: { accept: "*/*", referer: `${base}/`, origin: base }
        };
    }
    return { url: opcion.url, cabeceras: { accept: "*/*" } };
}

function recortarEstadoSenal() {
    if (estadoSenal.size <= 100) return;
    const orden = [...estadoSenal.entries()].sort((a, b) => (a[1].ultimaMuestraEn || 0) - (b[1].ultimaMuestraEn || 0));
    orden.slice(0, estadoSenal.size - 100).forEach(([clave, valor]) => { if (!valor.enCurso) estadoSenal.delete(clave); });
}

async function verificarSenal(opcion, { forzar = false } = {}) {
    const previo = estadoSenal.get(opcion.clave) || {};
    // La caché comparte el estado de la señal, no la descripción (una prueba del editor no cambia el tablero).
    if (previo.enCurso) return previo.enCurso.then(r => ({ ...r, ...describirOpcion(opcion) }));
    if (previo.resultado && Date.now() - previo.resultado.verificado_en < (forzar ? 2000 : SENAL_CACHE_MS)) {
        return { ...previo.resultado, ...describirOpcion(opcion) };
    }
    const tarea = (async () => {
        const { url, cabeceras } = urlYCabecerasDe(opcion);
        const muestra = await muestrearLista(url, cabeceras);
        return { ...describirOpcion(opcion), ...clasificarSenal(opcion.clave, muestra, Date.now()) };
    })();
    estadoSenal.set(opcion.clave, { ...previo, enCurso: tarea });
    recortarEstadoSenal();
    try {
        const resultado = await tarea;
        estadoSenal.set(opcion.clave, { ...(estadoSenal.get(opcion.clave) || {}), enCurso: null, resultado });
        return resultado;
    } catch (error) {
        estadoSenal.set(opcion.clave, { ...(estadoSenal.get(opcion.clave) || {}), enCurso: null });
        throw error;
    }
}

// Qué se verifica en el tablero: las opciones Bunny visibles (hasta 6) y, si la señal principal (opción
// predeterminada de la transmisión predeterminada) es de otro tipo, también esa.
function opcionesParaTablero(config) {
    const lista = [];
    const transmisiones = (config.transmissions || []).filter(t => t.visible);
    const predeterminada = transmisiones.find(t => t.id === config.default_transmission_id) || transmisiones[0];
    const ordenadas = predeterminada ? [predeterminada, ...transmisiones.filter(t => t !== predeterminada)] : transmisiones;
    ordenadas.forEach(t => {
        const opciones = (t.options || []).filter(o => o.enabled);
        const porOmision = opciones.find(o => o.id === t.default_option_id) || opciones[0];
        [porOmision, ...opciones.filter(o => o !== porOmision)].filter(Boolean).forEach(o => {
            const principal = t === predeterminada && o === porOmision;
            const base = { id: `${t.id}/${o.id}`, transmision: t.name, etiqueta: o.label, principal };
            if (o.source_type === "bunny" && o.path) lista.push({ ...base, tipo: "bunny", ruta: o.path, clave: "bunny:" + o.path });
            else if (o.source_type === "external" && o.url && principal) lista.push({ ...base, tipo: "external", url: o.url, clave: "ext:" + o.url });
            else if (principal) lista.push({ ...base, tipo: o.source_type, url: o.url, clave: `otra:${t.id}/${o.id}`, noVerificable: true });
        });
    });
    const vistas = new Set();
    return lista.filter(o => {
        if (vistas.has(o.clave)) return false;
        vistas.add(o.clave);
        return true;
    }).slice(0, SENAL_MAX_VERIFICADAS);
}

function resultadoNoVerificable(opcion) {
    return {
        ...describirOpcion(opcion), estado: "NO_VERIFICABLE", verificado_en: Date.now(),
        motivo: opcion.tipo === "iframe"
            ? "Reproductor externo (iframe): el servidor no puede comprobar el video que muestra."
            : "Este tipo de fuente no se verifica."
    };
}

// 17.3.5 Actividad y salud del servidor.
function acumularQoe(r) {
    const q = metricasMinuto.qoe;
    const acotar = (v, max) => (Number.isFinite(v) && v >= 0 ? Math.min(v, max) : 0);
    q.n++;
    if (Number.isFinite(r.arranqueMs) && r.arranqueMs >= 0 && r.arranqueMs <= 600000 && q.arranques.length < 200) q.arranques.push(r.arranqueMs);
    // /qoe no exige sesión: cada reporte se acota a valores posibles para que uno falso no domine el resumen.
    q.rebuffers += acotar(r.rebuffers, 300);
    q.rebufferMs += acotar(r.rebufferMs, 60 * 60 * 1000);
    q.errores += acotar(r.errores, 100);
    q.minutos += acotar(r.minutos, 240);
}

function resumenActividad() {
    return {
        minutos: historialMetricas.slice(-HISTORIAL_METRICAS_MAX),
        en_curso: resumirMetricas(metricasMinuto, inicioMinutoMetricas),
        rechazos_429_desde_arranque: { ...rechazosPorLimitador },
        encendido_desde_ms: Date.now() - Math.round(process.uptime() * 1000)
    };
}

function resumenServidor() {
    const memoria = process.memoryUsage();
    return {
        version: VERSION_BACKEND,
        encendido_s: Math.round(process.uptime()),
        memoria_mb: Math.round(memoria.rss / 1048576),
        heap_mb: Math.round(memoria.heapUsed / 1048576),
        retardo: retardoUltimoMinuto,
        node: process.version,
        dependencias: VERSIONES_DEPENDENCIAS
    };
}

// Las etapas siguientes agregan campos al tablero y herramientas a esta lista.
const EXTENSIONES_TABLERO = [];
const HERRAMIENTAS = {
    tablero: true, probar_fuente: true, liberar_sesion: true, restaurar_pase: true,
    nueva_clave_vip: true, ingresos_admin: true
};
const CIERRES_DE_MINUTO = [];
function alCerrarMinuto(resumen) {
    CIERRES_DE_MINUTO.forEach(fn => { try { fn(resumen); } catch (_) {} });
}

const TABLERO_RATE_LIMIT_MAX = parseInt(process.env.TABLERO_RATE_LIMIT_MAX || "30", 10);
const tableroLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: TABLERO_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: claveLimitePorIp,
    skip: (req) => req.method === 'OPTIONS',
    message: MENSAJE_LIMITE_ADMIN,
    handler: manejadorLimite("tablero", MENSAJE_LIMITE_ADMIN)
});

// El tablero tiene su propio límite: se actualiza solo cada 20 s y no debe consumir el de las acciones.
app.post('/admin/tablero', tableroLimiter, verifyAdmin, async (req, res) => {
    try {
        const forzar = req.body?.verificar === true;
        const config = await getActiveStreamConfig();
        const opciones = opcionesParaTablero(config);
        const verificadas = await Promise.all(opciones.map(o => o.noVerificable
            ? Promise.resolve(resultadoNoVerificable(o))
            : verificarSenal(o, { forzar }).catch(() => ({ ...describirOpcion(o), estado: "ERROR", motivo: "No se pudo verificar la señal.", verificado_en: Date.now() }))));
        const principal = verificadas.find(v => v.principal) || verificadas[0] || null;
        const extra = {};
        EXTENSIONES_TABLERO.forEach(fn => { try { Object.assign(extra, fn()); } catch (_) {} });
        return res.json({
            success: true,
            version: VERSION_BACKEND,
            generado_en: Date.now(),
            senal: {
                principal: principal ? principal.estado : "SIN_FUENTES",
                verificadas,
                // La segunda lectura tiene que llegar después de la caché, o repetiría la primera.
                reintentar_ms: verificadas.some(v => v.estado === "SIN_COMPARAR") ? SENAL_CACHE_MS + 1000 : null,
                origen_config: ultimoOrigenConfig
            },
            actividad: resumenActividad(),
            servidor: resumenServidor(),
            alertas: { configuracion: configuracionAlertas(), ...estadoAlertas },
            herramientas: { ...HERRAMIENTAS, alertas: configuracionAlertas() },
            app_base_url: String(APP_BASE_URL || "https://golazosp.net").replace(/\/+$/, ""),
            ...extra
        });
    } catch (e) {
        console.error("❌ Error armando el tablero:", e);
        return res.status(500).json({ success: false, message: "Error armando el tablero." });
    }
});

// Prueba de una fuente desde el editor de transmisiones, antes o después de guardarla: hasta cuatro
// lecturas de la lista (al inicio, a los 4, 7 y 10 s) hasta ver que avanza. Una lista que no avanza en
// 7 s (o en 2,5 duraciones de segmento, si son más largos) se informa como detenida.
app.post('/admin/probar-fuente', adminLimiter, verifyAdmin, async (req, res) => {
    try {
        const tipo = String(req.body?.source_type || "").trim().toLowerCase();
        let opcion;
        if (tipo === "bunny") {
            const ruta = normalizeBunnyPath(req.body?.path);
            if (!ruta) return res.status(400).json({ success: false, code: "INVALID_PATH", message: "Ruta Bunny inválida: debe empezar con /stream/ y terminar en .m3u8." });
            opcion = { tipo: "bunny", ruta, clave: "bunny:" + ruta, etiqueta: String(req.body?.label || "").slice(0, 40) };
        } else if (tipo === "external" || tipo === "hls" || tipo === "iframe") {
            const url = String(req.body?.url || "").trim();
            if (!isValidHttpUrl(url) || url.length > 2000) return res.status(400).json({ success: false, code: "INVALID_URL", message: "URL inválida." });
            opcion = { tipo: tipo === "iframe" ? "iframe" : "external", url, clave: (tipo === "iframe" ? "pagina:" : "ext:") + url, etiqueta: String(req.body?.label || "").slice(0, 40) };
        } else {
            return res.status(400).json({ success: false, code: "INVALID_SOURCE", message: "Tipo de fuente inválido." });
        }

        if (opcion.tipo === "iframe") {
            const pagina = await solicitudSaliente(opcion.url, { timeoutMs: SENAL_TIMEOUT_MS, maxBytes: 64 * 1024 });
            const responde = pagina.ok;
            return res.json({
                success: true,
                resultado: {
                    ...describirOpcion(opcion), estado: responde ? "NO_VERIFICABLE" : "ERROR", http: pagina.status || null, ms: pagina.ms, verificado_en: Date.now(),
                    motivo: responde
                        ? `La página responde (código ${pagina.status}). El video dentro de un reproductor externo no se puede comprobar desde el servidor: ábralo para verlo.`
                        : (pagina.error === "red_privada" ? "La dirección apunta a una red privada o reservada: el servidor no la consulta."
                            : pagina.error === "tiempo" ? `La página no respondió en ${Math.round(SENAL_TIMEOUT_MS / 1000)} s.`
                            : pagina.error ? "No se pudo conectar con la página." : `La página respondió con el código ${pagina.status}.`)
                },
                muestras: []
            });
        }

        const { url, cabeceras } = urlYCabecerasDe(opcion);
        const muestras = [];
        let resultado = null;
        let objetivoS = 2;
        const comienzo = Date.now();
        for (let i = 0; ; i++) {
            if (i) await new Promise(r => setTimeout(r, i === 1 ? 4000 : 3000));
            const muestra = await muestrearLista(url, cabeceras);
            objetivoS = (muestra.lista && muestra.lista.objetivo_s) || objetivoS;
            const umbral = Math.max(7000, 2.5 * Math.max(1000, objetivoS * 1000));
            resultado = { ...describirOpcion(opcion), ...clasificarSenal(opcion.clave, muestra, Date.now(), { umbralMs: umbral }) };
            muestras.push({ http: resultado.http, ms: resultado.ms, secuencia: resultado.lista ? resultado.lista.secuencia : null, estado: resultado.estado });
            // Con segmentos largos se sigue leyendo hasta pasar el umbral (como máximo unos 20 s en total).
            const limite = Math.min(19000, Math.max(10000, umbral + 1000));
            if (resultado.estado !== "SIN_COMPARAR" || Date.now() - comienzo >= limite) break;
        }
        if (resultado && resultado.estado === "SIN_COMPARAR") {
            resultado = { ...resultado, motivo: `No se pudo confirmar en ${Math.round((Date.now() - comienzo) / 1000)} s si la lista avanza (segmentos de ${objetivoS} s). Pruebe otra vez.` };
        }
        estadoSenal.set(opcion.clave, { ...(estadoSenal.get(opcion.clave) || {}), resultado });
        recortarEstadoSenal();
        return res.json({ success: true, resultado, muestras });
    } catch (e) {
        console.error("❌ Error probando la fuente:", e);
        return res.status(500).json({ success: false, message: "Error probando la fuente." });
    }
});

// Liberar la sesión de un pase: el cliente puede entrar desde cualquier equipo sin «Continuar aquí» (por
// ejemplo, si su equipo anterior se apagó sin cerrar, o si alcanzó el tope de tomas de control). El equipo
// que estuviera viendo se detiene en su siguiente comprobación.
app.post('/admin/liberar-sesion', adminLimiter, verifyAdmin, async (req, res) => {
    const uid = String(req.body?.uid || "").trim();
    const reiniciarTomas = req.body?.reiniciar_tomas !== false;
    if (!uid || uid.length > 128) return res.status(400).json({ success: false, code: "MISSING_UID", message: "Falta el pase (UID)." });
    try {
        const ref = db.collection('usuarios').doc(uid);
        let resultado = null;
        await db.runTransaction(async (t) => {
            const snap = await t.get(ref);
            if (!snap.exists) {
                resultado = { status: 404, body: { success: false, code: "PASS_NOT_FOUND", message: "El pase ya no existe (pudo haberse limpiado)." } };
                return;
            }
            const data = snap.data() || {};
            if (isRevokedUser(data)) {
                resultado = { status: 409, body: { success: false, code: "PASS_REVOKED", message: "Este pase está revocado: use «Restaurar» si fue un error." } };
                return;
            }
            const estabaViendo = isUserWatchingNow(data);
            const tomas = Array.isArray(data.takeover_log) ? data.takeover_log.filter(x => Number.isFinite(x)).length : 0;
            const cambios = {
                session_id: "", active_device_id: "", active_page_id: "",
                last_status: "released_by_admin", session_released_at: nowTimestamp()
            };
            if (reiniciarTomas && tomas) cambios.takeover_log = [];
            t.update(ref, cambios);
            resultado = {
                status: 200,
                body: {
                    success: true, estaba_viendo: estabaViendo, tomas_reiniciadas: reiniciarTomas ? tomas : 0,
                    usuario: data.usuario_corto || uid,
                    message: estabaViendo
                        ? "Sesión liberada: el equipo que estaba viendo se detendrá en su próxima comprobación y el cliente puede entrar desde cualquier equipo."
                        : "Pase liberado: el cliente puede entrar desde cualquier equipo sin pulsar «Continuar aquí»."
                }
            };
        });
        if (resultado.status === 200) {
            const b = resultado.body;
            registrarAccionAdmin(req, "liberar", `${String(b.usuario).slice(0, 60)}${b.estaba_viendo ? " · estaba viendo" : ""}${b.tomas_reiniciadas ? ` · ${b.tomas_reiniciadas} toma(s) reiniciada(s)` : ""}`, { uid });
        }
        return res.status(resultado.status).json(resultado.body);
    } catch (e) {
        console.error("❌ Error liberando la sesión:", e);
        return res.status(500).json({ success: false, message: "Error liberando la sesión." });
    }
});

// Restaurar un pase revocado por error: vuelve a permitir el ingreso con su mismo código o usuario.
app.post('/admin/restaurar-pase', adminLimiter, verifyAdmin, async (req, res) => {
    const uid = String(req.body?.uid || "").trim();
    if (!uid || uid.length > 128) return res.status(400).json({ success: false, code: "MISSING_UID", message: "Falta el pase (UID)." });
    try {
        const ref = db.collection('usuarios').doc(uid);
        let resultado = null;
        await db.runTransaction(async (t) => {
            const snap = await t.get(ref);
            if (!snap.exists) {
                resultado = { status: 404, body: { success: false, code: "PASS_NOT_FOUND", message: "El pase ya no existe (pudo haberse limpiado)." } };
                return;
            }
            const data = snap.data() || {};
            if (!isRevokedUser(data)) {
                resultado = { status: 409, body: { success: false, code: "NOT_REVOKED", message: "Este pase no está revocado." } };
                return;
            }
            const vencido = getTimestampMillis(data.fecha_expiracion) <= Date.now();
            t.update(ref, {
                session_id: "", active_device_id: "", active_page_id: "",
                last_status: "restored_by_admin", restored_at: nowTimestamp()
            });
            resultado = {
                status: 200,
                body: {
                    success: true, vencido, usuario: data.usuario_corto || uid,
                    message: vencido
                        ? "Pase restaurado, pero ya venció: extiéndalo para que el cliente pueda entrar."
                        : "Pase restaurado: el cliente puede volver a entrar con su código o usuario."
                }
            };
        });
        if (resultado.status === 200) {
            registrarAccionAdmin(req, "restaurar", `${String(resultado.body.usuario).slice(0, 60)}${resultado.body.vencido ? " · vencido" : ""}`, { uid });
        }
        return res.status(resultado.status).json(resultado.body);
    } catch (e) {
        console.error("❌ Error restaurando el pase:", e);
        return res.status(500).json({ success: false, message: "Error restaurando el pase." });
    }
});

// Nueva contraseña para un socio VIP que perdió la suya (la clave no se guarda en ningún lado, así que no
// se puede «reenviar»). Las sesiones abiertas con la anterior dejan de renovarse (en una hora como máximo).
app.post('/admin/nueva-clave-vip', adminLimiter, verifyAdmin, async (req, res) => {
    const uid = String(req.body?.uid || "").trim();
    if (!uid || uid.length > 128) return res.status(400).json({ success: false, code: "MISSING_UID", message: "Falta el socio (UID)." });
    try {
        const snap = await db.collection('usuarios').doc(uid).get();
        if (!snap.exists) return res.status(404).json({ success: false, code: "PASS_NOT_FOUND", message: "El socio ya no existe (pudo haberse limpiado)." });
        const data = snap.data() || {};
        const esVip = data.tipo_acceso === "vip" || data.login_mode === "email_password";
        if (!esVip) return res.status(400).json({ success: false, code: "NOT_VIP", message: "Solo los socios VIP tienen contraseña: los pases rápidos entran con su código." });
        if (isRevokedUser(data)) return res.status(409).json({ success: false, code: "PASS_REVOKED", message: "Este socio está revocado: restáurelo antes de darle una contraseña nueva." });
        try {
            const cuenta = await auth.getUser(uid);
            if (cuenta && cuenta.customClaims && cuenta.customClaims.admin === true) {
                return res.status(403).json({ success: false, code: "ADMIN_ACCOUNT", message: "Esa cuenta es de un administrador: su contraseña no se cambia desde el panel." });
            }
        } catch (_) {
            // Si Auth no responde aquí, el cambio de contraseña de abajo dará el error que corresponda.
        }
        const clave = crypto.randomInt(10000000, 100000000).toString();
        try {
            await auth.updateUser(uid, { password: clave });
        } catch (errorAuth) {
            if (errorAuth && errorAuth.code === "auth/user-not-found") {
                return res.status(404).json({ success: false, code: "AUTH_USER_NOT_FOUND", message: "La cuenta del socio no existe en Firebase Authentication." });
            }
            throw errorAuth;
        }
        let sesionesCerradas = false;
        try {
            await auth.revokeRefreshTokens(uid);
            sesionesCerradas = true;
        } catch (errorRevocar) {
            console.error("❌ No se pudieron cerrar las sesiones anteriores del socio:", errorRevocar.message);
        }
        registrarAccionAdmin(req, "nueva_clave_vip", `${String(data.usuario_corto || uid).slice(0, 80)}${sesionesCerradas ? "" : " · sin cerrar sesiones"}`, { uid });
        return res.json({
            success: true, usuario: data.usuario_corto || "", clave, expira_ms: getTimestampMillis(data.fecha_expiracion),
            sesiones_cerradas: sesionesCerradas,
            message: sesionesCerradas
                ? "Contraseña nueva generada. Las sesiones abiertas con la anterior dejan de renovarse (en una hora como máximo)."
                : "Contraseña nueva generada, pero no se pudieron cerrar las sesiones abiertas con la anterior: si el socio compartió su acceso, revóquelo y restáurelo."
        });
    } catch (e) {
        console.error("❌ Error generando la contraseña del socio:", e);
        return res.status(500).json({ success: false, message: "Error generando la contraseña." });
    }
});

// --- 17.4 VIGILANCIA DE LA SEÑAL Y ALERTAS (B11) ---
// Con VIGILANCIA_SENAL=on, el servidor verifica la señal principal cada VIGILANCIA_INTERVALO_S (20 s) aunque
// no haya un panel abierto. Si la señal estaba en vivo y deja de avanzar durante VIGILANCIA_CAIDA_S (45 s),
// abre un incidente y avisa; al recuperarse, lo cierra con su duración. Si nunca estuvo en vivo (no hay
// partido) no avisa. También avisa de picos de rechazos por límite (429) y de errores del servidor (5xx).
const VIGILANCIA_SENAL = String(process.env.VIGILANCIA_SENAL || "").trim().toLowerCase() === "on";
const VIGILANCIA_INTERVALO_MS = Math.max(10, parseInt(process.env.VIGILANCIA_INTERVALO_S || "20", 10) || 20) * 1000;
const VIGILANCIA_CAIDA_MS = Math.max(20, parseInt(process.env.VIGILANCIA_CAIDA_S || "45", 10) || 45) * 1000;
const VIGILANCIA_FIN_MS = 30 * 60 * 1000;
const ALERTA_429_POR_MIN = Math.max(1, parseInt(process.env.ALERTA_429_POR_MIN || "30", 10) || 30);
const ALERTA_5XX_POR_MIN = Math.max(1, parseInt(process.env.ALERTA_5XX_POR_MIN || "10", 10) || 10);
const INCIDENTES_DIAS = 90;

const vigilancia = {
    estado: "INACTIVA",        // INACTIVA (no hay transmisión en curso), EN_VIVO o CAIDA
    desde_ms: Date.now(),
    ultima: null,              // última verificación de la señal principal
    ultimoAvanceEn: 0,
    incidente: null,           // incidente abierto
    incidentes: [],            // últimos incidentes (abiertos y cerrados), en memoria
    verificaciones: 0,
    errores: 0
};

function describirFuenteVigilada(v) {
    return `${v.transmision ? v.transmision + " / " : ""}${v.etiqueta || v.ruta || v.host || "señal principal"}`;
}

function minutosTexto(ms) {
    const min = Math.round(ms / 60000);
    return min < 1 ? `${Math.round(ms / 1000)} s` : `${min} min`;
}

// B12 lo reemplaza: estado del emisor (OBS) según el agente del origen, o null si no hay datos recientes.
let emisorSegunAgente = () => null;

async function abrirIncidente(ahora, resultado, principal) {
    const emisor = emisorSegunAgente();
    const emisorDetenido = Boolean(emisor && emisor.conectado === false);
    const fuente = describirFuenteVigilada(resultado);
    const incidente = {
        id: "", tipo: emisorDetenido ? "emision_detenida" : "senal_caida", clave: principal ? principal.clave : "",
        inicio_ms: vigilancia.ultimoAvanceEn || ahora, fin_ms: null, duracion_s: null,
        motivo: String(resultado.motivo || "").slice(0, 300), fuente, cierre: "", guardado: null
    };
    vigilancia.incidente = incidente;
    vigilancia.incidentes.unshift(incidente);
    if (vigilancia.incidentes.length > 20) vigilancia.incidentes.length = 20;
    console.warn(`VIGILANCIA ${emisorDetenido ? "emisión detenida" : "señal caída"} | ${fuente} | ${incidente.motivo}`);
    // El aviso sale primero: un Firestore lento no lo retrasa ni detiene la vigilancia.
    const hace = minutosTexto(ahora - incidente.inicio_ms);
    if (emisorDetenido) {
        enviarAlerta(`AVISO: OBS dejó de emitir y la señal ${fuente} no avanza desde hace ${hace}. Si terminó el partido, no hace falta hacer nada; si no, revise OBS.`);
    } else if (emisor && emisor.conectado) {
        enviarAlerta(`ALERTA: la señal ${fuente} dejó de avanzar hace ${hace} aunque OBS sigue conectado. Causa probable: ${incidente.motivo}`);
    } else {
        enviarAlerta(`ALERTA: la señal ${fuente} dejó de avanzar hace ${hace}. Si terminó el partido, ignore este aviso. Causa probable: ${incidente.motivo}`);
    }
    incidente.guardado = db.collection('incidentes').add({
        tipo: incidente.tipo, inicio: admin.firestore.Timestamp.fromMillis(incidente.inicio_ms), fin: null,
        duracion_s: null, motivo: incidente.motivo, fuente: incidente.fuente, cierre: "",
        expira_en: admin.firestore.Timestamp.fromMillis(ahora + INCIDENTES_DIAS * 86400000)
    }).then(ref => { incidente.id = ref.id; }).catch(error => {
        console.error("❌ No se pudo guardar el incidente:", error.message);
    });
}

async function cerrarIncidente(ahora, cierre) {
    const incidente = vigilancia.incidente;
    if (!incidente) return;
    vigilancia.incidente = null;
    incidente.fin_ms = ahora;
    incidente.duracion_s = Math.round((ahora - incidente.inicio_ms) / 1000);
    incidente.cierre = cierre;
    console.warn(`VIGILANCIA incidente cerrado (${cierre}) | ${incidente.fuente} | ${incidente.duracion_s} s`);
    const duracion = minutosTexto(ahora - incidente.inicio_ms);
    if (cierre === "recuperada") {
        enviarAlerta(`Señal recuperada: ${incidente.fuente} vuelve a estar en vivo tras ${duracion} sin avanzar.`);
    } else if (cierre === "fuente_cambiada") {
        enviarAlerta(`Se cambió la señal principal durante la caída de ${incidente.fuente} (${duracion}): se cierra el incidente y la vigilancia sigue con la señal nueva.`);
    }
    // «sin_recuperacion» (30 minutos sin volver) solo se registra: un segundo aviso no aporta nada.
    Promise.resolve(incidente.guardado).then(() => {
        if (!incidente.id) return null;
        return db.collection('incidentes').doc(incidente.id).update({
            fin: admin.firestore.Timestamp.fromMillis(ahora), duracion_s: incidente.duracion_s, cierre
        });
    }).catch(error => console.error("❌ No se pudo cerrar el incidente:", error.message));
}

function pasarAEnEspera(ahora) {
    vigilancia.estado = "INACTIVA";
    vigilancia.desde_ms = ahora;
}

let vigilandoAhora = false;
async function vigilarSenal() {
    if (vigilandoAhora) return;
    vigilandoAhora = true;
    try {
        const config = await getActiveStreamConfig();
        const principal = opcionesParaTablero(config).find(o => o.principal);
        if (!principal || principal.noVerificable) {
            vigilancia.ultima = { estado: principal ? "NO_VERIFICABLE" : "SIN_FUENTES", motivo: principal ? "La señal principal no es verificable (reproductor externo)." : "No hay transmisiones visibles.", en_ms: Date.now() };
            // Si durante una caída la señal principal pasa a un reproductor externo o desaparece, el incidente se cierra.
            if (vigilancia.estado === "CAIDA") await cerrarIncidente(Date.now(), "fuente_cambiada");
            if (vigilancia.estado !== "INACTIVA") pasarAEnEspera(Date.now());
            return;
        }
        // Si se cambió la señal principal durante una caída, el incidente de la anterior se cierra.
        if (vigilancia.estado === "CAIDA" && vigilancia.incidente && vigilancia.incidente.clave && vigilancia.incidente.clave !== principal.clave) {
            await cerrarIncidente(Date.now(), "fuente_cambiada");
            pasarAEnEspera(Date.now());
        }
        const r = await verificarSenal(principal);
        const ahora = Date.now();
        vigilancia.verificaciones++;
        vigilancia.ultima = { estado: r.estado, motivo: r.motivo, en_ms: ahora, fuente: describirFuenteVigilada(r) };
        if (r.estado === "EN_VIVO") {
            // Con un resultado en caché, el avance cuenta desde cuando se verificó, no desde ahora.
            vigilancia.ultimoAvanceEn = Math.min(ahora, Number(r.verificado_en) || ahora);
            if (vigilancia.estado === "CAIDA") await cerrarIncidente(ahora, "recuperada");
            else if (vigilancia.estado === "INACTIVA") {
                console.log(`VIGILANCIA señal en vivo | ${describirFuenteVigilada(r)}`);
                enviarAlerta(`Comenzó la transmisión (o se reanudó la vigilancia tras un reinicio del servidor): ${describirFuenteVigilada(r)} está en vivo. La vigilancia de la señal queda activa.`);
            }
            if (vigilancia.estado !== "EN_VIVO") vigilancia.desde_ms = ahora;
            vigilancia.estado = "EN_VIVO";
            return;
        }
        if (r.estado === "SIN_COMPARAR") return;
        if (vigilancia.estado === "EN_VIVO" && ahora - vigilancia.ultimoAvanceEn >= VIGILANCIA_CAIDA_MS) {
            vigilancia.estado = "CAIDA";
            vigilancia.desde_ms = ahora;
            await abrirIncidente(ahora, r, principal);
        } else if (vigilancia.estado === "CAIDA" && vigilancia.incidente && ahora - vigilancia.incidente.inicio_ms >= VIGILANCIA_FIN_MS) {
            await cerrarIncidente(ahora, "sin_recuperacion");
            pasarAEnEspera(ahora);
        }
    } catch (error) {
        vigilancia.errores++;
    } finally {
        vigilandoAhora = false;
    }
}

if (VIGILANCIA_SENAL) {
    // El estado de la vigilancia vive en memoria (una sola instancia del servicio): un incidente que quedó
    // abierto en Firestore por un reinicio se cierra al arrancar.
    const temporizadorLimpieza = setTimeout(() => {
        try {
            db.collection('incidentes').where('fin', '==', null).limit(20).get().then(snap => {
                snap.forEach(doc => {
                    doc.ref.update({ fin: admin.firestore.Timestamp.fromMillis(Date.now()), cierre: "reinicio_servidor" }).catch(() => {});
                });
            }).catch(() => {});
        } catch (_) {
            // Nunca debe tumbar el proceso: a lo sumo, el incidente viejo queda abierto en Firestore.
        }
    }, 5000);
    if (temporizadorLimpieza.unref) temporizadorLimpieza.unref();
    const temporizadorVigilancia = setInterval(() => { vigilarSenal().catch(() => {}); }, VIGILANCIA_INTERVALO_MS);
    if (temporizadorVigilancia.unref) temporizadorVigilancia.unref();
    console.log(`VIGILANCIA de la señal activa: cada ${VIGILANCIA_INTERVALO_MS / 1000} s; aviso tras ${VIGILANCIA_CAIDA_MS / 1000} s sin avanzar.`);
}

// Picos por minuto (con o sin vigilancia de la señal): como máximo un aviso de cada tipo cada 15 minutos.
const ultimoAvisoPico = { r429: 0, r5xx: 0 };
CIERRES_DE_MINUTO.push((m) => {
    const ahora = Date.now();
    if (m.r429 >= ALERTA_429_POR_MIN && ahora - ultimoAvisoPico.r429 >= 15 * 60000) {
        ultimoAvisoPico.r429 = ahora;
        enviarAlerta(`Atención: ${m.r429} solicitudes rechazadas por límite (429) en el último minuto. Si hay un partido en curso, revise el tablero del panel: pueden ser espectadores bloqueados.`);
    }
    if (m.r5xx >= ALERTA_5XX_POR_MIN && ahora - ultimoAvisoPico.r5xx >= 15 * 60000) {
        ultimoAvisoPico.r5xx = ahora;
        enviarAlerta(`Atención: ${m.r5xx} errores del servidor (5xx) en el último minuto. Revise los registros de Render.`);
    }
});

function resumenVigilancia() {
    return {
        activa: VIGILANCIA_SENAL,
        estado: vigilancia.estado,
        desde_ms: vigilancia.desde_ms,
        ultima: vigilancia.ultima,
        intervalo_s: VIGILANCIA_INTERVALO_MS / 1000,
        caida_s: VIGILANCIA_CAIDA_MS / 1000,
        incidentes: vigilancia.incidentes.slice(0, 10).map(i => ({
            id: i.id, tipo: i.tipo, inicio_ms: i.inicio_ms, fin_ms: i.fin_ms, duracion_s: i.duracion_s,
            motivo: i.motivo, fuente: i.fuente, cierre: i.cierre
        }))
    };
}

HERRAMIENTAS.vigilancia = VIGILANCIA_SENAL ? "activa" : "desactivada";
HERRAMIENTAS.alerta_prueba = true;
EXTENSIONES_TABLERO.push(() => ({ vigilancia: resumenVigilancia() }));

// Aviso de prueba desde el panel: confirma que el bot y el chat están bien configurados.
app.post('/admin/alertas/prueba', adminLimiter, verifyAdmin, async (req, res) => {
    if (!ALERTAS_TELEGRAM) {
        return res.status(409).json({
            success: false, code: "ALERTS_OFF", configuracion: configuracionAlertas(),
            message: configuracionAlertas() === "incompleta"
                ? "Los avisos están pedidos (ALERTAS_TELEGRAM=on), pero falta TELEGRAM_BOT_TOKEN o MI_TELEGRAM_ID con un valor válido en Render."
                : "Los avisos por Telegram están desactivados. En Render: ALERTAS_TELEGRAM=on, con TELEGRAM_BOT_TOKEN y MI_TELEGRAM_ID."
        });
    }
    try {
        // Si hay avisos en cola (o Telegram está lento), no se espera más de 10 s: el aviso sale igual después.
        const entregada = await Promise.race([
            enviarAlerta(`Prueba de avisos desde el panel (${(req.golazoAdmin && req.golazoAdmin.email) || "administrador"}): si lee este mensaje, los avisos funcionan.`, { forzar: true }),
            new Promise(resolver => { const t = setTimeout(() => resolver("en_cola"), 10000); if (t.unref) t.unref(); })
        ]);
        if (entregada === "en_cola") {
            registrarAccionAdmin(req, "alerta_prueba", "Aviso de prueba en cola", {});
            return res.json({ success: true, entregada: false, en_cola: true, message: "El aviso quedó en cola: Telegram está lento o hay otros avisos pendientes. Llegará en cuanto se pueda." });
        }
        registrarAccionAdmin(req, "alerta_prueba", entregada ? "Aviso de prueba entregado" : `Aviso de prueba no entregado (${estadoAlertas.ultimo_error || "sin detalle"})`, {});
        return res.json({
            success: true, entregada,
            message: entregada ? "Aviso entregado: revise Telegram." : `No se pudo entregar el aviso: ${estadoAlertas.ultimo_error || "sin detalle"}.`
        });
    } catch (e) {
        console.error("❌ Error enviando el aviso de prueba:", e);
        return res.status(500).json({ success: false, message: "Error enviando el aviso de prueba." });
    }
});

// --- 17.5 AGENTE DEL ORIGEN Y CLAVE DE EMISIÓN (B12) ---
// El agente es un programa pequeño en el VPS que cada 15 s envía el estado de OBS (emisor RTMP), del HLS
// que genera nginx y del propio VPS. Firma cada envío con AGENTE_CLAVE (HMAC-SHA256 del instante y del
// cuerpo) y recibe, firmada igual, la lista de claves de emisión vigentes (solo sus huellas SHA-256) para
// validar la publicación de OBS (on_publish). Sin AGENTE_CLAVE de 32 caracteres o más, nada de esto existe.
const AGENTE_CLAVE = String(process.env.AGENTE_CLAVE || "").trim();
const AGENTE_ACTIVO = AGENTE_CLAVE.length >= 32;
if (AGENTE_CLAVE && !AGENTE_ACTIVO) {
    console.warn("AVISO agente: AGENTE_CLAVE debe tener al menos 32 caracteres; el agente del origen queda desactivado.");
}
const CLAVE_ANTERIOR_HORAS = Math.min(72, Math.max(1, parseInt(process.env.CLAVE_EMISION_ANTERIOR_HORAS || "24", 10) || 24));
const EMISION_NOMBRE = (String(process.env.EMISION_NOMBRE || "canal").trim().replace(/[^A-Za-z0-9_-]/g, "") || "canal").slice(0, 40);
const EMISION_SERVIDOR = String(process.env.EMISION_SERVIDOR_RTMP || "").trim().slice(0, 200);
const estadoOrigen = { datos: null, recibido_en: 0, ip: "", latidos: 0, rechazados: 0 };
let clavesEmision = null;
let clavesEmisionLeidasEn = 0;
let ultimoTiempoAgente = 0;
const CLAVES_ANTERIORES_MAX = 3;

// La firma separa el sentido del mensaje («latido» del agente, «respuesta» del servidor): una respuesta
// copiada no sirve como latido. Además, el instante de cada latido debe ser mayor que el del anterior.
function firmarAgente(tipo, tiempo, cuerpo) {
    return crypto.createHmac('sha256', AGENTE_CLAVE).update(`${tipo}\n${tiempo}.${cuerpo}`).digest('hex');
}

function compararSeguro(a, b) {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function numeroAcotado(v, min, max) {
    const n = Number(v);
    return v === null || v === undefined || v === "" || !Number.isFinite(n) ? null : Math.min(max, Math.max(min, n));
}

function textoCorto(v, max = 40) {
    return String(v === null || v === undefined ? "" : v).replace(/[^\w .:,/+-]/g, "").slice(0, max);
}

function ipOVacio(v) {
    return net.isIP(String(v || "")) ? String(v) : "";
}

// Solo se guardan los campos conocidos, acotados: el agente no puede llenar la memoria del servidor.
function depurarDatosAgente(d) {
    const o = (x) => (x && typeof x === "object" && !Array.isArray(x) ? x : {});
    const e = o(d && d.emisor), h = o(d && d.hls), s = o(d && d.sistema), v = o(d && d.validador);
    return {
        agente_version: textoCorto(d && d.agente_version, 20),
        emisor: {
            conectado: e.conectado === true, ip: ipOVacio(e.ip), segundos: numeroAcotado(e.segundos, 0, 1e7),
            kbps_entrada: numeroAcotado(e.kbps_entrada, 0, 1e6), kbps_video: numeroAcotado(e.kbps_video, 0, 1e6), kbps_audio: numeroAcotado(e.kbps_audio, 0, 1e6),
            ancho: numeroAcotado(e.ancho, 0, 10000), alto: numeroAcotado(e.alto, 0, 10000), fps: numeroAcotado(e.fps, 0, 300),
            codec_video: textoCorto(e.codec_video, 20), perfil: textoCorto(e.perfil, 20), nivel: textoCorto(e.nivel, 10),
            codec_audio: textoCorto(e.codec_audio, 20), canales: numeroAcotado(e.canales, 0, 16), frecuencia: numeroAcotado(e.frecuencia, 0, 192000),
            clientes: numeroAcotado(e.clientes, 0, 1e6)
        },
        hls: {
            existe: h.existe === true, edad_lista_s: numeroAcotado(h.edad_lista_s, 0, 1e8), segmentos: numeroAcotado(h.segmentos, 0, 10000),
            objetivo_s: numeroAcotado(h.objetivo_s, 0, 3600), secuencia: numeroAcotado(h.secuencia, 0, 1e12),
            ultima_duracion_s: numeroAcotado(h.ultima_duracion_s, 0, 3600), edad_segmento_s: numeroAcotado(h.edad_segmento_s, 0, 1e8)
        },
        sistema: {
            carga_1m: numeroAcotado(s.carga_1m, 0, 1000), cpus: numeroAcotado(s.cpus, 0, 1024),
            memoria_total_mb: numeroAcotado(s.memoria_total_mb, 0, 1e7), memoria_libre_mb: numeroAcotado(s.memoria_libre_mb, 0, 1e7),
            hls_uso_pct: numeroAcotado(s.hls_uso_pct, 0, 100), salida_mbps: numeroAcotado(s.salida_mbps, 0, 1e5),
            entrada_mbps: numeroAcotado(s.entrada_mbps, 0, 1e5), encendido_s: numeroAcotado(s.encendido_s, 0, 1e10), nginx: s.nginx === true
        },
        validador: {
            activo: v.activo === true, claves_version: numeroAcotado(v.claves_version, 0, 1e9), aceptadas: numeroAcotado(v.aceptadas, 0, 1e9),
            rechazadas: numeroAcotado(v.rechazadas, 0, 1e9), ultima_ip_rechazada: ipOVacio(v.ultima_ip_rechazada),
            ultimo_rechazo_hace_s: numeroAcotado(v.ultimo_rechazo_hace_s, 0, 1e9)
        },
        // Nombre de la aplicación y del stream que valida el agente (deben coincidir con EMISION_NOMBRE).
        rtmp_app: textoCorto(d && d.rtmp_app, 40),
        rtmp_stream: textoCorto(d && d.rtmp_stream, 40)
    };
}

async function leerClavesEmision(forzar = false) {
    if (!forzar && clavesEmision && Date.now() - clavesEmisionLeidasEn < 60000) return clavesEmision;
    const snap = await db.collection('config').doc('emision').get();
    const d = snap.exists ? snap.data() || {} : {};
    clavesEmision = { version: Number(d.version) || 0, actual: d.actual || null, anterior: d.anterior || null, anteriores: Array.isArray(d.anteriores) ? d.anteriores : [] };
    clavesEmisionLeidasEn = Date.now();
    return clavesEmision;
}

// Claves anteriores todavía vigentes, de la más reciente a la más antigua (hasta 3).
function anterioresVigentes(c, ahora = Date.now()) {
    if (!c) return [];
    return [c.anterior].concat(Array.isArray(c.anteriores) ? c.anteriores : [])
        .filter(x => x && x.hash && Number(x.vence_en_ms) > ahora).slice(0, CLAVES_ANTERIORES_MAX);
}

// Lo que recibe el agente: las huellas vigentes y hasta cuándo vale cada una (null: la actual, sin plazo).
// Sin una clave actual se responde null («conserve las suyas»): una lista vacía haría rechazar a OBS.
function clavesParaAgente(c) {
    if (!c || !c.actual || !c.actual.hash) return null;
    const anteriores = anterioresVigentes(c);
    return {
        version: c.version,
        hashes: [String(c.actual.hash)].concat(anteriores.map(x => String(x.hash))),
        vencen: [null].concat(anteriores.map(x => Number(x.vence_en_ms)))
    };
}

function describirClaves(c) {
    const ahora = Date.now();
    return {
        version: c ? c.version : 0,
        actual: c && c.actual ? { version: c.actual.version, creada_en_ms: c.actual.creada_en_ms, creada_por: c.actual.creada_por || "" } : null,
        anterior: c && c.anterior ? {
            version: c.anterior.version, creada_en_ms: c.anterior.creada_en_ms, vence_en_ms: c.anterior.vence_en_ms,
            vigente: Number(c.anterior.vence_en_ms) > ahora
        } : null,
        anteriores_vigentes: anterioresVigentes(c, ahora).length,
        nombre: EMISION_NOMBRE, servidor_rtmp: EMISION_SERVIDOR, horas_anterior: CLAVE_ANTERIOR_HORAS
    };
}

function resumenAgente() {
    const ahora = Date.now();
    return {
        activo: AGENTE_ACTIVO,
        conectado: Boolean(estadoOrigen.recibido_en && ahora - estadoOrigen.recibido_en < 60000),
        visto_hace_s: estadoOrigen.recibido_en ? Math.round((ahora - estadoOrigen.recibido_en) / 1000) : null,
        ip: estadoOrigen.ip, latidos: estadoOrigen.latidos, firmas_rechazadas: estadoOrigen.rechazados,
        datos: estadoOrigen.datos
    };
}

HERRAMIENTAS.agente = AGENTE_ACTIVO ? "activo" : "desactivado";
HERRAMIENTAS.clave_emision = AGENTE_ACTIVO;

// La vigilancia (B11) usa el estado de OBS que informa el agente para distinguir el fin de una emisión de una
// caída. Sin datos recientes, o si nginx no responde (no se sabe si OBS está conectado), no opina.
emisorSegunAgente = () => {
    const d = estadoOrigen.datos;
    if (!AGENTE_ACTIVO || !d || !estadoOrigen.recibido_en || Date.now() - estadoOrigen.recibido_en > 60000) return null;
    if (!d.sistema || d.sistema.nginx !== true) return null;
    return { conectado: Boolean(d.emisor && d.emisor.conectado) };
};

if (AGENTE_ACTIVO) {
    EXTENSIONES_TABLERO.push(() => ({ origen: resumenAgente(), emision: clavesEmision ? describirClaves(clavesEmision) : null }));

    const agenteLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 12,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: claveLimitePorIp,
        message: MENSAJE_LIMITE_GENERAL,
        handler: manejadorLimite("agente", MENSAJE_LIMITE_GENERAL)
    });

    // El agente envía texto plano (así el analizador JSON general no toca el cuerpo y la firma se comprueba
    // sobre los bytes recibidos). Un reloj desfasado más de 60 s se rechaza: una copia vieja no sirve.
    app.post('/agente/latido', agenteLimiter, express.text({ type: '*/*', limit: '16kb' }), async (req, res) => {
        try {
            const tiempo = Number(req.headers['x-golazo-tiempo']);
            const firma = String(req.headers['x-golazo-firma'] || "");
            const cuerpo = typeof req.body === "string" ? req.body : "";
            if (!Number.isFinite(tiempo) || Math.abs(Date.now() - tiempo) > 60000 || tiempo <= ultimoTiempoAgente ||
                !compararSeguro(firma, firmarAgente("latido", tiempo, cuerpo))) {
                estadoOrigen.rechazados++;
                return res.status(401).json({ success: false, code: "AGENT_SIGNATURE" });
            }
            ultimoTiempoAgente = tiempo;
            let datos;
            try { datos = JSON.parse(cuerpo); } catch (_) {
                return res.status(400).json({ success: false, code: "BAD_JSON" });
            }
            estadoOrigen.datos = depurarDatosAgente(datos);
            estadoOrigen.recibido_en = Date.now();
            estadoOrigen.ip = ipCliente(req);
            estadoOrigen.latidos++;
            let claves = null;
            try {
                claves = clavesParaAgente(await leerClavesEmision());
            } catch (error) {
                // Sin Firestore, el agente conserva las claves que ya tiene.
                console.error("❌ No se pudieron leer las claves de emisión:", error.message);
            }
            const respuesta = JSON.stringify({ success: true, servidor_ms: Date.now(), claves });
            const t = Date.now();
            res.set('X-Golazo-Tiempo', String(t));
            res.set('X-Golazo-Firma', firmarAgente("respuesta", t, respuesta));
            return res.type('application/json').send(respuesta);
        } catch (e) {
            console.error("❌ Error atendiendo al agente del origen:", e && e.message);
            return res.status(500).json({ success: false });
        }
    });

    app.post('/admin/clave-emision/estado', adminLimiter, verifyAdmin, async (req, res) => {
        try {
            const c = await leerClavesEmision(true);
            return res.json({ success: true, ...describirClaves(c), agente: resumenAgente() });
        } catch (e) {
            console.error("❌ Error leyendo la clave de emisión:", e);
            return res.status(500).json({ success: false, message: "Error leyendo la clave de emisión." });
        }
    });

    // Nueva clave: se muestra una sola vez (Firestore guarda solo su huella). La anterior sigue valiendo
    // CLAVE_EMISION_ANTERIOR_HORAS (24 h) o hasta retirarla: cambiar la clave no corta a OBS si reconecta.
    app.post('/admin/clave-emision/nueva', adminLimiter, verifyAdmin, async (req, res) => {
        if (req.body?.confirmar !== true) {
            return res.status(400).json({ success: false, code: "CONFIRM_REQUIRED", message: "Confirme que no hay un partido en curso antes de generar una clave nueva." });
        }
        try {
            const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            let clave = "";
            for (let i = 0; i < 24; i++) clave += abc[crypto.randomInt(abc.length)];
            const hash = crypto.createHash('sha256').update(clave).digest('hex');
            const ref = db.collection('config').doc('emision');
            let resultado = null;
            await db.runTransaction(async (t) => {
                const snap = await t.get(ref);
                const d = snap.exists ? snap.data() || {} : {};
                const version = (Number(d.version) || 0) + 1;
                const ahora = Date.now();
                // La clave actual pasa a «anterior» y las anteriores que siguen vigentes se conservan (hasta 3):
                // dos rotaciones seguidas (doble clic o un reenvío del navegador) no dejan sin validez la de OBS.
                const relevada = d.actual && d.actual.hash ? { ...d.actual, vence_en_ms: ahora + CLAVE_ANTERIOR_HORAS * 3600000 } : null;
                const previas = (relevada ? [relevada] : []).concat(anterioresVigentes(d, ahora)).slice(0, CLAVES_ANTERIORES_MAX);
                const anterior = previas[0] || null;
                const anteriores = previas.slice(1);
                const actual = { hash, version, creada_en_ms: ahora, creada_por: (req.golazoAdmin && (req.golazoAdmin.email || req.golazoAdmin.uid)) || "" };
                t.set(ref, { version, actual, anterior, anteriores, actualizado_en: nowTimestamp() });
                resultado = { version, actual, anterior, anteriores };
            });
            clavesEmision = resultado;
            clavesEmisionLeidasEn = Date.now();
            registrarAccionAdmin(req, "clave_emision", `Nueva clave de emisión (versión ${resultado.version})${resultado.anterior ? `; la anterior vale ${CLAVE_ANTERIOR_HORAS} h más` : ""}`, { version: resultado.version });
            return res.json({
                success: true, clave, clave_obs: `${EMISION_NOMBRE}?k=${clave}`, servidor_rtmp: EMISION_SERVIDOR,
                version: resultado.version, anterior_vence_en_ms: resultado.anterior ? resultado.anterior.vence_en_ms : null,
                anteriores_vigentes: anterioresVigentes(resultado).length,
                message: "Clave nueva generada. Cópiela ahora: no se vuelve a mostrar."
            });
        } catch (e) {
            console.error("❌ Error generando la clave de emisión:", e);
            return res.status(500).json({ success: false, message: "Error generando la clave de emisión." });
        }
    });

    app.post('/admin/clave-emision/retirar-anterior', adminLimiter, verifyAdmin, async (req, res) => {
        try {
            const ref = db.collection('config').doc('emision');
            let resultado = null;
            await db.runTransaction(async (t) => {
                const snap = await t.get(ref);
                const d = snap.exists ? snap.data() || {} : {};
                const vigentes = anterioresVigentes(d);
                if (!vigentes.length) {
                    resultado = { status: 409, body: { success: false, code: "NO_PREVIOUS_KEY", message: "No hay claves anteriores vigentes." } };
                    return;
                }
                t.set(ref, { ...d, anterior: null, anteriores: [], actualizado_en: nowTimestamp() });
                resultado = { status: 200, body: { success: true, retiradas: vigentes.length, message: vigentes.length > 1 ? `${vigentes.length} claves anteriores retiradas: solo vale la actual.` : "Clave anterior retirada: solo vale la actual." }, version: vigentes.map(x => x.version).join(", "), datos: { version: Number(d.version) || 0, actual: d.actual || null, anterior: null, anteriores: [] } };
            });
            if (resultado.status === 200) {
                clavesEmision = resultado.datos;
                clavesEmisionLeidasEn = Date.now();
                registrarAccionAdmin(req, "clave_emision", `Claves de emisión anteriores retiradas (versión ${resultado.version})`, { version: resultado.version });
            }
            return res.status(resultado.status).json(resultado.body);
        } catch (e) {
            console.error("❌ Error retirando la clave anterior:", e);
            return res.status(500).json({ success: false, message: "Error retirando la clave anterior." });
        }
    });
}

// --- 17.6 CDN: PURGA Y CONSUMO (B13, OPCIONAL) ---
// Necesita la clave de la API de la cuenta de Bunny (BUNNY_API_KEY) y el número de la zona (BUNNY_PULLZONE_ID).
// Advertencia: Bunny tiene una sola clave de API por cuenta y controla toda la cuenta (zonas, facturación).
// Sin ambas variables, nada de esto existe. La clave nunca se escribe en los registros ni en las respuestas.
const BUNNY_API_KEY = String(process.env.BUNNY_API_KEY || "").trim();
const BUNNY_PULLZONE_ID = String(process.env.BUNNY_PULLZONE_ID || "").trim();
const CDN_API_ACTIVA = /^[A-Za-z0-9-]{20,}$/.test(BUNNY_API_KEY) && /^\d{1,12}$/.test(BUNNY_PULLZONE_ID);
if ((BUNNY_API_KEY || BUNNY_PULLZONE_ID) && !CDN_API_ACTIVA) {
    console.warn("AVISO CDN: faltan BUNNY_API_KEY o BUNNY_PULLZONE_ID con un valor válido; la purga y el consumo quedan desactivados.");
}
const CDN_PRECIO_GB_USD = Number(process.env.CDN_PRECIO_GB_USD) > 0 ? Number(process.env.CDN_PRECIO_GB_USD) : null;
const TIPO_CAMBIO_PEN = Number(process.env.TIPO_CAMBIO_PEN) > 0 ? Number(process.env.TIPO_CAMBIO_PEN) : null;
const PRECIO_ACCESO_PEN = Number(process.env.PRECIO_ACCESO_PEN) > 0 ? Number(process.env.PRECIO_ACCESO_PEN) : 5;
let ultimaPurgaCdn = 0;
let consumoCdnCache = null;

function mensajeErrorBunny(r) {
    if (r.error) return `Bunny no respondió (${r.error === "tiempo" ? "tiempo agotado" : r.error}).`;
    if (r.status === 401 || r.status === 403) return `Bunny rechazó la clave de la API (${r.status}): revise BUNNY_API_KEY.`;
    return `Bunny respondió con el código ${r.status}.`;
}

HERRAMIENTAS.cdn = CDN_API_ACTIVA ? "bunny" : "desactivada";

if (CDN_API_ACTIVA) {
    // Purga de la lista de reproducción de una transmisión configurada (no de toda la zona). Con listas de 2 s
    // rara vez hace falta; sirve si la CDN guardó una respuesta de error o una lista vieja tras un corte.
    app.post('/admin/cdn/purgar', adminLimiter, verifyAdmin, async (req, res) => {
        try {
            const ruta = normalizeBunnyPath(req.body?.ruta);
            const config = await getActiveStreamConfig();
            const rutas = new Set((config.transmissions || []).flatMap(t => (t.options || []).filter(o => o.source_type === "bunny" && o.path).map(o => o.path)));
            if (!ruta || !rutas.has(ruta)) {
                return res.status(400).json({ success: false, code: "PATH_NOT_IN_CATALOG", message: "Solo se purgan las listas de las transmisiones configuradas." });
            }
            const espera = 60000 - (Date.now() - ultimaPurgaCdn);
            if (espera > 0) {
                res.set('Retry-After', String(Math.ceil(espera / 1000)));
                return res.status(429).json({ success: false, code: "PURGE_TOO_SOON", message: `Espere ${Math.ceil(espera / 1000)} s entre purgas.` });
            }
            ultimaPurgaCdn = Date.now();
            const url = `${BUNNY_CDN_URL}${ruta}`;
            // Si la ruta es una lista maestra, también se purgan sus listas de medios (las que cambian cada 2 s).
            const urls = [url];
            try {
                const { url: firmada, cabeceras } = urlYCabecerasDe({ tipo: "bunny", ruta });
                const lectura = await solicitudSaliente(firmada, { cabeceras, timeoutMs: SENAL_TIMEOUT_MS, maxBytes: 256 * 1024 });
                const lista = lectura.ok ? analizarListaHls(lectura.texto) : null;
                if (lista && lista.maestra) {
                    lista.variantes.slice(0, 4).forEach(v => {
                        try {
                            const u = new URL(v, url);
                            if (u.origin === new URL(url).origin && !urls.includes(u.origin + u.pathname)) urls.push(u.origin + u.pathname);
                        } catch (_) {}
                    });
                }
            } catch (_) {}
            let r = null;
            let purgadas = 0;
            for (const destino of urls) {
                r = await solicitudSaliente(`https://api.bunny.net/purge?url=${encodeURIComponent(destino)}&async=false`, {
                    metodo: 'POST', cabeceras: { AccessKey: BUNNY_API_KEY, accept: 'application/json' },
                    timeoutMs: 15000, maxBytes: 16384, soloPublicas: false, redirecciones: 0
                });
                if (!r.ok) break;
                purgadas++;
            }
            registrarAccionAdmin(req, "purgar_cdn", `${ruta} · ${r.ok ? `purgada${purgadas > 1 ? ` (con ${purgadas - 1} lista(s) de medios)` : ""}` : `falló (${r.status || r.error})`}`, { ruta, ok: Boolean(r.ok) });
            if (!r.ok) {
                ultimaPurgaCdn = 0;   // si Bunny falló, se puede reintentar enseguida
                return res.status(502).json({ success: false, code: "CDN_PURGE_FAILED", message: mensajeErrorBunny(r) });
            }
            return res.json({ success: true, url, urls, message: purgadas > 1 ? `Lista purgada junto con ${purgadas - 1} lista(s) de medios: la CDN las vuelve a pedir al origen en la siguiente lectura.` : "Lista purgada: la CDN la vuelve a pedir al origen en la siguiente lectura." });
        } catch (e) {
            console.error("❌ Error purgando la CDN:", e);
            return res.status(500).json({ success: false, message: "Error purgando la CDN." });
        }
    });

    // Consumo del día (hora de Lima) según las estadísticas de Bunny: GB entregados, solicitudes y acierto de
    // caché, con costo estimado si se configura CDN_PRECIO_GB_USD. Se guarda 5 minutos.
    app.post('/admin/cdn/consumo', adminLimiter, verifyAdmin, async (req, res) => {
        try {
            if (consumoCdnCache && Date.now() - consumoCdnCache.en < 5 * 60000 && req.body?.actualizar !== true) {
                return res.json({ success: true, ...consumoCdnCache.datos, en_cache: true });
            }
            const ahora = new Date();
            const dia = formatPeruDateKey(ahora);
            const desde = `${dia}T05:00:00Z`;
            const hasta = `${ahora.toISOString().slice(0, 19)}Z`;
            const url = `https://api.bunny.net/statistics?pullZone=${encodeURIComponent(BUNNY_PULLZONE_ID)}&dateFrom=${encodeURIComponent(desde)}&dateTo=${encodeURIComponent(hasta)}&hourly=true&exactRange=true&loadBandwidthUsed=true&loadRequestsServed=true`;
            const r = await solicitudSaliente(url, {
                cabeceras: { AccessKey: BUNNY_API_KEY, accept: 'application/json' },
                timeoutMs: 15000, maxBytes: 2 * 1024 * 1024, soloPublicas: false, redirecciones: 0
            });
            if (!r.ok) return res.status(502).json({ success: false, code: "CDN_STATS_FAILED", message: mensajeErrorBunny(r) });
            let d;
            try { d = JSON.parse(r.texto || "{}"); } catch (_) {
                return res.status(502).json({ success: false, code: "CDN_STATS_FAILED", message: "Bunny devolvió estadísticas ilegibles." });
            }
            const gb = (Number(d.TotalBandwidthUsed) || 0) / 1e9;
            const acierto = Number(d.CacheHitRate) || 0;
            const serie = Object.entries(d.BandwidthUsedChart && typeof d.BandwidthUsedChart === "object" ? d.BandwidthUsedChart : {})
                .map(([hora, bytes]) => ({ hora, gb: Math.round((Number(bytes) || 0) / 1e7) / 100 }))
                .sort((a, b) => String(a.hora).localeCompare(String(b.hora)))
                .slice(-48);
            const datos = {
                dia, desde, hasta,
                gb: Math.round(gb * 100) / 100,
                solicitudes: Number(d.TotalRequestsServed) || 0,
                acierto_cache_pct: Math.round((acierto <= 1 && acierto > 0 ? acierto * 100 : acierto) * 10) / 10,
                serie,
                precio_gb_usd: CDN_PRECIO_GB_USD, tipo_cambio_pen: TIPO_CAMBIO_PEN, precio_acceso_pen: PRECIO_ACCESO_PEN,
                costo_usd: CDN_PRECIO_GB_USD ? Math.round(gb * CDN_PRECIO_GB_USD * 100) / 100 : null
            };
            consumoCdnCache = { en: Date.now(), datos };
            return res.json({ success: true, ...datos, en_cache: false });
        } catch (e) {
            console.error("❌ Error leyendo el consumo de la CDN:", e);
            return res.status(500).json({ success: false, message: "Error leyendo el consumo de la CDN." });
        }
    });
}

// --- 17.2 RUTAS INEXISTENTES Y ERRORES NO CONTROLADOS ---
// Respuesta JSON breve con el mismo formato que el resto de la API: sin página HTML
// ni traza (por ejemplo, ante un JSON malformado o un cuerpo demasiado grande).
app.use((req, res) => {
    res.status(404).json({ success: false, code: "NOT_FOUND" });
});

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    const estado = Number(err && (err.status || err.statusCode)) || 500;
    const estadoFinal = estado >= 400 && estado < 600 ? estado : 500;

    if (estadoFinal >= 500) {
        console.error("❌ Error no controlado:", err && err.message ? err.message : err);
    }

    const code = estadoFinal === 400 ? "BAD_REQUEST"
        : estadoFinal === 413 ? "PAYLOAD_TOO_LARGE"
        : estadoFinal < 500 ? "REQUEST_ERROR"
        : "SERVER_ERROR";

    return res.status(estadoFinal).json({ success: false, code });
});

// Un rechazo de promesa sin capturar se registra; no derriba el proceso.
process.on('unhandledRejection', (motivo) => {
    console.error("❌ Promesa rechazada sin control:", motivo && motivo.stack ? motivo.stack : motivo);
});

// --- 18. START SERVER ---
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
    console.log(`🚀 GOLAZO SECURE STREAM READY (${VERSION_BACKEND}) | ${JSON.stringify(VERSIONES_DEPENDENCIAS)}`);
});

// Render recomienda 120 s para evitar errores 502 intermitentes en conexiones reutilizadas.
const HTTP_KEEPALIVE_MS = parseInt(process.env.HTTP_KEEPALIVE_MS || "120000", 10);
server.keepAliveTimeout = HTTP_KEEPALIVE_MS;
server.headersTimeout = HTTP_KEEPALIVE_MS + 1000;

// Cierre ordenado: termina las solicitudes en curso antes de salir.
process.on('SIGTERM', () => {
    console.log("SIGTERM recibido: se terminan las solicitudes en curso y se cierra el servidor.");
    server.close(() => process.exit(0));
    const salida = setTimeout(() => process.exit(0), 10000);
    if (salida.unref) salida.unref();
});
