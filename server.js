<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">

    <title>GOLAZO SP - Modo TV</title>

    <link rel="icon" href="https://i.ibb.co/r2KxcWgG/logo-golazo.png" type="image/png">

    <script src="https://cdn.jsdelivr.net/npm/promise-polyfill@8/dist/polyfill.min.js"></script>
    <script src="https://www.gstatic.com/firebasejs/9.17.1/firebase-app-compat.js"></script>
    <script src="https://www.gstatic.com/firebasejs/9.17.1/firebase-auth-compat.js"></script>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: #000;
            color: #fff;
            font-family: Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        header {
            width: 100%;
            background: #111;
            padding: 16px 0;
            text-align: center;
            border-bottom: 2px solid #e50914;
        }

        header img {
            height: 58px;
        }

        .container {
            width: 100%;
            max-width: 1280px;
            padding: 18px;
            text-align: center;
        }

        .tv-title {
            margin: 12px 0 18px;
            font-size: 22px;
            font-weight: 800;
            color: #fff;
            text-transform: uppercase;
        }

        .video-wrap {
            width: 100%;
            background: #000;
            border: 1px solid #222;
            border-radius: 8px;
            overflow: hidden;
        }

        video {
            width: 100%;
            aspect-ratio: 16 / 9;
            background: #000;
            display: block;
        }

        #status {
            margin-top: 18px;
            color: #25d366;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 18px;
            padding: 14px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
        }

        .help {
            margin-top: 12px;
            color: #aaa;
            font-size: 15px;
            line-height: 1.45;
        }

        .mode-switch {
            margin-top: 16px;
            display: flex;
            gap: 10px;
            justify-content: center;
            flex-wrap: wrap;
        }

        .mode-btn {
            border: 1px solid #444;
            background: #181818;
            color: #ddd;
            padding: 12px 15px;
            border-radius: 999px;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }

        .mode-btn:hover {
            background: #262626;
            color: #fff;
        }

        .mode-btn.active {
            background: #e50914;
            border-color: #e50914;
            color: #fff;
            cursor: default;
        }

        .actions {
            margin-top: 18px;
            display: flex;
            gap: 12px;
            justify-content: center;
            flex-wrap: wrap;
        }

        button.action-btn {
            background: #e50914;
            color: #fff;
            border: 0;
            border-radius: 8px;
            padding: 13px 18px;
            font-size: 16px;
            font-weight: 800;
            cursor: pointer;
        }

        button.secondary {
            background: #222;
            border: 1px solid #555;
        }

        @media (max-width: 700px) {
            header img {
                height: 48px;
            }

            .container {
                padding: 12px;
            }

            #status {
                font-size: 15px;
            }

            .tv-title {
                font-size: 18px;
            }

            .mode-btn,
            button.action-btn {
                width: 100%;
            }
        }
    </style>
</head>

<body>
    <header>
        <img src="https://i.ibb.co/r2KxcWgG/logo-golazo.png" alt="GOLAZO SP">
    </header>

    <main class="container">
        <div class="tv-title">Modo Smart TV</div>

        <div class="video-wrap">
            <video
                id="video"
                controls
                autoplay
                playsinline
                preload="auto"
            ></video>
        </div>

        <div id="status">⌛ VERIFICANDO ACCESO...</div>

        <div class="mode-switch">
            <button class="mode-btn active" type="button">
                📺 Modo TV
            </button>

            <button class="mode-btn" type="button" onclick="window.location.href='/en-directo.html?force=normal'">
                💻 Cel / Laptop / PC / Tablet
            </button>
        </div>

        <div class="help">
            Este modo prioriza estabilidad para Smart TV. Si el video no inicia automáticamente,
            presiona Play en el control remoto.
        </div>

        <div class="actions">
            <button class="action-btn" id="btnTakeover" style="display:none" onclick="continuarEnEsteTelevisor()">CONTINUAR EN ESTA TV</button>
            <button class="action-btn" onclick="intentarReproducir()">▶️ Reproducir</button>
            <button class="action-btn secondary" onclick="location.reload()">🔄 Recargar</button>
            <button class="action-btn secondary" onclick="cerrarSesion(true)">Salir</button>
        </div>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/hls.js@1.5.15"></script>

<!-- Modo TV ES5: evita async/fetch/clases en navegadores antiguos. -->
    <script>
        (function () {
            var firebaseConfig = {
                apiKey: "AIzaSyCJ9fHy1ldvHFp6NdMexfoz4KR4d54j_Hw",
                authDomain: "golazostreamperu-de4fd.firebaseapp.com",
                projectId: "golazostreamperu-de4fd",
                storageBucket: "golazostreamperu-de4fd.firebasestorage.app",
                messagingSenderId: "940862641322",
                appId: "1:940862641322:web:a2afefcc21a5e5245decd3"
            };
            var BACKEND_URL = "https://golazo-backend-ellz.onrender.com";
            var HEARTBEAT_MS = 15000;
            var RENEWAL_MS = 480000;
            var DEVICE_ID_KEY = "golazo_device_id";
            var SESSION_KEY_PREFIX = "golazo_stream_session_";
            var pageId = "page_" + Date.now() + "_" + Math.random().toString(36).slice(2);
            var deviceId = obtenerDeviceId();
            var currentUid = "";
            var currentSessionId = "";
            var currentStreamUrl = "";
            var currentStreamSource = "bunny";
            var currentIdToken = "";
            var hls = null;
            var nativeMode = false;
            var heartbeatTimer = null;
            var renewalTimer = null;
            var closing = false;
            var hlsRecoveryInProgress = false;
            var lastHlsRecoveryAt = 0;
            var networkRecoveryAttempts = 0;
            var mediaRecoveryAttempts = 0;
            var video = document.getElementById("video");
            var statusEl = document.getElementById("status");

            function setStatus(text) {
                statusEl.innerText = text;
            }

            function randomId(prefix) {
                return prefix + "_" + Date.now() + "_" + Math.random().toString(36).slice(2) + "_" + Math.random().toString(36).slice(2);
            }

            function obtenerDeviceId() {
                var value;
                try {
                    value = localStorage.getItem(DEVICE_ID_KEY);
                    if (!value) {
                        value = randomId("device");
                        localStorage.setItem(DEVICE_ID_KEY, value);
                    }
                    return value;
                } catch (_) {
                    return randomId("device");
                }
            }

            function leerSesion(uid) {
                try {
                    return localStorage.getItem(SESSION_KEY_PREFIX + uid) ||
                        sessionStorage.getItem("golazo_current_session_id") || "";
                } catch (_) {
                    return "";
                }
            }

            function guardarSesion(uid, sessionId) {
                try {
                    localStorage.setItem(SESSION_KEY_PREFIX + uid, sessionId);
                    sessionStorage.setItem("golazo_current_session_id", sessionId);
                } catch (_) {}
            }

            function borrarSesion() {
                try {
                    if (currentUid) localStorage.removeItem(SESSION_KEY_PREFIX + currentUid);
                    sessionStorage.removeItem("golazo_current_session_id");
                } catch (_) {}
            }

            function requestJson(method, url, token, body, callback) {
                var xhr = new XMLHttpRequest();
                xhr.open(method, url, true);
                xhr.timeout = 20000;
                if (token) xhr.setRequestHeader("Authorization", "Bearer " + token);
                if (body) xhr.setRequestHeader("Content-Type", "application/json");
                xhr.onreadystatechange = function () {
                    var data;
                    if (xhr.readyState !== 4) return;
                    try {
                        data = JSON.parse(xhr.responseText || "{}");
                    } catch (_) {
                        data = { code: "INVALID_RESPONSE" };
                    }
                    callback(null, xhr.status, data);
                };
                xhr.onerror = function () { callback(new Error("network"), 0, {}); };
                xhr.ontimeout = function () { callback(new Error("timeout"), 0, {}); };
                xhr.send(body ? JSON.stringify(body) : null);
            }

            function normalizarUrlTv(url) {
                return String(url || "")
                    .replace("/stream/720p/index.m3u8", "/stream/master.m3u8")
                    .replace("/720p/index.m3u8", "/master.m3u8");
            }

            function aplicarTokenBunny(url) {
                var current;
                var target;
                var streamIndex;
                var currentStreamIndex;
                var authPrefix;
                try {
                    current = document.createElement("a");
                    current.href = currentStreamUrl;
                    target = document.createElement("a");
                    target.href = url;

                    if (target.hostname !== current.hostname) return url;
                    streamIndex = target.pathname.indexOf("/stream/");
                    if (streamIndex < 0) return target.href;

                    currentStreamIndex = current.pathname.indexOf("/stream/");
                    authPrefix = currentStreamIndex > 0 ? current.pathname.slice(0, currentStreamIndex) : "";

                    if (authPrefix && target.pathname.indexOf(authPrefix) !== 0) {
                        return current.protocol + "//" + current.host + authPrefix +
                            target.pathname.slice(streamIndex) + (target.search || "");
                    }
                    return target.href;
                } catch (_) {
                    return url;
                }
            }

            function crearLoaderTv() {
                var BaseLoader = Hls.DefaultConfig.loader;
                return function TvLoader(config) {
                    var loader = new BaseLoader(config);
                    var originalLoad = loader.load;
                    loader.load = function (context, loaderConfig, callbacks) {
                        if (context.type === "manifest" && currentStreamUrl) {
                            context.url = currentStreamUrl;
                        } else if (context.url) {
                            context.url = aplicarTokenBunny(context.url);
                        }
                        return originalLoad.call(loader, context, loaderConfig, callbacks);
                    };
                    return loader;
                };
            }

            function destruirPlayer() {
                if (hls) {
                    try { hls.destroy(); } catch (_) {}
                    hls = null;
                }
                try {
                    video.pause();
                    video.removeAttribute("src");
                    video.load();
                } catch (_) {}
            }

            window.intentarReproducir = function () {
                var result;
                try {
                    fijarVelocidadNormal();
                    result = video.play();
                    if (result && result.catch) {
                        result.catch(function () {
                            setStatus("PRESIONA PLAY PARA INICIAR LA SEÑAL.");
                        });
                    }
                } catch (_) {
                    setStatus("PRESIONA PLAY PARA INICIAR LA SEÑAL.");
                }
            };

            function fijarVelocidadNormal() {
                try {
                    video.defaultPlaybackRate = 1;
                    if (video.playbackRate !== 1) video.playbackRate = 1;
                    if ("preservesPitch" in video) video.preservesPitch = true;
                    if ("webkitPreservesPitch" in video) video.webkitPreservesPitch = true;
                } catch (_) {}
            }

            video.addEventListener("ratechange", function () {
                if (video.playbackRate !== 1) fijarVelocidadNormal();
            });

            function liberarBloqueoRecuperacion(delay) {
                setTimeout(function () {
                    hlsRecoveryInProgress = false;
                }, delay || 3000);
            }

            function manejarErrorHls(data) {
                var now;
                if (!data || !data.fatal || !hls) return;

                now = Date.now();
                if (hlsRecoveryInProgress || now - lastHlsRecoveryAt < 2500) return;

                hlsRecoveryInProgress = true;
                lastHlsRecoveryAt = now;
                setStatus("RECUPERANDO SEÑAL TV...");

                if (data.type === Hls.ErrorTypes.NETWORK_ERROR) {
                    networkRecoveryAttempts += 1;

                    if (networkRecoveryAttempts <= 1) {
                        try { hls.startLoad(); } catch (_) {}
                        liberarBloqueoRecuperacion(3000);
                    } else {
                        networkRecoveryAttempts = 0;
                        renovarUrl(true);
                        liberarBloqueoRecuperacion(5000);
                    }
                    return;
                }

                if (data.type === Hls.ErrorTypes.MEDIA_ERROR) {
                    mediaRecoveryAttempts += 1;

                    try {
                        if (mediaRecoveryAttempts >= 2 && hls.swapAudioCodec) {
                            hls.swapAudioCodec();
                        }
                        hls.recoverMediaError();
                    } catch (_) {
                        renovarUrl(true);
                    }

                    if (mediaRecoveryAttempts >= 3) mediaRecoveryAttempts = 0;
                    liberarBloqueoRecuperacion(4000);
                    return;
                }

                renovarUrl(true);
                liberarBloqueoRecuperacion(5000);
            }

            function iniciarVideoNativo(url) {
                nativeMode = true;
                video.src = url;
                video.onloadedmetadata = function () {
                    try {
                        if (video.seekable && video.seekable.length) {
                            var end = video.seekable.end(video.seekable.length - 1);
                            var start = video.seekable.start(0);
                            video.currentTime = Math.max(start, end - 16);
                        }
                    } catch (_) {}
                    fijarVelocidadNormal();
                    setStatus("EN VIVO - MODO TV");
                    window.intentarReproducir();
                };
                video.onerror = function () {
                    setStatus("ERROR DE REPRODUCCIÓN. PRUEBA RECARGAR.");
                };
            }

            function iniciarVideo(url) {
                var nativeSupported;
                destruirPlayer();
                nativeMode = false;
                setStatus("CARGANDO REPRODUCTOR TV...");
                nativeSupported = video.canPlayType && video.canPlayType("application/vnd.apple.mpegurl");

                if (window.Hls && Hls.isSupported()) {
                    hls = new Hls({
                        liveSyncDuration: 16,
                        liveMaxLatencyDuration: 22,
                        maxLiveSyncPlaybackRate: 1.0,
                        maxBufferLength: 24,
                        maxMaxBufferLength: 32,
                        backBufferLength: 16,
                        maxBufferHole: 1,
                        nudgeOffset: 0.1,
                        nudgeMaxRetry: 5,
                        startFragPrefetch: true,
                        fragLoadingTimeOut: 25000,
                        fragLoadingMaxRetry: 10,
                        manifestLoadingMaxRetry: 10,
                        lowLatencyMode: false,
                        loader: crearLoaderTv()
                    });
                    hls.loadSource(url);
                    hls.attachMedia(video);
                    hls.on(Hls.Events.MANIFEST_PARSED, function () {
                        hlsRecoveryInProgress = false;
                        networkRecoveryAttempts = 0;
                        mediaRecoveryAttempts = 0;
                        fijarVelocidadNormal();
                        setStatus("EN VIVO - MODO TV");
                        window.intentarReproducir();
                    });

                    hls.on(Hls.Events.FRAG_BUFFERED, function () {
                        networkRecoveryAttempts = 0;
                        mediaRecoveryAttempts = 0;
                    });

                    hls.on(Hls.Events.ERROR, function (event, data) {
                        console.warn("HLS TV error:", data);
                        manejarErrorHls(data);
                    });
                    return;
                }

                // Respaldo para TVs sin MediaSource/Hls.js.
                if (nativeSupported) {
                    iniciarVideoNativo(url);
                    return;
                }

                setStatus("ESTA TV NO SOPORTA HLS EN EL NAVEGADOR.");
            }

            function mostrarSesionActiva() {
                setStatus("ESTA CUENTA YA ESTÁ ABIERTA EN OTRO DISPOSITIVO.");
                document.getElementById("btnTakeover").style.display = "inline-block";
            }

            function manejarError(data) {
                var code = data.code || data.motivo || "ERROR";
                if (code === "SESSION_ALREADY_ACTIVE") {
                    mostrarSesionActiva();
                } else if (code === "PASS_EXPIRED" || code === "expirado") {
                    setStatus("TU PASE HA CADUCADO.");
                    window.cerrarSesion(false);
                } else if (code === "SESSION_REVOKED" || code === "revocado") {
                    setStatus("TU SESIÓN FUE FINALIZADA POR ADMINISTRACIÓN.");
                    window.cerrarSesion(false);
                } else if (code === "pirateria") {
                    setStatus("SESIÓN TRASLADADA A OTRO DISPOSITIVO.");
                    window.cerrarSesion(false);
                } else if (code === "NO_AUTH" || code === "INVALID_AUTH" || code === "missing_session") {
                    window.cerrarSesion(true);
                } else {
                    setStatus("NO SE PUDO VALIDAR TU ACCESO.");
                }
            }

            function iniciarTV(user, takeover) {
                setStatus(takeover ? "TRASLADANDO SESIÓN A ESTA TV..." : "OBTENIENDO SEÑAL TV...");
                user.getIdToken().then(function (idToken) {
                    var saved = leerSesion(currentUid);
                    var query = "device_id=" + encodeURIComponent(deviceId) +
                        "&page_id=" + encodeURIComponent(pageId);
                    currentIdToken = idToken;
                    if (saved) query += "&session_id=" + encodeURIComponent(saved);
                    if (takeover) query += "&takeover=1";

                    requestJson("GET", BACKEND_URL + "/generate-stream?" + query, idToken, null,
                        function (error, status, data) {
                            if (error || status < 200 || status >= 300 || !data.stream_url) {
                                manejarError(data || {});
                                return;
                            }

                            currentSessionId = data.session_id;
                            currentStreamUrl = normalizarUrlTv(data.stream_url);
                            currentStreamSource = data.stream_source || "bunny";
                            guardarSesion(currentUid, currentSessionId);
                            document.getElementById("btnTakeover").style.display = "none";
                            iniciarVideo(currentStreamUrl);
                            programarHeartbeat();
                            programarRenovacion();
                        });
                }).catch(function () {
                    setStatus("NO SE PUDO VALIDAR LA SESIÓN EN ESTA TV.");
                });
            }

            function verificarSesion() {
                var user = firebase.auth().currentUser;
                if (!user || !currentSessionId || closing) return;
                user.getIdToken().then(function (token) {
                    currentIdToken = token;
                    requestJson("POST", BACKEND_URL + "/check-session", token, {
                        session_id: currentSessionId,
                        page_id: pageId
                    }, function (error, status, data) {
                        if (!error && data && data.valid === false) manejarError(data);
                    });
                });
            }

            function renovarUrl(restart) {
                var user = firebase.auth().currentUser;
                if (!user || !currentSessionId || closing) return;
                user.getIdToken().then(function (token) {
                    var url = BACKEND_URL + "/generate-stream?session_id=" + encodeURIComponent(currentSessionId) +
                        "&device_id=" + encodeURIComponent(deviceId) + "&page_id=" + encodeURIComponent(pageId);
                    currentIdToken = token;
                    requestJson("GET", url, token, null, function (error, status, data) {
                        if (error || !data || !data.stream_url) {
                            if (data) manejarError(data);
                            return;
                        }
                        currentStreamUrl = normalizarUrlTv(data.stream_url);
                        currentStreamSource = data.stream_source || currentStreamSource;
                        currentSessionId = data.session_id || currentSessionId;
                        guardarSesion(currentUid, currentSessionId);
                        if (restart || nativeMode) iniciarVideo(currentStreamUrl);
                    });
                });
            }

            function programarHeartbeat() {
                if (heartbeatTimer) clearTimeout(heartbeatTimer);
                heartbeatTimer = setTimeout(function tick() {
                    verificarSesion();
                    if (!closing) heartbeatTimer = setTimeout(tick, HEARTBEAT_MS);
                }, HEARTBEAT_MS);
            }

            function programarRenovacion() {
                if (renewalTimer) clearTimeout(renewalTimer);
                renewalTimer = setTimeout(function tick() {
                    renovarUrl(nativeMode);
                    if (!closing) renewalTimer = setTimeout(tick, RENEWAL_MS);
                }, RENEWAL_MS);
            }

            function releaseSession(useBeacon, callback) {
                var payload;
                if (!currentSessionId || !currentIdToken) {
                    if (callback) callback();
                    return;
                }
                payload = {
                    session_id: currentSessionId,
                    page_id: pageId,
                    id_token: currentIdToken
                };

                if (useBeacon && navigator.sendBeacon && window.Blob) {
                    try {
                        if (navigator.sendBeacon(BACKEND_URL + "/release-session",
                            new Blob([JSON.stringify(payload)], { type: "application/json" }))) {
                            if (callback) callback();
                            return;
                        }
                    } catch (_) {}
                }

                requestJson("POST", BACKEND_URL + "/release-session", currentIdToken, payload,
                    function () { if (callback) callback(); });
            }

            window.continuarEnEsteTelevisor = function () {
                var user = firebase.auth().currentUser;
                if (!user) {
                    window.location.href = "/index.html?next=/tv.html";
                    return;
                }
                document.getElementById("btnTakeover").style.display = "none";
                iniciarTV(user, true);
            };

            window.cerrarSesion = function (redirect) {
                closing = true;
                if (heartbeatTimer) clearTimeout(heartbeatTimer);
                if (renewalTimer) clearTimeout(renewalTimer);
                destruirPlayer();
                releaseSession(false, function () {
                    borrarSesion();
                    firebase.auth().signOut().then(function () {
                        if (redirect !== false) window.location.href = "/index.html?next=/tv.html";
                    });
                });
            };

            window.addEventListener("pagehide", function () {
                releaseSession(true);
            });

            window.addEventListener("pageshow", function (event) {
                if (event.persisted) window.location.reload();
            });

            if (!window.firebase) {
                setStatus("NO SE PUDO CARGAR EL ACCESO EN ESTA TV.");
                return;
            }

            firebase.initializeApp(firebaseConfig);
            firebase.auth().onAuthStateChanged(function (user) {
                if (!user) {
                    window.location.href = "/index.html?next=/tv.html";
                    return;
                }
                currentUid = user.uid;
                iniciarTV(user, false);
            });
        }());
    </script>
</body>
</html>
