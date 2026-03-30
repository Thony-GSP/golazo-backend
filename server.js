// 🎯 ENDPOINT 3: GENERAR PASE RÁPIDO (Ahora con tiempo dinámico y seguridad)
app.post('/admin/generar-pase-rapido', async (req, res) => {
    try {
        const { admin_secret, horas } = req.body; // Recibimos la clave maestra y las horas

        // 🔒 Candado de Seguridad
        if (admin_secret !== process.env.PANEL_SECRET) {
            return res.status(403).json({ success: false, error: "Acceso denegado: Clave maestra incorrecta." });
        }

        const duracionHoras = horas || 4; // Si no mandas nada, por defecto son 4

        const randomUser = Math.floor(10000 + Math.random() * 90000).toString();
        const randomPass = Math.floor(1000 + Math.random() * 9000).toString();
        const correoFirebase = `${randomUser}@golazosp.net`;

        const userRecord = await admin.auth().createUser({
            email: correoFirebase,
            password: randomPass,
        });

        // Calculamos la expiración basada en lo que tú elijas en el Panel
        const fechaExpiracion = admin.firestore.Timestamp.fromMillis(Date.now() + (duracionHoras * 60 * 60 * 1000));

        await db.collection('usuarios').doc(userRecord.uid).set({
            email: correoFirebase,
            usuario_corto: randomUser, // Guardamos esto para buscarlo rápido luego
            expires_at: fechaExpiracion,
            tipo: 'pase_ocasional',
            creado_el: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({
            success: true,
            usuario: randomUser,
            clave: randomPass,
            expira_en: duracionHoras + " horas"
        });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// 🎯 ENDPOINT 4: EXTENDER ACCESO (El botón de "Tiempo Suplementario" con seguridad)
app.post('/admin/extender-acceso', async (req, res) => {
    try {
        const { admin_secret, usuario_corto, horas_extra } = req.body; // Recibimos clave y datos
        
        // 🔒 Candado de Seguridad
        if (admin_secret !== process.env.PANEL_SECRET) {
            return res.status(403).json({ success: false, error: "Acceso denegado: Clave maestra incorrecta." });
        }

        // 1. Buscamos al usuario por su código de 5 dígitos
        const snapshot = await db.collection('usuarios').where('usuario_corto', '==', usuario_corto).get();
        
        if (snapshot.empty) return res.status(404).json({ error: "Usuario no encontrado" });
        
        const doc = snapshot.docs[0];
        const data = doc.data();
        
        // 2. Calculamos el nuevo tiempo (Tiempo actual que tenía + las horas extra)
        const tiempoActual = data.expires_at.toMillis();
        const nuevoTiempo = admin.firestore.Timestamp.fromMillis(tiempoActual + (horas_extra * 60 * 60 * 1000));

        // 3. Actualizamos en la DB
        await db.collection('usuarios').doc(doc.id).update({
            expires_at: nuevoTiempo
        });

        // 4. LIMPIAMOS CACHÉ (Vital para que el reproductor detecte el cambio al instante)
        userCache.delete(doc.id);

        res.json({ 
            success: true, 
            mensaje: `Acceso extendido ${horas_extra} hora(s) para ${usuario_corto}` 
        });

    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

