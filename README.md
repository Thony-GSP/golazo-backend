# 🧠 Golazo Stream Peru - API Backend

Este es el núcleo lógico del sistema. Se encarga de la autenticación de usuarios y de garantizar la **sesión única** para evitar la piratería de cuentas.

## 🚀 Funcionalidades
- **Validación de Firebase Auth:** Verifica que los tokens de usuario sean legítimos.
- **Sistema de Heartbeat:** Monitorea las sesiones activas en tiempo real.
- **Control de Multicuentas:** Si un usuario abre una segunda sesión, la API detecta el nuevo `sessionId` y marca la anterior como inválida.

## 🛠️ Tecnologías
- **Runtime:** Node.js
- **Framework:** Express.js
- **Base de Datos:** Firebase Cloud Firestore
- **Hosting:** Render.com

## 📦 Instalación y Configuración
1. Clonar el repositorio.
2. Ejecutar `npm install` para instalar dependencias.
3. Crear un archivo `.env` basado en `.env.example`.
4. Iniciar en modo desarrollo con `npm start`.

## 🔒 Variables de Entorno (.env)
Es necesario configurar las siguientes llaves para que el servidor conecte con Firebase:
- `FIREBASE_PROJECT_ID`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY`
