# Nuestro Adviento

31 días juntos: un calendario de Adviento para parejas. Cada persona lo usa desde su móvil y comparten el mismo calendario en tiempo real.

- Web app estática (HTML + JS, sin build) desplegada en Vercel, instalable con "Añadir a pantalla de inicio".
- Backend: Supabase (Postgres + RLS + Realtime + acceso anónimo). Sin cuentas ni correos: una persona crea el calendario y la otra se une con un código de 6 caracteres. Cada persona recibe una clave de recuperación.
- En los días "Cada uno", la respuesta de la pareja no es legible (RLS) hasta que las dos están enviadas.

## Puesta en marcha
1. Crear un proyecto en Supabase.
2. SQL Editor → pegar y ejecutar `supabase/schema.sql`.
3. Authentication → Sign In / Providers → activar **Allow anonymous sign-ins**.
4. Rellenar `config.js` con la Project URL y la clave pública (anon / publishable).
