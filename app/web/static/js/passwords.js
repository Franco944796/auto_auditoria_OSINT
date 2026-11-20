// k-anonimidad: solo los 5 primeros caracteres del SHA-1 salen del navegador, y van directo a
// Pwned Passwords. Nuestro backend nunca ve la contraseña ni su hash.
const RANGE_API = "https://api.pwnedpasswords.com/range/";

export async function sha1Hex(text) {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function fetchRange(prefix, padded) {
  return fetch(RANGE_API + prefix, {
    headers: padded ? { "Add-Padding": "true" } : {},
    credentials: "omit",
    referrerPolicy: "no-referrer",
    cache: "no-store",
  });
}

export async function timesSeen(password) {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  let response;
  try {
    // El relleno oculta el tamaño real de la respuesta; si el navegador bloquea la cabecera
    // extra por CORS, se repite la consulta sin relleno (sigue siendo k-anónima).
    response = await fetchRange(prefix, true);
  } catch {
    response = await fetchRange(prefix, false);
  }
  if (!response.ok) throw new Error("No pudimos consultar Pwned Passwords. Probá más tarde.");
  for (const line of (await response.text()).split("\n")) {
    const [candidate, count] = line.trim().split(":");
    if (candidate === suffix) return Number(count);
  }
  return 0;
}
