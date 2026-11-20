const CSRF_COOKIE = "csrf_token";
const GENERIC_ERROR = "Algo salió mal. Probá de nuevo en un momento.";

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

export function csrfToken() {
  const entry = document.cookie.split("; ").find((cookie) => cookie.startsWith(`${CSRF_COOKIE}=`));
  return entry ? entry.slice(CSRF_COOKIE.length + 1) : "";
}

function describeError(detail) {
  if (typeof detail === "string") return detail;
  // Los 422 de FastAPI traen una lista de errores de validación en inglés.
  if (Array.isArray(detail)) return "Revisá los datos ingresados.";
  return GENERIC_ERROR;
}

export async function api(path, { method = "GET", json, body, headers = {} } = {}) {
  const init = { method, credentials: "same-origin", headers: { ...headers } };
  if (method !== "GET") init.headers["X-CSRF-Token"] = csrfToken();
  if (json !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(json);
  } else if (body !== undefined) {
    init.body = body;
  }
  let response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError("No hay conexión con el servidor.", 0);
  }
  if (!response.ok) {
    let detail = GENERIC_ERROR;
    try {
      detail = describeError((await response.json()).detail);
    } catch {
      // respuesta sin JSON: queda el mensaje genérico
    }
    throw new ApiError(detail, response.status);
  }
  return response;
}

export function el(tag, { className, text, attrs } = {}, children = []) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  for (const [name, value] of Object.entries(attrs ?? {})) node.setAttribute(name, value);
  node.append(...children);
  return node;
}

export function clear(node) {
  node.replaceChildren();
}

export function showMessage(node, text, kind = "error") {
  node.textContent = text;
  node.className = `notice notice--${kind}`;
  node.hidden = !text;
}

export function hideMessage(node) {
  node.hidden = true;
}

export function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = el("a", { attrs: { href: url, download: filename } });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function formatNumber(value) {
  return new Intl.NumberFormat("es").format(value);
}
