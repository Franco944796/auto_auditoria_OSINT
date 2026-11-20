import { api, showMessage } from "./common.js";

const token = new URLSearchParams(window.location.hash.slice(1)).get("t");
// Saca el token de la barra de direcciones y del historial apenas se lee.
window.history.replaceState(null, "", window.location.pathname);

const message = document.getElementById("message");
document.getElementById(token ? "with-token" : "without-token").hidden = false;

document.getElementById("confirm").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api("/api/auth/verify-link", { method: "POST", json: { token } });
    window.location.assign("/panel");
  } catch (error) {
    showMessage(message, error.message);
    button.disabled = false;
  }
});
