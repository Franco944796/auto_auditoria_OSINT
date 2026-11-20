import { api, showMessage } from "./common.js";

const emailForm = document.getElementById("email-form");
const codeForm = document.getElementById("code-form");
const message = document.getElementById("message");
let email = "";

async function withButton(form, action) {
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    await action();
  } finally {
    button.disabled = false;
  }
}

emailForm.addEventListener("submit", (event) => {
  event.preventDefault();
  email = emailForm.email.value.trim();
  withButton(emailForm, async () => {
    try {
      const data = await (await api("/api/auth/start", { method: "POST", json: { email } })).json();
      document.getElementById("sent-to").textContent = email;
      codeForm.hidden = false;
      codeForm.code.focus();
      showMessage(message, data.detail, "info");
    } catch (error) {
      showMessage(message, error.status === 422 ? "Ingresá un email válido." : error.message);
    }
  });
});

codeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const code = codeForm.code.value.trim();
  withButton(codeForm, async () => {
    try {
      await api("/api/auth/verify-code", { method: "POST", json: { email, code } });
      window.location.assign("/panel");
    } catch (error) {
      showMessage(message, error.status === 422 ? "El código tiene 6 dígitos." : error.message);
    }
  });
});

api("/api/session")
  .then((response) => response.json())
  .then(({ authenticated }) => {
    document.getElementById("session-hint").hidden = !authenticated;
  })
  .catch(() => {});
