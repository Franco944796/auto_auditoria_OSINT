import { api, clear, el, formatNumber, hideMessage, showMessage, triggerDownload } from "./common.js";
import { timesSeen } from "./passwords.js";
import { downloadReportHtml, renderReport } from "./report.js";

const POLL_INTERVAL_MS = 2000;
const POLL_TIMEOUT_MS = 5 * 60 * 1000;

const state = {
  breachJobId: null,
  passwordChecks: [],
  photos: new Map(),
  report: null,
};

const $ = (id) => document.getElementById(id);

async function pollJob(jobId) {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const job = await (await api(`/api/analysis/jobs/${encodeURIComponent(jobId)}`)).json();
    if (job.status !== "pending") return job;
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error("El análisis está tardando demasiado. Probá de nuevo más tarde.");
}

function renderBreaches(findings) {
  const list = $("breach-results");
  clear(list);
  for (const finding of findings) {
    const classes = finding.data.data_classes_es ?? finding.data.data_classes ?? [];
    list.append(
      el("li", { className: "result" }, [
        el("h3", { text: finding.title }),
        el("p", {
          className: "muted",
          text: `Fecha de la filtración: ${finding.data.breach_date ?? "desconocida"}`,
        }),
        el("p", { text: `Datos expuestos: ${classes.join(", ")}` }),
        el("details", {}, [el("summary", { text: "Qué pasó" }), el("p", { text: finding.detail })]),
      ]),
    );
  }
}

async function startBreachAnalysis(event) {
  const button = event.currentTarget;
  const status = $("breach-status");
  button.disabled = true;
  clear($("breach-results"));
  state.breachJobId = null;
  showMessage(status, `Consultando ${button.dataset.label}…`, "info");
  try {
    const source = encodeURIComponent(button.dataset.source);
    const { job_id: jobId } = await (await api(`/api/analysis/${source}`, { method: "POST" })).json();
    const job = await pollJob(jobId);
    if (job.status === "failed") throw new Error(job.error);
    state.breachJobId = jobId;
    renderBreaches(job.findings);
    const count = job.findings.length;
    showMessage(
      status,
      count
        ? `Tu email aparece en ${count} ${count === 1 ? "filtración" : "filtraciones"}.`
        : "Tu email no aparece en filtraciones conocidas.",
      count ? "warning" : "ok",
    );
  } catch (error) {
    showMessage(status, error.message);
  } finally {
    button.disabled = false;
  }
}

function renderPasswords() {
  const list = $("password-results");
  clear(list);
  for (const check of state.passwordChecks) {
    const exposed = check.times_seen > 0;
    list.append(
      el("li", { className: `result result--${exposed ? "bad" : "good"}` }, [
        el("strong", { text: check.label }),
        el("span", {
          text: exposed
            ? ` Apareció ${formatNumber(check.times_seen)} veces en filtraciones: no la uses más.`
            : " No aparece en filtraciones conocidas.",
        }),
      ]),
    );
  }
}

async function checkPassword(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = $("password-status");
  const password = form.password.value;
  form.password.value = "";
  if (!password) return;
  form.querySelector("button").disabled = true;
  showMessage(status, "Comprobando…", "info");
  try {
    const count = await timesSeen(password);
    state.passwordChecks.push({
      label: `Contraseña ${state.passwordChecks.length + 1}`,
      times_seen: count,
    });
    renderPasswords();
    hideMessage(status);
  } catch (error) {
    showMessage(status, error.message);
  } finally {
    form.querySelector("button").disabled = false;
  }
}

function photoRequest(path, file) {
  return api(path, {
    method: "POST",
    body: file,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-Filename": encodeURIComponent(file.name),
    },
  });
}

function filenameFrom(disposition, fallback) {
  const match = /filename\*=UTF-8''([^;]+)/i.exec(disposition ?? "");
  return match ? decodeURIComponent(match[1]) : fallback;
}

async function downloadClean(name, file, button) {
  button.disabled = true;
  try {
    const response = await photoRequest("/api/photos/clean", file);
    triggerDownload(await response.blob(), filenameFrom(response.headers.get("Content-Disposition"), name));
  } catch (error) {
    showMessage($("photo-status"), error.message);
  } finally {
    button.disabled = false;
  }
}

function renderPhotos() {
  const grid = $("photo-results");
  clear(grid);
  for (const [name, { file, findings }] of state.photos) {
    const downloadButton = el("button", {
      className: "button button--small",
      text: "Descargar sin metadatos",
      attrs: { type: "button" },
    });
    downloadButton.addEventListener("click", () => downloadClean(name, file, downloadButton));
    const removeButton = el("button", {
      className: "button button--small button--secondary",
      text: "Quitar",
      attrs: { type: "button" },
    });
    removeButton.addEventListener("click", () => {
      state.photos.delete(name);
      renderPhotos();
    });
    grid.append(
      el("article", { className: "photo-card" }, [
        el("h3", { text: name }),
        el(
          "ul",
          {},
          findings.map((finding) =>
            el("li", { className: `photo-finding photo-finding--${finding.code.replace(".", "-")}` }, [
              el("strong", { text: finding.title }),
              ...(finding.detail ? [el("span", { text: ` ${finding.detail}` })] : []),
            ]),
          ),
        ),
        el("div", { className: "actions" }, [downloadButton, removeButton]),
      ]),
    );
  }
}

async function analyzePhotos(event) {
  const input = event.currentTarget;
  const status = $("photo-status");
  const files = Array.from(input.files);
  input.value = "";
  const errors = [];
  for (const [index, file] of files.entries()) {
    showMessage(status, `Analizando ${index + 1} de ${files.length}…`, "info");
    try {
      const data = await (await photoRequest("/api/photos/analyze", file)).json();
      state.photos.set(data.photo, { file, findings: data.findings });
      renderPhotos();
    } catch (error) {
      errors.push(`${file.name}: ${error.message}`);
    }
  }
  if (errors.length) showMessage(status, errors.join(" "));
  else hideMessage(status);
}

async function generateReport(event) {
  const button = event.currentTarget;
  const status = $("report-status");
  const body = {};
  if (state.breachJobId) body.breach_job_id = state.breachJobId;
  if (state.passwordChecks.length) body.password_checks = state.passwordChecks;
  const photoFindings = Array.from(state.photos.values()).flatMap((photo) => photo.findings);
  if (photoFindings.length) body.photo_findings = photoFindings;
  if (!Object.keys(body).length) {
    showMessage(status, "Hacé al menos un análisis antes de generar el informe.", "info");
    return;
  }
  button.disabled = true;
  try {
    state.report = await (await api("/api/report", { method: "POST", json: body })).json();
    renderReport(state.report, $("report"));
    $("report-download").hidden = false;
    $("report-print").hidden = false;
    hideMessage(status);
  } catch (error) {
    if (error.status === 404) state.breachJobId = null;
    showMessage(status, error.message);
  } finally {
    button.disabled = false;
  }
}

async function logout() {
  if (state.breachJobId) {
    await api(`/api/analysis/jobs/${encodeURIComponent(state.breachJobId)}`, {
      method: "DELETE",
    }).catch(() => {});
  }
  await api("/api/auth/logout", { method: "POST" }).catch(() => {});
  window.location.assign("/");
}

async function deleteAccount() {
  const confirmed = window.confirm(
    "Se borrará tu cuenta y tu email de nuestra base. Esta acción no se puede deshacer. ¿Continuar?",
  );
  if (!confirmed) return;
  try {
    await api("/api/me", { method: "DELETE" });
    window.location.assign("/");
  } catch (error) {
    window.alert(error.message);
  }
}

async function init() {
  try {
    const me = await (await api("/api/me")).json();
    $("user-email").textContent = me.email;
  } catch {
    window.location.replace("/");
    return;
  }
  $("breach-start").addEventListener("click", startBreachAnalysis);
  $("password-form").addEventListener("submit", checkPassword);
  $("photo-input").addEventListener("change", analyzePhotos);
  $("report-generate").addEventListener("click", generateReport);
  $("report-download").addEventListener("click", () => downloadReportHtml(state.report));
  $("report-print").addEventListener("click", () => window.print());
  $("logout").addEventListener("click", logout);
  $("delete-account").addEventListener("click", deleteAccount);
}

init();
