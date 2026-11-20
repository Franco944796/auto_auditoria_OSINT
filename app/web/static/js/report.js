import { clear, el, triggerDownload } from "./common.js";

export const LEVELS = { low: "Bajo", medium: "Medio", high: "Alto" };
const SEVERITIES = { info: "Informativo", low: "Bajo", medium: "Medio", high: "Alto" };

function formatDate(iso) {
  return new Date(iso).toLocaleString("es", { dateStyle: "long", timeStyle: "short" });
}

function levelBadge(level, prefix) {
  const text = level ? `${prefix}: ${LEVELS[level]}` : `${prefix}: sin revisar`;
  return el("span", { className: `badge badge--${level ?? "none"}`, text });
}

function findingNode(finding) {
  const children = [
    el("header", { className: "finding__head" }, [
      el("h5", { text: finding.title }),
      el("span", {
        className: `chip chip--${finding.severity}`,
        text: SEVERITIES[finding.severity],
      }),
    ]),
  ];
  if (finding.data?.photo) children.push(el("p", { className: "muted", text: `Foto: ${finding.data.photo}` }));
  if (finding.detail) children.push(el("p", { text: finding.detail }));
  if (finding.remediation.length) {
    children.push(
      el("p", { className: "finding__label", text: "Qué hacer" }),
      el("ol", {}, finding.remediation.map((step) => el("li", { text: step }))),
    );
  }
  return el("article", { className: `finding finding--${finding.severity}` }, children);
}

export function renderReport(report, container) {
  clear(container);
  container.append(
    el("div", { className: "report__head" }, [
      el("div", {}, [
        el("h3", { text: "Informe de exposición digital" }),
        el("p", { className: "muted", text: `${report.email} · ${formatDate(report.generated_at)}` }),
      ]),
      levelBadge(report.overall_level, "Riesgo global"),
    ]),
  );
  for (const category of report.categories) {
    const section = el("section", { className: "report__category" }, [
      el("header", { className: "report__category-head" }, [
        el("h4", { text: category.label }),
        levelBadge(category.level, "Riesgo"),
      ]),
      el("p", { text: category.summary }),
    ]);
    for (const finding of category.findings) section.append(findingNode(finding));
    container.append(section);
  }
  if (report.attributions.length) {
    container.append(
      el("footer", { className: "report__sources" }, report.attributions.map((t) => el("p", { text: t }))),
    );
  }
}

const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ESCAPES[char]);
}

const REPORT_CSS = `
body{font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#0a0a0a;background:#fff;max-width:760px;margin:48px auto;padding:0 20px}
h1{font-size:1.75rem;letter-spacing:-.03em;margin:0}h2{font-size:1rem;margin:0}h3{font-size:.9375rem;margin:0}p{margin:4px 0 0}
.muted{color:#737373}.head{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding-bottom:24px;border-bottom:1px solid #e5e5e5}
section{padding:24px 0 8px;border-bottom:1px solid #e5e5e5}.shead{display:flex;justify-content:space-between;align-items:center;gap:8px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border:1px solid #e5e5e5;border-radius:999px;font-size:.8125rem;font-weight:500;color:#404040;white-space:nowrap}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:#a3a3a3;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.high::before{background:#dc2626}.medium::before{background:#d97706}.low::before,.info::before{background:#16a34a}
.finding{border:1px solid #e5e5e5;border-radius:8px;padding:14px 16px;margin:12px 0;break-inside:avoid}
.fhead{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.finding p,.finding li{font-size:.875rem;color:#404040}
.label{font-size:.75rem;text-transform:uppercase;letter-spacing:.04em;color:#737373;margin-top:12px}ol{margin:6px 0 0;padding-left:18px}
footer{margin-top:24px;font-size:.75rem;color:#737373}
`;

export function reportToHtml(report) {
  const badge = (level, prefix) =>
    `<span class="badge ${level ?? "none"}">${escapeHtml(prefix)}: ${level ? LEVELS[level] : "sin revisar"}</span>`;
  const findings = (category) =>
    category.findings
      .map(
        (f) => `<div class="finding ${f.severity}">
  <div class="fhead"><h3>${escapeHtml(f.title)}</h3><span class="badge ${f.severity}">${SEVERITIES[f.severity]}</span></div>
  ${f.data?.photo ? `<p class="muted">Foto: ${escapeHtml(f.data.photo)}</p>` : ""}
  ${f.detail ? `<p>${escapeHtml(f.detail)}</p>` : ""}
  ${f.remediation.length ? `<p class="label">Qué hacer</p><ol>${f.remediation.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>` : ""}
</div>`,
      )
      .join("\n");
  const categories = report.categories
    .map(
      (c) => `<section>
  <div class="shead"><h2>${escapeHtml(c.label)}</h2>${badge(c.level, "Riesgo")}</div>
  <p>${escapeHtml(c.summary)}</p>
  ${findings(c)}
</section>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de exposición digital</title>
<style>${REPORT_CSS}</style>
</head>
<body>
<div class="head">
  <div><h1>Informe de exposición digital</h1>
  <p class="muted">${escapeHtml(report.email)} · ${escapeHtml(formatDate(report.generated_at))}</p></div>
  ${badge(report.overall_level, "Riesgo global")}
</div>
${categories}
<footer>${report.attributions.map((a) => `<p>${escapeHtml(a)}</p>`).join("")}
<p>Este informe se generó en tu navegador y no quedó guardado en el servidor.</p></footer>
</body>
</html>`;
}

export function downloadReportHtml(report) {
  const blob = new Blob([reportToHtml(report)], { type: "text/html;charset=utf-8" });
  triggerDownload(blob, `informe-exposicion-${report.generated_at.slice(0, 10)}.html`);
}
