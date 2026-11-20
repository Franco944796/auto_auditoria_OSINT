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
body{font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1b1f24;max-width:820px;margin:2rem auto;padding:0 1rem}
h1{font-size:1.6rem;margin:0}h2{font-size:1.25rem;margin:2rem 0 .25rem}h3{font-size:1rem;margin:0}
.muted{color:#57606a}.head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;border-bottom:2px solid #d0d7de;padding-bottom:1rem}
.badge{display:inline-block;padding:.2rem .7rem;border-radius:999px;font-weight:600;font-size:.85rem;white-space:nowrap}
.low,.info{background:#dafbe1;color:#116329}.medium{background:#fff1c2;color:#7a4d00}.high{background:#ffe0de;color:#a40e26}.none{background:#eaeef2;color:#57606a}
.finding{border:1px solid #d0d7de;border-left-width:5px;border-radius:8px;padding:.8rem 1rem;margin:.8rem 0;break-inside:avoid}
.finding.high{border-left-color:#cf222e;background:none;color:inherit}.finding.medium{border-left-color:#bf8700;background:none;color:inherit}
.finding.low,.finding.info{border-left-color:#1a7f37;background:none;color:inherit}
.fhead{display:flex;justify-content:space-between;gap:1rem;align-items:center}
footer{margin-top:2rem;font-size:.85rem;color:#57606a;border-top:1px solid #d0d7de}
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
  ${f.remediation.length ? `<p><strong>Qué hacer</strong></p><ol>${f.remediation.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>` : ""}
</div>`,
      )
      .join("\n");
  const categories = report.categories
    .map(
      (c) => `<section>
  <h2>${escapeHtml(c.label)}</h2>${badge(c.level, "Riesgo")}
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
