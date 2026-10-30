// Human-readable report: one card per finding (severity, location, taint path, why, proof, and the suggested fix),
// and color for the summary. Presentation only — the --json data path never goes through here. Without color (not a
// TTY, --json, NO_COLOR, --no-color) every status is still carried by a label or symbol, so piped text stays readable.
import { createColors } from "picocolors";
import { SEVERITIES, type Finding, type Severity } from "./types/index.js";

export type Colors = ReturnType<typeof createColors>;

/** Whether to color human output: never for --json or --no-color or with NO_COLOR; forced by FORCE_COLOR; else a TTY. */
export function colorEnabled(opts: { json: boolean; noColorFlag: boolean; env: NodeJS.ProcessEnv; isTTY: boolean }): boolean {
  if (opts.json || opts.noColorFlag || opts.env.NO_COLOR) return false;
  if (opts.env.FORCE_COLOR !== undefined && opts.env.FORCE_COLOR !== "0") return true;
  return opts.isTTY;
}

export function makeColors(enabled: boolean): Colors {
  return createColors(enabled);
}

/** The report width: the terminal's, kept between a readable minimum and maximum (100 when not a terminal). */
export function reportWidth(columns: number | undefined): number {
  return Math.max(72, Math.min(columns ?? 100, 110));
}

const SEVERITY_STYLE: Record<Severity, (c: Colors, s: string) => string> = {
  critical: (c, s) => c.bold(c.red(s)),
  high: (c, s) => c.yellow(s),
  medium: (c, s) => c.blue(s),
  low: (c, s) => c.dim(s),
};

export function paintSeverity(c: Colors, severity: Severity, text: string): string {
  return SEVERITY_STYLE[severity](c, text);
}

/** "critical 1, high 7, medium 0, low 0" — each nonzero count in its severity's color, zeros dimmed. */
export function severityCounts(c: Colors, findings: Finding[]): string {
  return SEVERITIES.map((s) => {
    const n = findings.filter((f) => f.severity === s).length;
    const text = `${s} ${n}`;
    return n > 0 ? paintSeverity(c, s, text) : c.dim(text);
  }).join(", ");
}

/** A full-width rule, optionally titled: "── Title ─────…". */
export function rule(c: Colors, width: number, title?: string): string {
  if (!title) return c.dim("─".repeat(width));
  return `${c.dim("──")} ${c.bold(title)} ${c.dim("─".repeat(Math.max(3, width - title.length - 4)))}`;
}

/** Word-wraps prose to `width` columns, each line prefixed with `indent`; existing line breaks are kept. */
export function wrap(text: string, width: number, indent: string): string[] {
  const out: string[] = [];
  const room = Math.max(20, width - indent.length);
  for (const para of text.split("\n")) {
    let line = "";
    for (const word of para.split(/\s+/).filter(Boolean)) {
      if (line && line.length + 1 + word.length > room) {
        out.push(indent + line);
        line = word;
      } else line = line ? `${line} ${word}` : word;
    }
    out.push(indent + line);
  }
  return out;
}

function confidenceBadge(c: Colors, f: Finding): { plain: string; painted: string } {
  if (f.confidence === "confirmed") return { plain: "✓ exploit confirmed", painted: c.bold(c.green("✓ exploit confirmed")) };
  if (f.confidence === "unverified") return { plain: "✗ not confirmed", painted: c.dim("✗ not confirmed") };
  return { plain: "suspected", painted: c.dim("suspected") };
}

const label = (c: Colors, text: string) => c.bold(text);

/**
 * The file a suggested patch changes, read from the finding's own path: a patched route registration lives in the
 * file the input enters (the handler), and a patched function in the file whose hop declares it. Undefined when the
 * patch names neither, rather than guessing — the sink is not always where the fix goes (an access check belongs in
 * the handler).
 */
export function patchFile(f: Finding): string | undefined {
  const code = f.suggestedPatch.trimStart();
  if (/^(?:router|app)\.(?:get|post|put|patch|delete|all|use)\s*\(/.test(code)) return f.file;
  const name = /^(?:export\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/.exec(code)?.[1] ?? /^(?:export\s+)?(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=/.exec(code)?.[1];
  if (!name) return undefined;
  const declares = new RegExp(`^(\\S+?):\\d+\\s+.*\\b(?:function\\s+${name.replace(/\$/g, "\\$")}\\s*\\(|${name.replace(/\$/g, "\\$")}\\s*=)`);
  for (const hop of f.taintPath) {
    const m = declares.exec(hop);
    if (m) return m[1];
  }
  return undefined;
}

/**
 * One finding as a card: a header with the severity badge, type and CWE, and the verification badge on the right;
 * the route and location; then the taint path, why it is exploitable, the proof (when verification ran), and the
 * suggested fix set off as a code block.
 */
export function findingCard(c: Colors, f: Finding, n: number, total: number, width: number): string {
  const sev = `[${f.severity.toUpperCase()}]`;
  const num = `${n}/${total}`;
  const title = `${f.type} · ${f.cwe}`;
  const badge = confidenceBadge(c, f);
  const leftPlain = `${num}  ${sev}  ${title}`;
  const gap = Math.max(2, width - leftPlain.length - badge.plain.length);
  const lines = [
    rule(c, width),
    `${c.dim(num)}  ${paintSeverity(c, f.severity, sev)}  ${c.bold(title)}${" ".repeat(gap)}${badge.painted}`,
  ];
  const pad = " ".repeat(num.length + 2);
  if (f.httpRoute) lines.push(`${pad}${c.cyan(f.httpRoute)}${f.writeRoute ? c.dim(`  (written via ${f.writeRoute})`) : ""}`);
  lines.push(`${pad}${f.file}:${f.sourceLine} ${c.dim("→")} ${f.sinkFile ?? f.file}:${f.sinkLine}`, "");

  lines.push(`  ${label(c, "Taint path")}`);
  const w = String(f.taintPath.length).length;
  f.taintPath.forEach((hop, i) => lines.push(`    ${c.dim(String(i + 1).padStart(w))}  ${hop}`));
  lines.push("", `  ${label(c, "Why")}`, ...wrap(f.explanation, width, "    "));

  const v = f.verification;
  if (v) {
    const head = v.outcome === "confirmed" ? c.green("Proof") : `Verification ${c.dim(`(${v.outcome})`)}`;
    lines.push("", `  ${label(c, head)}`, ...wrap(v.summary, width, "    ").map((l) => (v.outcome === "confirmed" ? l : c.dim(l))));
    if (v.outcome === "confirmed" && v.exploit) lines.push(`    ${c.dim("exploit")}  ${v.exploit.method} ${v.exploit.path} ${c.dim("→")} ${v.exploit.status}`);
    if (v.patchProof) lines.push(`    ${c.dim("patch check")}  ${v.patchProof.outcome} — ${v.patchProof.summary}`);
  }

  const target = patchFile(f);
  lines.push("", `  ${c.bold(c.green("Fix"))} ${c.dim(`— suggested patch${target ? ` for ${target}` : ""}`)}`);
  for (const code of f.suggestedPatch.replace(/\s+$/, "").split("\n")) lines.push(`    ${c.green("│")} ${code}`);
  return lines.join("\n");
}
