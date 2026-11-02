// Several request inputs into one sink: one vulnerability with several vectors. Stage 1 already traces every input
// that reaches a sink; when there is more than one, the judge is asked which of them are exploitable, the explanation
// names them all and the patch must close them all. A sink only one input reaches gets no extra prompt text and no
// `vectors` field — its prompt and finding are exactly what they were. Detection, severity and verification do not
// look at vectors: one confirmed exploit through any of them confirms the finding.
import type { Vector } from "../types/index.js";
import type { Hop } from "./crossfile/trace.js";

/** One traced path into the sink, in the judge prompt's "Path N" order. */
export interface VectorPath {
  /** What makes two paths the same input (e.g. the tracer's origin). */
  key: string;
  /** The input as the code reads it. */
  input: string;
  hops: Hop[];
  /** The path's hops formatted as a finding's taintPath. */
  taintPath: string[];
  route?: string;
  writeRoute?: string;
}

/** A distinct input among a sink's paths, with the 1-based Path numbers that carry it. */
export interface Input {
  path: VectorPath;
  numbers: number[];
}

/** The input name in a tracer origin (`file:line:<name or request expression>`). */
export function inputOfOrigin(origin: string): string {
  return origin.replace(/^[^:]*:\d+:/, "");
}

/** The distinct inputs among `paths`, in first-seen order. */
export function inputsOf(paths: VectorPath[]): Input[] {
  const out = new Map<string, Input>();
  paths.forEach((p, i) => {
    const seen = out.get(p.key);
    if (seen) seen.numbers.push(i + 1);
    else out.set(p.key, { path: p, numbers: [i + 1] });
  });
  return [...out.values()];
}

/** How each class words the prompt block: the sink, what fixing an input means, and what leaving one unfixed means. */
export interface VectorWording {
  sink: string;
  fix: string;
  open: string;
}

const pathRefs = (numbers: number[]) => `${numbers.length > 1 ? "Paths" : "Path"} ${numbers.join(", ")}`;

/**
 * The prompt block for a sink two or more inputs reach: it lists them and asks for every exploitable one, named in
 * the explanation and closed by the patch, as one finding. Empty for fewer than two inputs.
 */
export function vectorsBlock(inputs: Input[], w: VectorWording): string {
  if (inputs.length < 2) return "";
  // Inputs entering through different routes (a shared function called from several handlers) are told apart by route.
  const routes = new Set(inputs.map((i) => i.path.route)).size > 1;
  const list = inputs
    .map((i) => `- ${i.path.input}, entering at ${i.path.hops[0].file}:${i.path.hops[0].line} (${routes && i.path.route ? `${i.path.route}, ` : ""}${pathRefs(i.numbers)})`)
    .join("\n");
  return `\n\nSEVERAL INPUTS — Stage 1 traced ${inputs.length} different request inputs into this ${w.sink}:
${list}
They are ONE vulnerability with several vectors: report one finding, not one per input. In "vectors", give the Path number of each input that is exploitable on its own — one number per input, including the input of "path"; leave out an input that is neutralized on its way. The explanation names every input in "vectors" and where it enters. The suggestedPatch must ${w.fix} for every input in "vectors", not only the one in "path": a patch that closes one and leaves another ${w.open} leaves the ${w.sink} exploitable.`;
}

/** The output-schema line for "vectors", or "" when there are fewer than two inputs. Appended to the severity line. */
export function vectorsField(inputs: Input[]): string {
  if (inputs.length < 2) return "";
  return `\n  "vectors": number[],       // the Path number of each exploitable input listed under SEVERAL INPUTS, one per input, the "path" number included`;
}

function toVector(p: VectorPath): Vector {
  return {
    input: p.input,
    file: p.hops[0].file,
    line: p.hops[0].line,
    ...(p.route ? { httpRoute: p.route } : {}),
    ...(p.writeRoute ? { writeRoute: p.writeRoute } : {}),
    taintPath: p.taintPath,
  };
}

/**
 * The finding's vectors from the judge's reply: the input of the chosen path first, then every other offered input
 * the judge listed in "vectors", each shown by the path it named. Undefined — no `vectors` on the finding — unless
 * that makes two or more inputs: a reply without "vectors", or listing only one input, leaves the finding as it was.
 * `related` keeps only inputs into the same vulnerability as the chosen path (access control: the same resource).
 */
export function parseVectors(
  reply: Record<string, unknown>,
  paths: VectorPath[],
  inputs: Input[],
  chosen: VectorPath,
  related: (p: VectorPath) => boolean = () => true,
): Vector[] | undefined {
  if (inputs.length < 2 || !Array.isArray(reply.vectors)) return undefined;
  const offered = new Set(inputs.map((i) => i.path.key));
  if (!offered.has(chosen.key)) return undefined;
  const picked = new Map<string, VectorPath>([[chosen.key, chosen]]);
  for (const raw of reply.vectors) {
    const p = Number.isInteger(raw) ? paths[(raw as number) - 1] : undefined;
    if (p && offered.has(p.key) && !picked.has(p.key) && related(p)) picked.set(p.key, p);
  }
  return picked.size >= 2 ? [...picked.values()].map(toVector) : undefined;
}
