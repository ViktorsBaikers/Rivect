import { tint, Ink, Pen, Badge } from "./barrel";
const ink = new Ink();
const pen = new Pen();
export const swatch = tint();
export const first = "🧵é🧵" + ink.mark();
export const other = pen.mark();
export const badge = <Badge />;
const local = 1;
export const n = local;
