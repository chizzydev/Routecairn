/** Preserve invalid text for correction; JavaScript coercion is not an owner assertion. */
export function reviewedScalar(value: string, numeric: boolean): string | number {
  if (!numeric || !/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(value) || !Number.isFinite(Number(value)))
    return value;
  return Number(value);
}
export function assertReviewedScalar(value: unknown, scalarType: string | undefined) {
  if (scalarType === "number" && (typeof value !== "number" || !Number.isFinite(value)))
    throw new Error(
      "Use an explicit finite decimal for the observed numeric policy field. Whitespace and implicit conversions cannot declare identity or ownership."
    );
}
