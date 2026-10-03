/** Lexical masking preserves executable tokens while excluding comments and
 * string contents. Regex comment removal is unsafe when '#' occurs in a string. */
export function graphqlExecutableText(document: string): string | undefined {
  if (document.length > 65_536) return;
  const output: string[] = [];
  for (let index = 0; index < document.length;) {
    const character = document[index]!;
    if (character === "#") {
      while (index < document.length && !/[\r\n]/.test(document[index]!)) index++;
      output.push(" "); continue;
    }
    if (character !== '"') { output.push(character); index++; continue; }
    const block = document.startsWith('"""', index);
    index += block ? 3 : 1;
    let closed = false;
    while (index < document.length) {
      if (document[index] === "\\") { index += 2; continue; }
      if (block ? document.startsWith('"""', index) : document[index] === '"') { index += block ? 3 : 1; closed = true; break; }
      if (!block && /[\r\n]/.test(document[index]!)) return;
      index++;
    }
    if (!closed) return;
    output.push('""');
  }
  return output.join("").trim();
}

export function isReadOnlyGraphqlDocument(document: string): boolean {
  const text = graphqlExecutableText(document);
  return text !== undefined && /^(?:query\b|\{)/.test(text) && !/\b(?:mutation|subscription)\b/i.test(text);
}
