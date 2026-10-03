import { describe, expect, it } from "vitest";
import { graphqlExecutableText, isReadOnlyGraphqlDocument } from "../../src/modules/apiGraphql/GraphqlDocumentSafety.js";

describe("GraphQL executable token safety", () => {
  it.each([
    'query Read { lookup(value: "# string") { id } } mutation Write { deleteAccount }',
    'query Read { lookup(value: "# string") { id } } subscription Watch { events }',
    'query Read { lookup(value: "escaped \\" # string") { id } } mutation Write { remove }',
    'query Read { lookup(value: """# block string""") { id } } mutation Write { remove }',
    'query Read { lookup(value: "unterminated # mutation { remove }',
    'query Read { lookup(value: "invalid\nstring") { id } }',
    'query Read { lookup(value: """unterminated) { id } }'
  ])("rejects hidden executable writes or malformed literals: %s", (document) => {
    expect(isReadOnlyGraphqlDocument(document)).toBe(false);
  });

  it.each([
    'query Read { lookup(value: "# mutation subscription") { id } }',
    'query Read { lookup(value: """# mutation subscription""") { id } }',
    '# mutation in a comment\nquery Read { viewer { id } }',
    '{ viewer { id } } # subscription in a comment'
  ])("allows real reads with comment or literal content: %s", (document) => {
    expect(isReadOnlyGraphqlDocument(document)).toBe(true);
  });

  it("bounds masking and retains depth-relevant executable delimiters", () => {
    expect(graphqlExecutableText("x".repeat(65_537))).toBeUndefined();
    expect(graphqlExecutableText('query { value(arg: "{{{") { id } }')).toBe('query { value(arg: "") { id } }');
  });
});
