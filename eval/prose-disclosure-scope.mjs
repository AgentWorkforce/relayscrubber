// Scope labels for the invented prose-disclosure corpus.
//
// The mandatory nouns have no minimum value length: one-character letters and
// symbols after `is`, `was` or `:` are the `pr21_required_short_values` scope
// and must be redacted. The generator spells only password/passcode/passphrase/
// pw; passwd, pwd and the spaced forms are exercised by the exact fixtures.
export const SUPPORTED = new Set(['password', 'passcode', 'passphrase', 'passwd', 'pwd', 'pw', 'pass code', 'pass phrase']);
const INLINE = ['is', 'was', ':'];
const SHORT = ['short_letter', 'short_symbol'];

export function scope(c) {
  if (c.expected === 'preserve') return 'benign_controls';
  if (c.group === 'exact_fixture') return 'exact_fixture_positive';
  const mandatory = c.keyword.split('+').every(n => SUPPORTED.has(n));
  const inline = c.group === 'grammar' && mandatory && INLINE.includes(c.connector);
  if (inline && SHORT.includes(c.valueKind)) return 'pr21_required_short_values';
  if (inline && !(c.valueKind === 'spaces' && c.quote === 'none') || c.group === 'unmatched_quote' && mandatory) return 'pr21_intent_subset';
  return mandatory ? 'broader_mandatory_nouns' : 'optional_nouns_not_required';
}
