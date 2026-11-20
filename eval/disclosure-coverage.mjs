// Synthetic qualification inputs only. No production/session sample is used.
export const REDACTION = '[REDACTED]';
export const PUBLIC = 'QUALIFICATION_PUBLIC_CONTEXT';

/** Check that every sensitive input span can only map to a redaction token.
 * Unchanged output must map, in order, entirely outside the protected spans.
 * This catches partial suffix leaks and handles one-character values that also
 * occur innocently in the keyword or surrounding text. Broader redaction is
 * allowed here; public-marker and benign-input checks measure precision.
 */
export function spansCovered(input, output, spans) {
  if (!spans.length) return input === output;
  if (!output.includes(REDACTION)) return false;
  const protectedAt = new Uint8Array(input.length);
  for (const [start, end] of spans) protectedAt.fill(1, start, end);
  const protectedCount = new Uint32Array(input.length + 1);
  for (let i = 0; i < input.length; i++) protectedCount[i + 1] = protectedCount[i] + protectedAt[i];
  const safe = (start, length) => protectedCount[start + length] === protectedCount[start];
  const parts = output.replace(/(?:\[REDACTED\]){2,}/g, REDACTION).split(REDACTION);
  if (!input.startsWith(parts[0]) || !safe(0, parts[0].length)) return false;
  const memo = new Map();
  function follows(index, from) {
    const cacheKey = `${index}:${from}`;
    if (memo.has(cacheKey)) return memo.get(cacheKey);
    const literal = parts[index];
    if (index === parts.length - 1) {
      const start = input.length - literal.length;
      return start >= from && input.endsWith(literal) && safe(start, literal.length);
    }
    for (let at = input.indexOf(literal, from); at !== -1; at = input.indexOf(literal, at + 1)) {
      if (safe(at, literal.length) && follows(index + 1, at + literal.length)) {
        memo.set(cacheKey, true);
        return true;
      }
    }
    memo.set(cacheKey, false);
    return false;
  }
  return follows(1, parts[0].length);
}

const keywords = ['password', 'passcode', 'passphrase', 'pw', 'pass', 'PIN', 'secret', 'key', 'token'];
const connectors = ['is', 'was', '=', ':', 'is now', 'set to', 'is set to'];
const quotes = ['', "'", '"'];
const values = {
  short_letter: 'q', short_symbol: '!', digits: '0047',
  symbols: 'R7!#%&(=~', ordinary_word: 'orchid', type_word: 'string',
  spaces: 'velvet river lantern', unicode: '松🔐éж', long: 'v'.repeat(2048) + '!',
};
function casing(text, mode) {
  if (mode === 'upper') return text.toUpperCase();
  if (mode === 'mixed') return [...text].map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join('');
  return text.toLowerCase();
}

function disclosure({keyword, connector, quote = '', value, mode = 'lower', gap1 = ' ', gap2 = ' ', close = true}) {
  const left = `${casing('my', mode)} ${casing(keyword, mode)}${gap1}${casing(connector, mode)}${gap2}${quote}`;
  return {text: left + value + (close ? quote : ''), span: [left.length, left.length + value.length]};
}

/** Deterministic cross-product plus seeded mutation-style inputs. */
export function disclosureCases(seed = 24301, fuzzCount = 1024) {
  const out = [];
  function positive(group, dimensions, disclosures, separator = '') {
    let input = PUBLIC + '\n';
    const spans = [];
    for (const [i, d] of disclosures.entries()) {
      if (i) input += separator;
      spans.push(d.span.map(n => n + input.length));
      input += d.text;
    }
    out.push({id: `${group}-${String(out.length).padStart(6, '0')}`, expected: 'redact', group, ...dimensions, input, spans});
  }
  for (const keyword of keywords) for (const connector of connectors)
    for (const mode of ['lower', 'upper', 'mixed']) for (const quote of quotes)
      for (const [valueKind, value] of Object.entries(values))
        positive('grammar', {keyword: keyword.toLowerCase(), connector, mode, quote: quote || 'none', valueKind},
          [disclosure({keyword, connector, quote, value, mode})]);

  for (const keyword of keywords) for (const connector of connectors)
    for (const quote of quotes) for (const [gap1, gap2, lineBreak] of [
      ['\n', ' ', 'before_connector'], [' ', '\n', 'before_value'],
      ['\r\n', '\r\n', 'crlf'], ['\u2003', '\n', 'unicode_space'],
    ]) positive('line_break', {keyword: keyword.toLowerCase(), connector, quote: quote || 'none', lineBreak},
      [disclosure({keyword, connector, quote, value: 'synthetic-amber#47', gap1, gap2})]);

  for (const keyword of keywords) for (const connector of ['is\nnow', 'set\nto', 'is\nset\nto'])
    positive('split_connector', {keyword: keyword.toLowerCase(), connector},
      [disclosure({keyword, connector, value: 'synthetic-cobalt#53'})]);

  for (const keyword of keywords) for (const quote of ["'", '"', '`', '“']) {
    const d = disclosure({keyword, connector: 'is', quote, value: 'synthetic violet\nsynthetic cobalt'});
    if (quote === '“') d.text = d.text.slice(0, -1) + '”';
    positive('multiline_value', {keyword: keyword.toLowerCase(), quote}, [d]);
  }
  for (const keyword of keywords) for (const quote of ["'", '"'])
    positive('unmatched_quote', {keyword: keyword.toLowerCase(), quote},
      [disclosure({keyword, connector: 'is', quote, value: 'synthetic unfinished river', close: false})]);

  for (const first of keywords) for (const second of keywords) for (const connector of ['is', ':']) {
    positive('multiple', {keyword: `${first.toLowerCase()}+${second.toLowerCase()}`, connector}, [
      disclosure({keyword: first, connector, quote: '"', value: 'synthetic-mauve#17'}),
      disclosure({keyword: second, connector, quote: "'", value: 'synthetic-teal#29'}),
    ], '; then ');
  }

  let state = seed >>> 0;
  const random = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
  const pick = xs => xs[random() % xs.length];
  const alphabet = [...'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!#%&()[]{}^~+-_=?:/松é🔐'];
  for (let i = 0; i < fuzzCount; i++) {
    const keyword = pick(keywords), connector = pick(connectors), quote = pick(quotes);
    const length = pick([1, 2, 3, 8, 31, 64, 257, 1024]);
    const value = Array.from({length}, () => pick(alphabet)).join('');
    const mode = pick(['lower', 'upper', 'mixed']);
    positive('seeded_mutation', {keyword: keyword.toLowerCase(), connector, quote: quote || 'none', mode, seed, ordinal: i},
      [disclosure({keyword, connector, quote, value, mode, gap1: pick([' ', '  ', '\t', '\n']), gap2: pick([' ', '\t', '\n', '\r\n'])})]);
  }

  const benign = [
    ['requested_controls', 'password policy'],
    ['requested_controls', 'reset your password'],
    ['requested_controls', 'the password field'],
    ['documentary', 'The password field is required.'],
    ['documentary', 'The PIN field is empty.'],
    ['documentary', 'A token is a unit of text.'],
    ['documentary', 'The key is pressed to continue.'],
    ['documentary', 'The pass is complete.'],
    ['documentary', 'The password is stored securely.'],
    ['references', 'my password is ${PASSWORD}'],
    ['references', 'my password is process.env.PASSWORD'],
    ['type_annotation', 'const password: string'],
    ['word_boundary', 'compass is pointing north'],
    ['word_boundary', 'monkey is on the branch'],
    ['word_boundary', 'tokenizer is configured'],
  ];
  for (const [group, text] of benign) for (const mode of ['lower', 'upper', 'mixed']) {
    // Vary prose/identifiers, preserving case-sensitive language syntax.
    const varied = group === 'type_annotation' ? `const ${casing('password', mode)}: string`
      : text.includes('process.env.PASSWORD') ? `${casing('my password is', mode)} process.env.PASSWORD`
        : casing(text, mode);
    out.push({id: `benign-${String(out.length).padStart(6, '0')}`, expected: 'preserve', group, mode, input: PUBLIC + '\n' + varied, spans: []});
  }
  return out;
}
