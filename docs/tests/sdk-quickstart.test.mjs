import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Exercise the published examples so edits to the guide change the code tested.
// WASM and BIP-39 are injected: this tests the integration flow, not cryptography.
const guide = await readFile(new URL('../SDK_QUICKSTART.md', import.meta.url), 'utf8');
const examples = [...guide.matchAll(/^```typescript\r?\n([\s\S]*?)^```/gm)]
  .map(match => match[1]);

function exampleContaining(text) {
  const matches = examples.filter(source => source.includes(text));
  assert.equal(matches.length, 1, `Expected one TypeScript example containing ${text}`);
  return matches[0];
}

const initialization = exampleContaining('await init()')
  .replace(/^import[\s\S]*?;\r?\n/gm, '');
const initialize = new Function('init', 'bip39', 'derive_identity_keypair_from_seed', 'console',
  `return (async () => {\n${initialization}\n})();`);

// Only erase the parameter annotations; execute the function body unchanged.
// This deliberately does not claim to type-check TypeScript or compile WASM.
const definition = exampleContaining('export async function resolveAndQuote(')
  .match(/^export async function resolveAndQuote\(([^)]*)\)\s*\{([\s\S]*)\}\s*$/m);
assert.ok(definition, 'The guide must define resolveAndQuote');
const parameters = definition[1].split(',').map(parameter => parameter.split(':')[0].trim());
const createResolveAndQuote = new Function('quote', 'console',
  `return async function (${parameters.join(',')}) {\n${definition[2]}\n};`);

function captureConsole() {
  const logs = [];
  return { logs, log: (...args) => logs.push(args) };
}

const alias = 'alice@example.com';

function successfulQuote(overrides = {}) {
  return {
    status: 'ok',
    recipient: { alias, profile_signature_verified: true },
    selected_method: { type: 'Lightning' },
    fee_sats: 1,
    qr: 'lntb1example',
    ...overrides,
  };
}

test('identity example initializes WASM before deriving account zero and logs only the public key', async () => {
  const calls = [];
  const seed = new Uint8Array(64).fill(42);
  const identity = { pubkey_hex: '02' + 'ab'.repeat(32) };
  Object.defineProperty(identity, 'secret_key_hex', {
    get() { assert.fail('The example must not read the identity secret for logging'); },
  });
  const output = captureConsole();
  let finishInitialization;
  const ready = new Promise(resolve => { finishInitialization = resolve; });

  const running = initialize(
    () => { calls.push('init'); return ready; },
    { mnemonicToSeedSync: mnemonic => {
      calls.push('seed');
      assert.equal(mnemonic, `${'abandon '.repeat(11)}about`);
      return seed;
    } },
    (receivedSeed, account) => {
      calls.push('derive');
      assert.strictEqual(receivedSeed, seed);
      assert.equal(account, 0);
      return identity;
    },
    output,
  );
  assert.deepEqual(calls, ['init']);
  assert.deepEqual(output.logs, []);
  finishInitialization();
  await running;
  assert.deepEqual(calls, ['init', 'seed', 'derive']);
  assert.deepEqual(output.logs, [['SatsPath Identity Pubkey:', identity.pubkey_hex]]);
});

test('identity example rejects a failed derivation without logging a public key', async () => {
  const output = captureConsole();
  await assert.rejects(initialize(
    async () => {},
    { mnemonicToSeedSync: () => new Uint8Array(64) },
    () => undefined,
    output,
  ), { message: 'Failed to derive SatsPath identity keypair' });
  assert.deepEqual(output.logs, []);
});

test('identity example propagates initialization errors before touching the seed', async () => {
  const failure = new Error('WASM unavailable');
  const output = captureConsole();
  await assert.rejects(initialize(
    async () => { throw failure; },
    { mnemonicToSeedSync: () => assert.fail('Seed must not be read before WASM is ready') },
    () => assert.fail('Derivation must not run after initialization fails'),
    output,
  ), error => error === failure);
  assert.deepEqual(output.logs, []);
});

test('identity example propagates seed conversion errors without deriving a key', async () => {
  const failure = new Error('Seed conversion failed');
  const output = captureConsole();
  await assert.rejects(initialize(
    async () => {},
    { mnemonicToSeedSync: () => { throw failure; } },
    () => assert.fail('Derivation must not run without seed bytes'),
    output,
  ), error => error === failure);
  assert.deepEqual(output.logs, []);
});

for (const [type, qr] of [
  ['Lightning', 'lntb1example'],
  ['Onchain', 'bitcoin:tb1qexample?amount=0.00021'],
  ['Ark', 'ark:example?amount=21000'],
]) {
  test(`quote example returns the original verified ${type} handoff`, async () => {
    const response = successfulQuote({ selected_method: { type }, qr });
    const calls = [];
    const output = captureConsole();
    const resolveAndQuote = createResolveAndQuote(async (...args) => {
      calls.push(args);
      return response;
    }, output);

    assert.strictEqual(await resolveAndQuote(alias, 21_000n), response);
    assert.deepEqual(calls, [[alias, 21_000n]]);
    assert.deepEqual(output.logs, [
      ['Selected Method:', type],
      ['Estimated Fee (sats):', 1],
      ['Validated Handoff Payload:', qr],
    ]);
  });
}

for (const amount of [1n, 21_000_000n * 100_000_000n, 2n ** 64n - 1n]) {
  test(`quote example preserves bigint amount ${amount} without rounding`, async () => {
    const calls = [];
    const response = successfulQuote();
    const resolveAndQuote = createResolveAndQuote(async (...args) => {
      calls.push(args);
      return response;
    }, captureConsole());
    assert.strictEqual(await resolveAndQuote(alias, amount), response);
    assert.deepEqual(calls, [[alias, amount]]);
  });
}

for (const fee of [0, null]) {
  test(`quote example preserves a ${fee} fee estimate`, async () => {
    const response = successfulQuote({ fee_sats: fee });
    const output = captureConsole();
    const resolveAndQuote = createResolveAndQuote(async () => response, output);
    assert.strictEqual(await resolveAndQuote(alias, 1n), response);
    assert.deepEqual(output.logs[1], ['Estimated Fee (sats):', fee]);
  });
}

for (const verified of [false, undefined]) {
  test(`quote example rejects ${verified === false ? 'false' : 'missing'} profile verification despite legacy verified=true`, async () => {
    // A legacy verification flag or DNSSEC identifier verification is insufficient.
    const recipient = { alias, verified: true, identifier_verified: true };
    if (verified !== undefined) recipient.profile_signature_verified = verified;
    const response = successfulQuote({ recipient });
    Object.defineProperty(response, 'qr', {
      get() { assert.fail('An unverified payment payload must not be accessed'); },
    });
    const output = captureConsole();
    const resolveAndQuote = createResolveAndQuote(async () => response, output);
    await assert.rejects(resolveAndQuote(alias, 21_000n), {
      message: 'Recipient profile signature failed verification',
    });
    assert.deepEqual(output.logs, []);
  });
}

test('quote example rejects invalid_signature with the recipient alias', async () => {
  const output = captureConsole();
  const response = { status: 'invalid_signature', recipient: { alias } };
  const resolveAndQuote = createResolveAndQuote(async () => response, output);
  await assert.rejects(resolveAndQuote(alias, 21_000n), {
    message: `Invalid profile signature for ${alias}`,
  });
  assert.deepEqual(output.logs, []);
});

test('quote example rejects no_route and preserves the diagnostic reason', async () => {
  const reason = 'No available rail for this amount';
  const output = captureConsole();
  const resolveAndQuote = createResolveAndQuote(async () => ({ status: 'no_route', reason }), output);
  await assert.rejects(resolveAndQuote(alias, 21_000n), {
    message: `No viable payment rail: ${reason}`,
  });
  assert.deepEqual(output.logs, []);
});

test('quote example returns null and displays an invite for an unregistered recipient', async () => {
  const response = { status: 'not_registered', invite: { invite_id: 'example-invite' } };
  const output = captureConsole();
  const resolveAndQuote = createResolveAndQuote(async () => response, output);
  assert.strictEqual(await resolveAndQuote(alias, 21_000n), null);
  assert.deepEqual(output.logs, [['Recipient not registered; invite token:', 'example-invite']]);
});

test('quote example propagates resolver failures without displaying a payment payload', async () => {
  const failure = new Error('Resolver unavailable');
  const output = captureConsole();
  const resolveAndQuote = createResolveAndQuote(async () => { throw failure; }, output);
  await assert.rejects(resolveAndQuote(alias, 21_000n), error => error === failure);
  assert.deepEqual(output.logs, []);
});

test('quote example waits for the resolver before returning or displaying the handoff', async () => {
  let complete;
  const pending = new Promise(resolve => { complete = resolve; });
  const output = captureConsole();
  const resolveAndQuote = createResolveAndQuote(() => pending, output);
  const running = resolveAndQuote(alias, 21_000n);
  assert.deepEqual(output.logs, []);
  const response = successfulQuote();
  complete(response);
  assert.strictEqual(await running, response);
  assert.equal(output.logs.length, 3);
});
