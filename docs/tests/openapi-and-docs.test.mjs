import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const openapiText = fs.readFileSync(path.join(repoRoot, 'docs/openapi.yaml'), 'utf8');
const apiRefText = fs.readFileSync(path.join(repoRoot, 'docs/API_REFERENCE.md'), 'utf8');
const routerText = fs.readFileSync(path.join(repoRoot, 'crates/satspathd/src/router.rs'), 'utf8');

const PUBLIC_MUTATION_PATHS = new Set([
  '/v1/receive',
  '/v1/send',
  '/v1/claim',
  '/v1/dns/resolve',
  '/v1/transparency/verify/inclusion',
  '/v1/transparency/verify/catena',
  '/v1/profile/recover',
  '/v2/resolve',
]);

const REMOVED_LEGACY_DOCS = [
  'docs/SATSPATH_FUNCIONAMIENTO_Y_ROADMAP.md',
  'docs/TECHNICAL_PLAN_MVP.md',
  'docs/TECHNICAL_PLAN_PRODUCTION.md',
  'docs/ark_swap_safety.md',
  'docs/docker_cheatsheet.md',
  'docs/identity_ownership_model.md',
  'docs/mainnet_preview_checklist.md',
  'docs/pear_threat_model.md',
  'docs/protocol_v01_audit.md',
  'docs/release_checklist.md',
  'docs/rfc-0046-s2s-identity.md',
  'docs/routing_model.md',
  'docs/s2s/methods-bolt12.md',
  'docs/satspath_audit_and_todolist.md',
  'docs/satspath_protocol.md',
  'docs/team_workflow.md',
];

function parseOpenApiOperations(yaml) {
  const lines = yaml.split(/\r?\n/);
  const operations = [];
  let inPaths = false;
  let currentPath = null;
  let currentMethod = null;
  let currentOpLines = [];

  const flushOperation = () => {
    if (currentPath && currentMethod) {
      const block = currentOpLines.join('\n');
      const requiresBearer = /security:\s*\r?\n\s*-\s*bearerAuth:\s*\[\]/.test(block);
      const hasOperationId = /^\s{6}operationId:\s*\S+/m.test(block);
      const hasResponses = /^\s{6}responses:/m.test(block);
      operations.push({
        path: currentPath,
        method: currentMethod.toUpperCase(),
        requiresBearer,
        hasOperationId,
        hasResponses,
      });
    }
    currentMethod = null;
    currentOpLines = [];
  };

  for (const line of lines) {
    if (/^paths:\s*$/.test(line)) {
      inPaths = true;
      continue;
    }
    if (inPaths && /^[a-zA-Z0-9_-]+:\s*$/.test(line)) {
      flushOperation();
      break;
    }
    if (!inPaths) continue;

    const pathMatch = line.match(/^  (\/[^\s:]*):\s*$/);
    if (pathMatch) {
      flushOperation();
      currentPath = pathMatch[1];
      continue;
    }

    const methodMatch = line.match(/^    (get|post|put|delete|head|options|patch):\s*$/);
    if (methodMatch && currentPath) {
      flushOperation();
      currentMethod = methodMatch[1];
      continue;
    }

    if (currentMethod) {
      currentOpLines.push(line);
    }
  }
  flushOperation();
  return operations;
}

function parseApiReferenceTable(markdown) {
  const rows = [];
  const regex = /^\|\s*`([A-Z]+)`\s*\|\s*`([^`]+)`\s*\|\s*(Public|Bearer)\s*\|/gm;
  let match;
  while ((match = regex.exec(markdown)) !== null) {
    rows.push({
      method: match[1],
      rawPath: match[2],
      path: match[2].split('?')[0],
      requiresBearer: match[3] === 'Bearer',
    });
  }
  return rows;
}

function walkMarkdownFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'target') {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkMarkdownFiles(full));
    } else if (entry.name.endsWith('.md')) {
      results.push(full);
    }
  }
  return results;
}

test('OpenAPI 3.0.3 operations have operationId, responses, and match router auth rules', () => {
  const operations = parseOpenApiOperations(openapiText);
  assert.equal(operations.length, 55, 'Expected all 55 HTTP operations in docs/openapi.yaml');

  for (const op of operations) {
    assert.ok(op.hasOperationId, `${op.method} ${op.path} must define an operationId`);
    assert.ok(op.hasResponses, `${op.method} ${op.path} must define responses`);

    const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(op.method);
    const expectedBearer = isMutation && !PUBLIC_MUTATION_PATHS.has(op.path);
    assert.equal(
      op.requiresBearer,
      expectedBearer,
      `Auth mismatch for ${op.method} ${op.path} in docs/openapi.yaml`,
    );
  }
});

test('API_REFERENCE.md endpoint table matches OpenAPI operations and router auth rules', () => {
  const operations = parseOpenApiOperations(openapiText);
  const tableRows = parseApiReferenceTable(apiRefText);
  assert.ok(tableRows.length >= 54, 'Expected endpoint summary table in docs/API_REFERENCE.md');

  const openApiSet = new Set(operations.map(op => `${op.method} ${op.path}`));
  const tableSet = new Set(tableRows.map(row => `${row.method} ${row.path}`));

  assert.deepEqual(
    [...tableSet].sort(),
    [...openApiSet].sort(),
    'API_REFERENCE.md endpoint table and openapi.yaml operations must match',
  );

  for (const row of tableRows) {
    const isMutation = !['GET', 'HEAD', 'OPTIONS'].includes(row.method);
    const expectedBearer = isMutation && !PUBLIC_MUTATION_PATHS.has(row.path);
    assert.equal(
      row.requiresBearer,
      expectedBearer,
      `Auth mismatch for ${row.method} ${row.rawPath} in docs/API_REFERENCE.md`,
    );
  }
});

test('satspathd router.rs public mutation allow-list matches documented public mutations', () => {
  for (const pubPath of PUBLIC_MUTATION_PATHS) {
    if (pubPath === '/v2/resolve') {
      assert.match(routerText, /path == "\/v2\/resolve"/);
    } else {
      assert.ok(
        routerText.includes(`path == "${pubPath}"`),
        `Expected router.rs public mutation allow-list to contain ${pubPath}`,
      );
    }
  }
});

test('every local $ref in docs/openapi.yaml resolves to a defined component', () => {
  const refs = [...openapiText.matchAll(/\$ref:\s*['"]?#\/components\/(schemas|parameters|headers|securitySchemes|responses)\/([A-Za-z0-9_]+)['"]?/g)];
  assert.ok(refs.length > 0, 'Expected component $refs in docs/openapi.yaml');

  for (const [, section, name] of refs) {
    const definitionRegex = new RegExp(`^  ${section}:[\\s\\S]*?^    ${name}:\\s*$`, 'm');
    assert.match(
      openapiText,
      definitionRegex,
      `Missing #/components/${section}/${name} in docs/openapi.yaml`,
    );
  }
});

test('obsolete docs are removed and all markdown relative links resolve', () => {
  for (const rel of REMOVED_LEGACY_DOCS) {
    assert.equal(
      fs.existsSync(path.join(repoRoot, rel)),
      false,
      `Obsolete doc ${rel} should remain removed`,
    );
  }

  const mdFiles = [
    path.join(repoRoot, 'README.md'),
    ...walkMarkdownFiles(path.join(repoRoot, 'docs')),
  ];

  for (const file of mdFiles) {
    const content = fs.readFileSync(file, 'utf8').replace(/```[\s\S]*?```/g, '');
    const linkRegex = /\[[^\]]+\]\(([^)#\s]+)(?:#[^)]*)?\)/g;
    let match;
    while ((match = linkRegex.exec(content)) !== null) {
      const target = match[1];
      if (/^(https?:|mailto:|bitcoin:|lightning:|ark:|file:)/.test(target)) continue;
      const resolved = path.resolve(path.dirname(file), target);
      assert.ok(
        fs.existsSync(resolved),
        `Broken markdown link in ${path.relative(repoRoot, file)} -> ${target}`,
      );
    }
  }
});
