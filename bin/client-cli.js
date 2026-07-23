#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { promises as dns } from 'node:dns';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  scryptSync,
} from 'node:crypto';

import { p384 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import bs58 from 'bs58';
import { importJWK, SignJWT } from 'jose';

const SUPPORTED_SCOPES = [
  'health-care:reader',
  'health-care:provider',
  'health-tech:provider',
  'health-research:provider',
  'health-research:reader',
  'animal-care:reader',
  'animal-care:provider',
  'animal-research:provider',
  'animal-research:reader',
  'health-insurance:provider',
  'health-insurance:reader',
  'vet-insurance:provider',
  'vet-insurance:reader',
];

function printHelp() {
  console.log(`
client-cli (public)

Usage:
  client-cli domain:precheck --domain <subdomain.globaldatacare.es> [--repo <path>]

  client-cli org:init-service \
    --domain <subdomain.globaldatacare.es> \
    --legal-name "<legal name>" \
    --tax-id <id> \
    --country <ISO2> \
    --sector <scope> \
    [--terms-url <https-url>] \
    [--scrypt 17:8:1:48] \
    --passkey <secret> \
    [--repo <path>]

  client-cli org:add-controller \
    --domain <subdomain.globaldatacare.es> \
    --email <corporate-email> \
    --role-isco <4digits> \
    [--scrypt 17:8:1:48] \
    --passkey <secret> \
    [--repo <path>]

  client-cli org:recover-service \
    --domain <subdomain.globaldatacare.es> \
    [--scrypt 17:8:1:48] \
    --passkey <secret> \
    --salt <hex> \
    [--repo <path>]

  client-cli org:recover-controller \
    --domain <subdomain.globaldatacare.es> \
    --email <corporate-email> \
    --role-isco <4digits> \
    [--scrypt 17:8:1:48] \
    --passkey <secret> \
    --salt <hex> \
    [--repo <path>]

  client-cli org:derive-pontusx \
    --domain <subdomain.globaldatacare.es> \
    [--scrypt 17:8:1:48] \
    --passkey <secret> \
    [--salt <hex>] \
    [--replace-pontusx] \
    [--repo <path>]

  client-cli vp:sign \
    --domain <subdomain.globaldatacare.es> \
    --email <corporate-email> \
    --role-isco <4digits> \
    --aud <did-or-url> \
    --nonce <nonce> \
    [--exp-seconds 300] \
    [--out <jwt-file>] \
    [--repo <path>]

  client-cli submission:pack \
    --request-id <id> \
    --ica-domain <ica-domain> \
    [--domain <subdomain.globaldatacare.es>] \
    [--terms-pdf <signed-pdf>] \
    [--out <bundle.tgz>] \
    [--repo <path>]

Notes:
  - supported scopes (--sector): ${SUPPORTED_SCOPES.join(', ')}
  - current key suite in org:init-service: ES-384 + ES256K (secp256k1) for JWKS/DID.
  - CSR/X.509 remains ES-384 (P-384 key).
  - Pontus-X derivation command: org:derive-pontusx (re-derive ES256K/secp256k1).
  - use --replace-pontusx for ES256K rotation (replace prior Pontus-X key refs).
  - target compatibility (not generated yet in this CLI): ML-DSA, ML-KEM.
  - scrypt profile format: <log2N>:<r>:<p>:<dkLen>
  - default scrypt profile: 17:8:1:48  => N = 2^17 = 131072
  - org:init-service and org:add-controller always auto-generate salt.
  - passkey/salt are used together only in recover commands.
  - output root by domain: output/did_web_<domain>/
  - passkey/salt can be placed at the end of command.
`);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
      continue;
    }
    args[key] = next;
    i += 1;
  }
  return args;
}

function requireArg(args, name) {
  const value = args[name];
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`Missing required argument --${name}`);
  }
  return value.trim();
}

function ensureDir(dirPath) {
  mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function normalizeDomain(rawDomain) {
  const trimmed = rawDomain.trim().toLowerCase();
  const withoutProtocol = trimmed.replace(/^https?:\/\//, '');
  return withoutProtocol.replace(/\/+$/, '');
}

function normalizeRoleIsco(rawRole) {
  const role = rawRole.trim();
  if (!/^\d{4}$/.test(role)) {
    throw new Error('role-isco must be exactly 4 digits.');
  }
  return role;
}

function normalizeSaltHex(rawSalt) {
  const clean = rawSalt.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('salt must be hex string with even length.');
  }
  return clean;
}

function normalizeSector(rawSector) {
  const scope = rawSector.trim().toLowerCase();
  if (SUPPORTED_SCOPES.includes(scope)) {
    return scope;
  }
  if (!scope.includes(':')) {
    const providerDefault = `${scope}:provider`;
    if (SUPPORTED_SCOPES.includes(providerDefault)) {
      return providerDefault;
    }
  }
  throw new Error(`Invalid sector/scope "${rawSector}". Supported: ${SUPPORTED_SCOPES.join(', ')}`);
}

function requireSector(args) {
  const rawSector = args.sector || args.category;
  if (typeof rawSector !== 'string' || !rawSector.trim()) {
    throw new Error(`Missing required argument --sector (or --category). Supported: ${SUPPORTED_SCOPES.join(', ')}`);
  }
  return normalizeSector(rawSector);
}

function bigintToBytes(value, byteLength) {
  const hex = value.toString(16).padStart(byteLength * 2, '0');
  return Buffer.from(hex, 'hex');
}

function parseScryptProfile(raw) {
  const profile = (raw || '17:8:1:48').trim();
  const parts = profile.split(':').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n) || n <= 0)) {
    throw new Error('Invalid scrypt profile. Expected format <log2N>:<r>:<p>:<dkLen>, e.g. 17:8:1:48.');
  }
  const [log2N, r, p, dkLen] = parts;
  if (log2N < 10 || log2N > 24) {
    throw new Error('scrypt log2N must be between 10 and 24.');
  }
  return {
    profile,
    log2N,
    N: 2 ** log2N,
    r,
    p,
    dkLen,
  };
}

function buildDidWeb(domain) {
  return `did:web:${domain}`;
}

function getEmployeeIds(domain, email, roleIsco) {
  const emailNorm = email.trim().toLowerCase();
  const roleNorm = normalizeRoleIsco(roleIsco);
  const internalEmployeeId = `did:web:${domain}:employee:${emailNorm}:${roleNorm}`;
  const digest = createHash('sha256').update(internalEmployeeId).digest();
  const employeePublicId = `z${bs58.encode(digest)}`;
  const employeeDid = `did:web:${domain}:employee:multibase:${employeePublicId}`;
  return {
    emailNorm,
    roleNorm,
    internalEmployeeId,
    employeePublicId,
    employeeDid,
  };
}

function toDidWebFolderName(domain) {
  return `did_web_${domain.replace(/[^a-z0-9._-]/g, '_')}`;
}

function resolveOrgOutputRoot(repoRoot, domain) {
  return path.join(repoRoot, 'output', toDidWebFolderName(domain));
}

function resolveOrgOutputRootForPack(repoRoot, args) {
  if (typeof args.domain === 'string' && args.domain.trim()) {
    return resolveOrgOutputRoot(repoRoot, normalizeDomain(args.domain));
  }
  const outputRoot = path.join(repoRoot, 'output');
  if (!existsSync(outputRoot)) {
    throw new Error('Missing output directory. Provide --domain or run org:init-service first.');
  }
  const candidates = readdirSync(outputRoot)
    .filter((entry) => entry.startsWith('did_web_'))
    .map((entry) => path.join(outputRoot, entry))
    .filter((entryPath) => statSync(entryPath).isDirectory());
  if (candidates.length === 1) return candidates[0];
  if (candidates.length === 0) {
    throw new Error('No did_web_* outputs found. Provide --domain or run org:init-service first.');
  }
  throw new Error('Multiple did_web_* outputs found. Use --domain to select one.');
}

function deriveDeterministicP384Key(passkey, saltHex, scryptProfile) {
  const salt = Buffer.from(normalizeSaltHex(saltHex), 'hex');
  const scrypt = parseScryptProfile(scryptProfile);
  const seed = scryptSync(passkey, salt, scrypt.dkLen, {
    N: scrypt.N,
    r: scrypt.r,
    p: scrypt.p,
    maxmem: 128 * scrypt.N * scrypt.r * 2,
  });

  const order = p384.Point.Fn.ORDER;
  const scalar = (BigInt(`0x${Buffer.from(seed).toString('hex')}`) % (order - 1n)) + 1n;
  const dBytes = bigintToBytes(scalar, 48);
  const pub = p384.getPublicKey(dBytes, false);
  const x = Buffer.from(pub.slice(1, 49)).toString('base64url');
  const y = Buffer.from(pub.slice(49)).toString('base64url');
  const d = dBytes.toString('base64url');

  const privateJwk = {
    kty: 'EC',
    crv: 'P-384',
    x,
    y,
    d,
  };
  const publicJwk = {
    kty: 'EC',
    crv: 'P-384',
    x,
    y,
  };
  const kid = createHash('sha256')
    .update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }))
    .digest('base64url');

  return {
    privateJwk,
    publicJwk: {
      ...publicJwk,
      kid,
      use: 'sig',
      alg: 'ES384',
    },
    kid,
    scrypt,
  };
}

function deriveDeterministicSecp256k1Key(passkey, saltHex, scryptProfile) {
  const salt = Buffer.from(normalizeSaltHex(saltHex), 'hex');
  const scrypt = parseScryptProfile(scryptProfile);
  const seed = scryptSync(passkey, salt, scrypt.dkLen, {
    N: scrypt.N,
    r: scrypt.r,
    p: scrypt.p,
    maxmem: 128 * scrypt.N * scrypt.r * 2,
  });

  // Domain separation for Pontus-X profile from the same passkey/salt.
  const context = Buffer.from('gdc:v1:service:pontusx:es256k', 'utf8');
  const separatedSeed = createHash('sha256').update(seed).update(Buffer.from('|')).update(context).digest();
  const order = secp256k1.Point.Fn.ORDER;
  const scalar = (BigInt(`0x${Buffer.from(separatedSeed).toString('hex')}`) % (order - 1n)) + 1n;
  const dBytes = bigintToBytes(scalar, 32);
  const pub = secp256k1.getPublicKey(dBytes, false);
  const x = Buffer.from(pub.slice(1, 33)).toString('base64url');
  const y = Buffer.from(pub.slice(33)).toString('base64url');
  const d = dBytes.toString('base64url');

  const privateJwk = {
    kty: 'EC',
    crv: 'secp256k1',
    x,
    y,
    d,
  };
  const publicJwk = {
    kty: 'EC',
    crv: 'secp256k1',
    x,
    y,
  };
  const kid = createHash('sha256')
    .update(JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y }))
    .digest('base64url');

  return {
    privateJwk,
    publicJwk: {
      ...publicJwk,
      kid,
      use: 'sig',
      alg: 'ES256K',
    },
    kid,
    scrypt,
    context: 'gdc:v1:service:pontusx:es256k',
  };
}

function samePublicKey(left, right) {
  if (!left || !right) return false;
  return left.kty === right.kty && left.crv === right.crv && left.x === right.x && left.y === right.y;
}

function toPkcs8Pem(privateJwk) {
  const keyObject = createPrivateKey({ key: privateJwk, format: 'jwk' });
  return keyObject.export({ format: 'pem', type: 'pkcs8' }).toString();
}

function toSpkiPem(publicJwk) {
  const keyObject = createPublicKey({ key: publicJwk, format: 'jwk' });
  return keyObject.export({ format: 'pem', type: 'spki' }).toString();
}

function pemToDerBase64(pem) {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function sanitizeX509SubjectValue(value) {
  return value.replace(/[\/=+<>#;]/g, '_').trim();
}

function runOpenSsl(args, options = {}) {
  try {
    return execFileSync('openssl', args, { stdio: 'pipe', ...options }).toString();
  } catch (error) {
    const stderr = error?.stderr?.toString?.() || error?.message || 'unknown error';
    throw new Error(`openssl ${args.join(' ')} failed: ${stderr}`);
  }
}

function scopeToPathSegment(scope) {
  return scope.replace(':', '/');
}

function scopeToIdSuffix(scope) {
  return scope.replace(/[^a-z0-9_-]/g, '-');
}

function buildOrgDidDocument(domain, serviceJwk, sector, extra = {}) {
  const orgDid = buildDidWeb(domain);
  const scopePath = scopeToPathSegment(sector);
  const scopeId = scopeToIdSuffix(sector);
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: orgDid,
    ...extra,
    verificationMethod: [
      {
        id: `${orgDid}#${serviceJwk.kid}`,
        type: 'JsonWebKey2020',
        controller: orgDid,
        publicKeyJwk: serviceJwk,
      },
      ...(extra.verificationMethod || []),
    ],
    authentication: [
      `${orgDid}#${serviceJwk.kid}`,
      ...((extra.authentication || []).filter((v) => v !== `${orgDid}#${serviceJwk.kid}`)),
    ],
    assertionMethod: [
      `${orgDid}#${serviceJwk.kid}`,
      ...((extra.assertionMethod || []).filter((v) => v !== `${orgDid}#${serviceJwk.kid}`)),
    ],
    service: [
      {
        id: `${orgDid}#dsp`,
        type: 'DataSpaceProtocolService',
        serviceEndpoint: `https://${domain}/dsp`,
      },
      {
        id: `${orgDid}#dsp-${scopeId}`,
        type: 'DataSpaceProtocolService',
        serviceEndpoint: `https://${domain}/dsp/${scopePath}`,
      },
    ],
  };
}

function buildOpenIdConfiguration(domain) {
  const issuer = `https://${domain}`;
  return {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    did_document_uri: `${issuer}/.well-known/did.json`,
    vc_uri: `${issuer}/.well-known/vc.json`,
  };
}

async function signJwt({ privateJwk, kid, iss, sub, aud, expiresInSeconds, payload }) {
  const key = await importJWK(privateJwk, 'ES384');
  let builder = new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES384', typ: 'JWT', kid })
    .setIssuer(iss)
    .setIssuedAt();

  if (sub) builder = builder.setSubject(sub);
  if (aud) builder = builder.setAudience(aud);
  if (expiresInSeconds) builder = builder.setExpirationTime(`${expiresInSeconds}s`);

  return builder.sign(key);
}

async function createOrganizationVc({
  domain,
  legalName,
  taxId,
  country,
  sector,
  termsUrl,
  privateJwk,
  serviceKid,
}) {
  const orgDid = buildDidWeb(domain);
  const credentialSubject = {
    id: orgDid,
    legalName,
    taxId,
    countryCode: country,
    sector,
    termsAndConditionsUrl: termsUrl,
    termsAndConditionsHashSha256: createHash('sha256').update(termsUrl).digest('hex'),
  };
  const proofJwt = await signJwt({
    privateJwk,
    kid: `${orgDid}#${serviceKid}`,
    iss: orgDid,
    sub: orgDid,
    payload: {
      type: ['VerifiableCredential', 'LegalParticipantCredential'],
      vc: { credentialSubject },
    },
  });
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'LegalParticipantCredential'],
    issuer: orgDid,
    validFrom: new Date().toISOString(),
    credentialSubject,
    proof: {
      type: 'JwtProof2020',
      verificationMethod: `${orgDid}#${serviceKid}`,
      jwt: proofJwt,
    },
  };
}

async function createEmployeeVc({
  orgDid,
  employeeDid,
  email,
  roleIsco,
  orgPrivateJwk,
  orgServiceKid,
}) {
  const credentialSubject = {
    id: employeeDid,
    employeeEmail: email,
    roleIsco,
    organization: orgDid,
  };
  const proofJwt = await signJwt({
    privateJwk: orgPrivateJwk,
    kid: `${orgDid}#${orgServiceKid}`,
    iss: orgDid,
    sub: employeeDid,
    payload: {
      type: ['VerifiableCredential', 'EmployeeCredential'],
      vc: { credentialSubject },
    },
  });
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${randomUUID()}`,
    type: ['VerifiableCredential', 'EmployeeCredential'],
    issuer: orgDid,
    validFrom: new Date().toISOString(),
    credentialSubject,
    proof: {
      type: 'JwtProof2020',
      verificationMethod: `${orgDid}#${orgServiceKid}`,
      jwt: proofJwt,
    },
  };
}

async function cmdDomainPrecheck(args) {
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const orgRoot = resolveOrgOutputRoot(repoRoot, domain);
  const notFoundCodes = new Set(['ENOTFOUND', 'ENODATA', 'EAI_NONAME', 'EAI_NODATA', 'NXDOMAIN', 'NOTFOUND']);
  const queryErrors = [];
  const queryRecords = {};

  async function runQuery(label, queryFn) {
    try {
      const value = await queryFn();
      if (Array.isArray(value) && value.length > 0) {
        queryRecords[label] = value;
      } else if (value && !Array.isArray(value)) {
        queryRecords[label] = value;
      }
      return { label, ok: true, code: null };
    } catch (error) {
      const code = error?.code || 'UNKNOWN';
      const message = error?.message || 'DNS query error';
      queryErrors.push({ label, code, message });
      return { label, ok: false, code };
    }
  }

  const checks = await Promise.all([
    runQuery('lookup', () => dns.lookup(domain, { all: true })),
    runQuery('A', () => dns.resolve4(domain)),
    runQuery('AAAA', () => dns.resolve6(domain)),
    runQuery('CNAME', () => dns.resolveCname(domain)),
    runQuery('MX', () => dns.resolveMx(domain)),
    runQuery('NS', () => dns.resolveNs(domain)),
    runQuery('TXT', () => dns.resolveTxt(domain)),
  ]);

  const hasAnyRecords = Object.keys(queryRecords).length > 0;
  const nonNotFoundErrors = queryErrors.filter((err) => !notFoundCodes.has(err.code));

  // "free" is true only when all checks consistently return not-found/nodata.
  // Any positive record or ambiguous error means "not free / unknown" to avoid false positives.
  const free = !hasAnyRecords && queryErrors.length > 0 && nonNotFoundErrors.length === 0;

  const result = {
    domain,
    checkedAt: new Date().toISOString(),
    dnsRecords: queryRecords,
    isLikelyFree: free,
    queryResults: checks,
    dnsErrors: queryErrors,
    confidence: hasAnyRecords ? 'high-in-use' : (free ? 'medium-free' : 'low-ambiguous'),
  };

  const outPath = path.join(orgRoot, 'onboarding', 'state', 'domain-precheck.json');
  writeJson(outPath, result);

  console.log(`Wrote ${path.relative(repoRoot, outPath)}`);
  if (hasAnyRecords) {
    console.log(`Domain appears in use or reserved: ${domain}`);
    return;
  }
  if (free) {
    console.log(`Domain appears free (DNS no-data): ${domain}`);
    return;
  }
  console.log(`Domain status ambiguous (not marking free): ${domain}`);
}

async function cmdOrgInitService(args) {
  if (args.salt) {
    throw new Error('org:init-service auto-generates salt. Use org:recover-service to regenerate.');
  }
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const outputRoot = resolveOrgOutputRoot(repoRoot, domain);
  const legalName = requireArg(args, 'legal-name');
  const taxId = requireArg(args, 'tax-id');
  const country = requireArg(args, 'country').toUpperCase();
  const sector = requireSector(args);
  const passkey = requireArg(args, 'passkey');
  const termsUrl = args['terms-url'] ? requireArg(args, 'terms-url') : `https://${domain}/terms`;
  const profile = args.scrypt || '17:8:1:48';
  const salt = randomBytes(16).toString('hex');

  const { privateJwk, publicJwk, kid, scrypt } = deriveDeterministicP384Key(passkey, salt, profile);
  const {
    privateJwk: pontusPrivateJwk,
    publicJwk: pontusPublicJwk,
    kid: pontusKid,
    context: pontusContext,
  } = deriveDeterministicSecp256k1Key(passkey, salt, profile);
  const orgDid = buildDidWeb(domain);

  const privateDir = path.join(outputRoot, '.private', 'service');
  const pontusPrivateDir = path.join(outputRoot, '.private', 'service-pontusx');
  const wellKnownDir = path.join(outputRoot, '.well-known');
  const pkiDir = path.join(outputRoot, 'pki');
  const stateDir = path.join(outputRoot, 'onboarding', 'state');

  ensureDir(privateDir);
  ensureDir(pontusPrivateDir);
  ensureDir(wellKnownDir);
  ensureDir(pkiDir);
  ensureDir(stateDir);

  writeJson(path.join(privateDir, 'private.jwk.json'), privateJwk);
  writeJson(path.join(privateDir, 'public.jwk.json'), publicJwk);
  const privateKeyPem = toPkcs8Pem(privateJwk);
  writeFileSync(path.join(privateDir, 'private-key.pem'), privateKeyPem);
  writeFileSync(path.join(privateDir, 'public-key.pem'), toSpkiPem(publicJwk));
  writeJson(path.join(pontusPrivateDir, 'private.jwk.json'), pontusPrivateJwk);
  writeJson(path.join(pontusPrivateDir, 'public.jwk.json'), pontusPublicJwk);
  writeFileSync(path.join(pontusPrivateDir, 'private-key.pem'), toPkcs8Pem(pontusPrivateJwk));
  writeFileSync(path.join(pontusPrivateDir, 'public-key.pem'), toSpkiPem(pontusPublicJwk));

  const csrPath = path.join(pkiDir, `${domain}.csr.pem`);
  runOpenSsl([
    'req',
    '-new',
    '-sha384',
    '-key',
    path.join(privateDir, 'private-key.pem'),
    '-out',
    csrPath,
    '-subj',
    `/CN=${sanitizeX509SubjectValue(domain)}/O=${sanitizeX509SubjectValue(legalName)}/C=${sanitizeX509SubjectValue(country)}`,
  ]);

  const pontusVmId = `${orgDid}#pontusx-${pontusKid}`;
  const didDoc = buildOrgDidDocument(domain, publicJwk, sector, {
    verificationMethod: [
      {
        id: pontusVmId,
        type: 'JsonWebKey2020',
        controller: orgDid,
        publicKeyJwk: pontusPublicJwk,
      },
    ],
    authentication: [pontusVmId],
    assertionMethod: [pontusVmId],
  });
  const jwks = { keys: [publicJwk, pontusPublicJwk] };
  const vc = await createOrganizationVc({
    domain,
    legalName,
    taxId,
    country,
    sector,
    termsUrl,
    privateJwk,
    serviceKid: kid,
  });

  writeJson(path.join(wellKnownDir, 'did.json'), didDoc);
  writeJson(path.join(wellKnownDir, 'jwks.json'), jwks);
  writeJson(path.join(wellKnownDir, 'vc.json'), vc);
  writeJson(path.join(wellKnownDir, 'openid-configuration'), buildOpenIdConfiguration(domain));
  writeJson(path.join(stateDir, 'organization-profile.json'), {
    version: 'v1',
    createdAt: new Date().toISOString(),
    domain,
    did: orgDid,
    legalName,
    taxId,
    country,
    sector,
  });

  writeJson(path.join(stateDir, 'service-kdf.json'), {
    version: 'v1',
    createdAt: new Date().toISOString(),
    did: orgDid,
    serviceKid: kid,
    pontusKid,
    sector,
    kdf: {
      algorithm: 'scrypt',
      profile: scrypt.profile,
      log2N: scrypt.log2N,
      r: scrypt.r,
      p: scrypt.p,
      dkLen: scrypt.dkLen,
      salt,
    },
    recovery: 'Re-run org:init-service with same domain, passkey, salt and scrypt profile.',
  });
  writeJson(path.join(stateDir, 'pontusx-kdf.json'), {
    version: 'v1',
    createdAt: new Date().toISOString(),
    did: orgDid,
    pontusKid,
    context: pontusContext,
    kdf: {
      algorithm: 'scrypt',
      profile: scrypt.profile,
      log2N: scrypt.log2N,
      r: scrypt.r,
      p: scrypt.p,
      dkLen: scrypt.dkLen,
      salt,
    },
    note: 'Derived ES256K/secp256k1 key for Pontus-X compatibility and added it to .well-known/jwks.json.',
  });

  console.log(`Generated service onboarding material for ${domain}`);
  console.log(`Output root: ${path.relative(repoRoot, outputRoot)}`);
  console.log(`CSR: ${path.relative(repoRoot, csrPath)}`);
  console.log(`JWKS keys: ES384=${kid}, ES256K=${pontusKid}`);
  console.log(`Generated salt: ${salt}`);
}

async function cmdOrgAddController(args) {
  if (args.salt) {
    throw new Error('org:add-controller auto-generates salt. Use org:recover-controller to regenerate.');
  }
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const outputRoot = resolveOrgOutputRoot(repoRoot, domain);
  const email = requireArg(args, 'email').toLowerCase();
  const roleIsco = normalizeRoleIsco(requireArg(args, 'role-isco'));
  const passkey = requireArg(args, 'passkey');
  const profile = args.scrypt || '17:8:1:48';
  const salt = randomBytes(16).toString('hex');

  const orgDid = buildDidWeb(domain);
  const { internalEmployeeId, employeePublicId, employeeDid } = getEmployeeIds(domain, email, roleIsco);
  const { privateJwk, publicJwk, kid, scrypt } = deriveDeterministicP384Key(passkey, salt, profile);

  const servicePrivateJwkPath = path.join(outputRoot, '.private', 'service', 'private.jwk.json');
  const orgDidPath = path.join(outputRoot, '.well-known', 'did.json');
  const orgJwksPath = path.join(outputRoot, '.well-known', 'jwks.json');
  if (!existsSync(servicePrivateJwkPath) || !existsSync(orgDidPath) || !existsSync(orgJwksPath)) {
    throw new Error('Missing organization service material. Run org:init-service first.');
  }

  const orgPrivateJwk = readJson(servicePrivateJwkPath);
  const orgDidDoc = readJson(orgDidPath);
  const orgJwks = readJson(orgJwksPath);
  const orgServiceKid = Array.isArray(orgJwks?.keys)
    ? orgJwks.keys.find((key) => key?.kty === 'EC' && key?.crv === 'P-384')?.kid
    : null;
  if (!orgServiceKid) {
    throw new Error('Invalid .well-known/jwks.json, missing ES384 service key kid.');
  }

  const controllerPrivateDir = path.join(outputRoot, '.private', 'controllers', employeePublicId);
  ensureDir(controllerPrivateDir);
  writeJson(path.join(controllerPrivateDir, 'private.jwk.json'), privateJwk);
  writeJson(path.join(controllerPrivateDir, 'public.jwk.json'), publicJwk);
  writeFileSync(path.join(controllerPrivateDir, 'private-key.pem'), toPkcs8Pem(privateJwk));
  writeFileSync(path.join(controllerPrivateDir, 'public-key.pem'), toSpkiPem(publicJwk));
  writeJson(path.join(controllerPrivateDir, 'identity.json'), {
    internalEmployeeId,
    employeePublicId,
    employeeDid,
    email,
    roleIsco,
  });

  const pkiDir = path.join(outputRoot, 'pki');
  ensureDir(pkiDir);
  const employeeCsrPath = path.join(pkiDir, `employee-${employeePublicId}.csr.pem`);
  const employeeCn = `emp-${employeePublicId}`.slice(0, 64);
  runOpenSsl([
    'req',
    '-new',
    '-sha384',
    '-key',
    path.join(controllerPrivateDir, 'private-key.pem'),
    '-out',
    employeeCsrPath,
    '-subj',
    `/CN=${sanitizeX509SubjectValue(employeeCn)}/O=${sanitizeX509SubjectValue(domain)}/C=ES`,
  ]);

  const controllerVmId = `${orgDid}#controller-${employeePublicId}`;
  const currentControllers = Array.isArray(orgDidDoc.controller) ? orgDidDoc.controller : [];
  if (!currentControllers.includes(employeeDid)) {
    currentControllers.push(employeeDid);
  }

  const existingVm = Array.isArray(orgDidDoc.verificationMethod) ? orgDidDoc.verificationMethod : [];
  const vmWithoutCurrent = existingVm.filter((vm) => vm.id !== controllerVmId);
  vmWithoutCurrent.push({
    id: controllerVmId,
    type: 'JsonWebKey2020',
    controller: employeeDid,
    publicKeyJwk: publicJwk,
  });

  const authentication = Array.isArray(orgDidDoc.authentication) ? orgDidDoc.authentication : [];
  if (!authentication.includes(controllerVmId)) authentication.push(controllerVmId);
  const assertionMethod = Array.isArray(orgDidDoc.assertionMethod) ? orgDidDoc.assertionMethod : [];
  if (!assertionMethod.includes(controllerVmId)) assertionMethod.push(controllerVmId);

  writeJson(orgDidPath, {
    ...orgDidDoc,
    controller: currentControllers,
    verificationMethod: vmWithoutCurrent,
    authentication,
    assertionMethod,
  });

  const employeeDir = path.join(outputRoot, 'employee', 'multibase', employeePublicId);
  ensureDir(employeeDir);
  const employeeDidDoc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: employeeDid,
    controller: [orgDid],
    verificationMethod: [
      {
        id: `${employeeDid}#${kid}`,
        type: 'JsonWebKey2020',
        controller: employeeDid,
        publicKeyJwk: publicJwk,
      },
    ],
    authentication: [`${employeeDid}#${kid}`],
    assertionMethod: [`${employeeDid}#${kid}`],
  };
  writeJson(path.join(employeeDir, 'did.json'), employeeDidDoc);
  writeJson(path.join(employeeDir, 'jwks.json'), { keys: [publicJwk] });

  const employeeVc = await createEmployeeVc({
    orgDid,
    employeeDid,
    email,
    roleIsco,
    orgPrivateJwk,
    orgServiceKid,
  });
  writeJson(path.join(employeeDir, 'vc.json'), employeeVc);

  const stateDir = path.join(outputRoot, 'onboarding', 'state');
  ensureDir(stateDir);
  writeJson(path.join(stateDir, `controller-${employeePublicId}-kdf.json`), {
    version: 'v1',
    createdAt: new Date().toISOString(),
    employeePublicId,
    employeeDid,
    kdf: {
      algorithm: 'scrypt',
      profile: scrypt.profile,
      log2N: scrypt.log2N,
      r: scrypt.r,
      p: scrypt.p,
      dkLen: scrypt.dkLen,
      salt,
    },
    recovery: 'Re-run org:add-controller with same domain, email, role-isco, passkey, salt and scrypt profile.',
  });

  console.log(`Added controller ${employeeDid}`);
  console.log(`Output root: ${path.relative(repoRoot, outputRoot)}`);
  console.log(`Employee CSR: ${path.relative(repoRoot, employeeCsrPath)}`);
  console.log(`Generated salt: ${salt}`);
}

async function cmdOrgRecoverService(args) {
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const outputRoot = resolveOrgOutputRoot(repoRoot, domain);
  const passkey = requireArg(args, 'passkey');
  const salt = normalizeSaltHex(requireArg(args, 'salt'));
  const profile = args.scrypt || '17:8:1:48';

  const jwksPath = path.join(outputRoot, '.well-known', 'jwks.json');
  if (!existsSync(jwksPath)) {
    throw new Error('Missing .well-known/jwks.json. Cannot verify recovered service key.');
  }
  const jwks = readJson(jwksPath);
  const existingServiceJwk = Array.isArray(jwks.keys)
    ? jwks.keys.find((key) => key?.kty === 'EC' && key?.crv === 'P-384')
    : null;
  if (!existingServiceJwk) {
    throw new Error('Invalid .well-known/jwks.json, missing ES384 service key.');
  }

  const { privateJwk, publicJwk, kid, scrypt } = deriveDeterministicP384Key(passkey, salt, profile);
  if (!samePublicKey(publicJwk, existingServiceJwk)) {
    throw new Error('Recovered service key does not match published jwks.json key.');
  }

  const privateDir = path.join(outputRoot, '.private', 'service');
  const stateDir = path.join(outputRoot, 'onboarding', 'state');
  ensureDir(privateDir);
  ensureDir(stateDir);
  writeJson(path.join(privateDir, 'private.jwk.json'), privateJwk);
  writeJson(path.join(privateDir, 'public.jwk.json'), publicJwk);
  writeFileSync(path.join(privateDir, 'private-key.pem'), toPkcs8Pem(privateJwk));
  writeFileSync(path.join(privateDir, 'public-key.pem'), toSpkiPem(publicJwk));

  writeJson(path.join(stateDir, 'service-kdf.recovery.json'), {
    version: 'v1',
    recoveredAt: new Date().toISOString(),
    did: buildDidWeb(domain),
    serviceKid: kid,
    kdf: {
      algorithm: 'scrypt',
      profile: scrypt.profile,
      log2N: scrypt.log2N,
      r: scrypt.r,
      p: scrypt.p,
      dkLen: scrypt.dkLen,
      salt,
    },
  });

  console.log(`Recovered service private material for ${domain}`);
  console.log(`Output root: ${path.relative(repoRoot, outputRoot)}`);
}

async function cmdOrgRecoverController(args) {
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const outputRoot = resolveOrgOutputRoot(repoRoot, domain);
  const email = requireArg(args, 'email').toLowerCase();
  const roleIsco = normalizeRoleIsco(requireArg(args, 'role-isco'));
  const passkey = requireArg(args, 'passkey');
  const salt = normalizeSaltHex(requireArg(args, 'salt'));
  const profile = args.scrypt || '17:8:1:48';

  const { internalEmployeeId, employeePublicId, employeeDid } = getEmployeeIds(domain, email, roleIsco);
  const employeeJwksPath = path.join(outputRoot, 'employee', 'multibase', employeePublicId, 'jwks.json');
  if (!existsSync(employeeJwksPath)) {
    throw new Error(`Missing employee jwks.json for ${employeeDid}`);
  }
  const employeeJwks = readJson(employeeJwksPath);
  const existingEmployeeJwk = Array.isArray(employeeJwks.keys) ? employeeJwks.keys[0] : null;
  if (!existingEmployeeJwk) {
    throw new Error(`Invalid jwks.json for ${employeeDid}`);
  }

  const { privateJwk, publicJwk, kid, scrypt } = deriveDeterministicP384Key(passkey, salt, profile);
  if (!samePublicKey(publicJwk, existingEmployeeJwk)) {
    throw new Error('Recovered controller key does not match published employee jwks.json key.');
  }

  const controllerPrivateDir = path.join(outputRoot, '.private', 'controllers', employeePublicId);
  const stateDir = path.join(outputRoot, 'onboarding', 'state');
  ensureDir(controllerPrivateDir);
  ensureDir(stateDir);
  writeJson(path.join(controllerPrivateDir, 'private.jwk.json'), privateJwk);
  writeJson(path.join(controllerPrivateDir, 'public.jwk.json'), publicJwk);
  writeFileSync(path.join(controllerPrivateDir, 'private-key.pem'), toPkcs8Pem(privateJwk));
  writeFileSync(path.join(controllerPrivateDir, 'public-key.pem'), toSpkiPem(publicJwk));
  writeJson(path.join(controllerPrivateDir, 'identity.json'), {
    internalEmployeeId,
    employeePublicId,
    employeeDid,
    email,
    roleIsco,
  });

  writeJson(path.join(stateDir, `controller-${employeePublicId}-kdf.recovery.json`), {
    version: 'v1',
    recoveredAt: new Date().toISOString(),
    employeePublicId,
    employeeDid,
    employeeKid: kid,
    kdf: {
      algorithm: 'scrypt',
      profile: scrypt.profile,
      log2N: scrypt.log2N,
      r: scrypt.r,
      p: scrypt.p,
      dkLen: scrypt.dkLen,
      salt,
    },
  });

  console.log(`Recovered controller private material for ${employeeDid}`);
  console.log(`Output root: ${path.relative(repoRoot, outputRoot)}`);
}

async function cmdOrgDerivePontusx(args) {
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const outputRoot = resolveOrgOutputRoot(repoRoot, domain);
  const passkey = requireArg(args, 'passkey');
  const replacePontusx = Boolean(args['replace-pontusx']);
  const stateDir = path.join(outputRoot, 'onboarding', 'state');
  const serviceKdfPath = path.join(stateDir, 'service-kdf.json');
  const serviceKdf = existsSync(serviceKdfPath) ? readJson(serviceKdfPath) : null;

  const profile = args.scrypt || serviceKdf?.kdf?.profile || '17:8:1:48';
  const rawSalt = args.salt ? String(args.salt) : String(serviceKdf?.kdf?.salt || '');
  if (!rawSalt.trim()) {
    throw new Error('Missing salt. Provide --salt or run org:init-service first.');
  }
  const salt = normalizeSaltHex(rawSalt);

  const { privateJwk, publicJwk, kid, scrypt, context } = deriveDeterministicSecp256k1Key(passkey, salt, profile);
  const orgDid = buildDidWeb(domain);

  const didPath = path.join(outputRoot, '.well-known', 'did.json');
  if (!existsSync(didPath)) {
    throw new Error('Missing .well-known/did.json. Run org:init-service first.');
  }
  const didDoc = readJson(didPath);
  if (didDoc.id !== orgDid) {
    throw new Error(`Domain/DID mismatch. Expected ${orgDid}, found ${didDoc.id}`);
  }

  const privateDir = path.join(outputRoot, '.private', 'service-pontusx');
  const wellKnownDir = path.join(outputRoot, '.well-known');
  const mainJwksPath = path.join(wellKnownDir, 'jwks.json');
  ensureDir(privateDir);
  ensureDir(wellKnownDir);
  ensureDir(stateDir);

  writeJson(path.join(privateDir, 'private.jwk.json'), privateJwk);
  writeJson(path.join(privateDir, 'public.jwk.json'), publicJwk);
  writeFileSync(path.join(privateDir, 'private-key.pem'), toPkcs8Pem(privateJwk));
  writeFileSync(path.join(privateDir, 'public-key.pem'), toSpkiPem(publicJwk));
  if (!existsSync(mainJwksPath)) {
    throw new Error('Missing .well-known/jwks.json. Run org:init-service first.');
  }
  const mainJwks = readJson(mainJwksPath);
  const existingKeys = Array.isArray(mainJwks.keys) ? mainJwks.keys : [];
  const isPontusxKey = (key) => key?.kty === 'EC' && key?.crv === 'secp256k1';
  const keysWithoutCurrent = existingKeys.filter((key) => (
    replacePontusx ? !isPontusxKey(key) : key?.kid !== publicJwk.kid
  ));
  keysWithoutCurrent.push(publicJwk);
  writeJson(mainJwksPath, {
    ...mainJwks,
    keys: keysWithoutCurrent,
  });

  const pontusVmId = `${orgDid}#pontusx-${kid}`;
  const currentVm = Array.isArray(didDoc.verificationMethod) ? didDoc.verificationMethod : [];
  const vmWithoutCurrent = currentVm.filter((vm) => {
    if (replacePontusx) {
      return !(typeof vm?.id === 'string' && vm.id.startsWith(`${orgDid}#pontusx-`));
    }
    return vm?.id !== pontusVmId;
  });
  vmWithoutCurrent.push({
    id: pontusVmId,
    type: 'JsonWebKey2020',
    controller: orgDid,
    publicKeyJwk: publicJwk,
  });

  const authBase = Array.isArray(didDoc.authentication) ? didDoc.authentication : [];
  const authentication = replacePontusx
    ? authBase.filter((entry) => !(typeof entry === 'string' && entry.startsWith(`${orgDid}#pontusx-`)))
    : authBase;
  if (!authentication.includes(pontusVmId)) authentication.push(pontusVmId);

  const assertionBase = Array.isArray(didDoc.assertionMethod) ? didDoc.assertionMethod : [];
  const assertionMethod = replacePontusx
    ? assertionBase.filter((entry) => !(typeof entry === 'string' && entry.startsWith(`${orgDid}#pontusx-`)))
    : assertionBase;
  if (!assertionMethod.includes(pontusVmId)) assertionMethod.push(pontusVmId);

  const service = Array.isArray(didDoc.service) ? didDoc.service : [];
  const serviceWithoutLegacyPontus = service.filter((entry) => entry.id !== `${orgDid}#jwks-pontusx`);

  writeJson(didPath, {
    ...didDoc,
    verificationMethod: vmWithoutCurrent,
    authentication,
    assertionMethod,
    service: serviceWithoutLegacyPontus,
  });

  writeJson(path.join(stateDir, 'pontusx-kdf.json'), {
    version: 'v1',
    createdAt: new Date().toISOString(),
    did: orgDid,
    pontusKid: kid,
    replacePontusx,
    context,
    kdf: {
      algorithm: 'scrypt',
      profile: scrypt.profile,
      log2N: scrypt.log2N,
      r: scrypt.r,
      p: scrypt.p,
      dkLen: scrypt.dkLen,
      salt,
    },
    note: replacePontusx
      ? 'Rotated ES256K/secp256k1 Pontus-X key and replaced prior Pontus-X references in jwks/did.'
      : 'Derived ES256K/secp256k1 key for Pontus-X compatibility and added it to .well-known/jwks.json.',
  });

  console.log(`Derived Pontus-X key profile for ${orgDid}`);
  console.log(`Pontus-X mode: ${replacePontusx ? 'rotation (replace)' : 'additive (append/update-by-kid)'}`);
  console.log(`Output root: ${path.relative(repoRoot, outputRoot)}`);
  console.log(`JWKS updated: ${path.relative(repoRoot, mainJwksPath)}`);
  if (!args.salt) {
    console.log(`Salt source: ${path.relative(repoRoot, serviceKdfPath)}`);
  }
}

async function cmdVpSign(args) {
  const repoRoot = path.resolve(args.repo || '.');
  const domain = normalizeDomain(requireArg(args, 'domain'));
  const outputRoot = resolveOrgOutputRoot(repoRoot, domain);
  const email = requireArg(args, 'email').toLowerCase();
  const roleIsco = normalizeRoleIsco(requireArg(args, 'role-isco'));
  const aud = requireArg(args, 'aud');
  const nonce = requireArg(args, 'nonce');
  const expSeconds = Number.parseInt(args['exp-seconds'] || '300', 10);
  if (!Number.isFinite(expSeconds) || expSeconds < 60 || expSeconds > 3600) {
    throw new Error('--exp-seconds must be between 60 and 3600.');
  }

  const { employeePublicId, employeeDid } = getEmployeeIds(domain, email, roleIsco);
  const controllerPrivatePath = path.join(outputRoot, '.private', 'controllers', employeePublicId, 'private.jwk.json');
  const controllerPublicPath = path.join(outputRoot, '.private', 'controllers', employeePublicId, 'public.jwk.json');
  const employeeVcPath = path.join(outputRoot, 'employee', 'multibase', employeePublicId, 'vc.json');
  if (!existsSync(controllerPrivatePath) || !existsSync(controllerPublicPath) || !existsSync(employeeVcPath)) {
    throw new Error('Missing controller material. Run org:add-controller first.');
  }

  const privateJwk = readJson(controllerPrivatePath);
  const publicJwk = readJson(controllerPublicPath);
  const employeeVc = readJson(employeeVcPath);
  const vcInPresentation = employeeVc?.proof?.jwt || employeeVc;

  const key = await importJWK(privateJwk, 'ES384');
  const vpPayload = {
    nonce,
    vp: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiablePresentation'],
      holder: employeeDid,
      verifiableCredential: [vcInPresentation],
    },
  };

  const token = await new SignJWT(vpPayload)
    .setProtectedHeader({ alg: 'ES384', typ: 'JWT', kid: `${employeeDid}#${publicJwk.kid}` })
    .setIssuer(employeeDid)
    .setSubject(employeeDid)
    .setAudience(aud)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${expSeconds}s`)
    .sign(key);

  const defaultOut = path.join(outputRoot, '.private', 'controllers', employeePublicId, 'vp-token.jwt');
  const outPath = args.out ? path.resolve(repoRoot, args.out) : defaultOut;
  ensureDir(path.dirname(outPath));
  writeFileSync(outPath, `${token}${os.EOL}`);
  console.log(`Wrote VP token: ${outPath}`);
}

async function cmdSubmissionPack(args) {
  const repoRoot = path.resolve(args.repo || '.');
  const orgRoot = resolveOrgOutputRootForPack(repoRoot, args);
  const requestId = requireArg(args, 'request-id');
  const icaDomain = normalizeDomain(requireArg(args, 'ica-domain'));
  const outPath = args.out
    ? path.resolve(repoRoot, args.out)
    : path.join(orgRoot, `submission-${requestId}.tgz`);
  const termsPdf = args['terms-pdf'] ? path.resolve(repoRoot, args['terms-pdf']) : null;
  const evidenceDir = path.join(orgRoot, 'evidence');
  ensureDir(evidenceDir);

  if (termsPdf) {
    if (!existsSync(termsPdf)) {
      throw new Error(`terms-pdf not found: ${termsPdf}`);
    }
    writeFileSync(path.join(evidenceDir, 'terms-fnmt-signed.pdf'), readFileSync(termsPdf));
  }

  const didPath = path.join(orgRoot, '.well-known', 'did.json');
  const jwksPath = path.join(orgRoot, '.well-known', 'jwks.json');
  const vcPath = path.join(orgRoot, '.well-known', 'vc.json');
  const pkiDir = path.join(orgRoot, 'pki');

  if (!existsSync(didPath) || !existsSync(jwksPath) || !existsSync(vcPath) || !existsSync(pkiDir)) {
    throw new Error('Missing onboarding public artifacts. Run org:init-service first.');
  }

  const didDoc = readJson(didPath);
  const orgProfilePath = path.join(orgRoot, 'onboarding', 'state', 'organization-profile.json');
  const orgProfile = existsSync(orgProfilePath) ? readJson(orgProfilePath) : null;
  const manifest = {
    schema: 'gdc-onboarding-submission-v1',
    requestId,
    icaDomain,
    createdAt: new Date().toISOString(),
    organizationDid: didDoc.id,
    organizationSector: orgProfile?.sector || null,
    bundleContents: [
      '.well-known/**',
      'pki/**/*.csr.pem',
      'employee/**',
      'onboarding/state/**',
      'evidence/terms-fnmt-signed.pdf (optional)',
    ],
  };
  const manifestPath = path.join(orgRoot, 'onboarding', 'state', `submission-${requestId}.json`);
  writeJson(manifestPath, manifest);

  const includeEntries = ['.well-known', 'pki', 'employee', 'onboarding/state'];
  if (existsSync(path.join(orgRoot, 'evidence', 'terms-fnmt-signed.pdf'))) {
    includeEntries.push('evidence/terms-fnmt-signed.pdf');
  }

  try {
    execFileSync('tar', ['-czf', outPath, ...includeEntries], { cwd: orgRoot, stdio: 'pipe' });
  } catch (error) {
    const stderr = error?.stderr?.toString?.() || error?.message || 'unknown error';
    throw new Error(`tar failed: ${stderr}`);
  }

  console.log(`Wrote bundle: ${outPath}`);
}

async function main() {
  const [, , command, ...rest] = process.argv;
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return;
  }
  const args = parseArgs(rest);

  switch (command) {
    case 'domain:precheck':
      await cmdDomainPrecheck(args);
      return;
    case 'org:init-service':
      await cmdOrgInitService(args);
      return;
    case 'org:add-controller':
      await cmdOrgAddController(args);
      return;
    case 'org:recover-service':
      await cmdOrgRecoverService(args);
      return;
    case 'org:recover-controller':
      await cmdOrgRecoverController(args);
      return;
    case 'org:derive-pontusx':
      await cmdOrgDerivePontusx(args);
      return;
    case 'vp:sign':
      await cmdVpSign(args);
      return;
    case 'submission:pack':
      await cmdSubmissionPack(args);
      return;
    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
