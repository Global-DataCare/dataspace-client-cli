# dataspace-client-cli (public)

CLI público para onboarding de organizaciones en producción.

## Requisitos

- Node.js 22+
- OpenSSL en `PATH`

## Instalación

```bash
npm install
```

## Suites criptográficas (estado actual y objetivo)

Estado actual en este CLI:
- Firma/JWKS/DID/CSR: `ES-384` (`ECDSA P-384`, curva `secp384r1`, `crv: P-384`).
- Certificados X.509 emitidos por ICA: cadena basada en `P-384`.
- Perfil operativo actual: legacy-compliant para integración principal de investigación con SMART-on-FHIR y perfiles compatibles Gaia-X.
- Esta implementación no incluye mensajería post-cuántica (ni transporte híbrido PQ) en producción.

Compatibilidad objetivo (pendiente de implementación en este CLI):
- `ML-DSA` (firma post-cuántica).
- `ML-KEM` (encapsulación/establecimiento de secreto post-cuántico).
- `ES256K / secp256k1` para otros perfiles además de Pontus-X.

## Contrato de IDs (fijo)

- ID interno (no público):
  `did:web:<subdomain>.globaldatacare.es:employee:<email_norm>:<role_isco4>`
- ID público:
  `z<base58btc(SHA-256(employee_id_interno))>`
- DID público:
  `did:web:<subdomain>.globaldatacare.es:employee:multibase:<employee_id_publico>`

## Perfil scrypt (fijo por defecto)

- Formato: `<log2N>:<r>:<p>:<dkLen>`
- Default: `17:8:1:48` (N = 2^17 = 131072)
- Sectores soportados:
  `health-care`, `health-tech`, `animal-care`, `animal-breed`, `onehealth-research`, `health-research`, `vet-research`

## Flujo de comandos

1. Precheck DNS

```bash
node ./bin/client-cli.js domain:precheck \
  --domain api-orgdemo.globaldatacare.es
```

2. Paso A: servicio organización (clave + DID + JWKS + VC + CSR, con salt autogenerado)

```bash
node ./bin/client-cli.js org:init-service \
  --domain api-orgdemo.globaldatacare.es \
  --legal-name "Org Demo" \
  --tax-id B00000000 \
  --country ES \
  --sector health-care \
  --scrypt 17:8:1:48 \
  --passkey "PASSKEY_SERVICIO"
```

3. Paso B: controlador/representante (clave + DID público multibase + VC + CSR, con salt autogenerado)

```bash
node ./bin/client-cli.js org:add-controller \
  --domain api-orgdemo.globaldatacare.es \
  --email "representante@orgdemo.globaldatacare.es" \
  --role-isco 1219 \
  --scrypt 17:8:1:48 \
  --passkey "PASSKEY_CONTROLADOR"
```

4. VP token para onboarding ICA (efímero)

```bash
node ./bin/client-cli.js vp:sign \
  --domain api-orgdemo.globaldatacare.es \
  --email "representante@orgdemo.globaldatacare.es" \
  --role-isco 1219 \
  --aud did:web:onehealth-ica.accuro.es \
  --nonce onboarding-2026-02-19-001 \
  --exp-seconds 300
```

5. Regeneración de claves privadas (usa passkey + salt + perfil scrypt)

```bash
node ./bin/client-cli.js org:recover-service \
  --domain api-orgdemo.globaldatacare.es \
  --scrypt 17:8:1:48 \
  --passkey "PASSKEY_SERVICIO" \
  --salt "a1b2c3d4e5f60718293a4b5c6d7e8f90"

node ./bin/client-cli.js org:recover-controller \
  --domain api-orgdemo.globaldatacare.es \
  --email "representante@orgdemo.globaldatacare.es" \
  --role-isco 1219 \
  --scrypt 17:8:1:48 \
  --passkey "PASSKEY_CONTROLADOR" \
  --salt "00112233445566778899aabbccddeeff"
```

6. Derivación Pontus-X (ES256K/secp256k1)

```bash
node ./bin/client-cli.js org:derive-pontusx \
  --domain api-orgdemo.globaldatacare.es \
  --passkey "PASSKEY_SERVICIO"
```

Notas:
- Si no pasas `--salt`, usa el salt de `onboarding/state/service-kdf.json`.
- Añade la clave `ES256K/secp256k1` al `/.well-known/jwks.json` principal y agrega la `verificationMethod` al `did.json`.

7. Empaquetar envío a ICA (incluye CSR y evidencias)

```bash
node ./bin/client-cli.js submission:pack \
  --request-id req-2026-0001 \
  --ica-domain onehealth-ica.accuro.es \
  --terms-pdf /ruta/terminos-firmados-fnmt.pdf \
  --out submission-req-2026-0001.tgz
```

## Secuencia exacta (qué se crea y en qué orden)

1. `org:init-service` (cliente)
- Deriva clave de servicio con `passkey + salt_autogenerado + scrypt`.
- Tipo de clave que genera hoy: `ES-384 / P-384`.
- Genera `/.well-known/jwks.json` (clave pública de servicio).
- Construye `/.well-known/did.json` base usando esa clave de `jwks.json`.
- Emite `/.well-known/vc.json` (autofirmada por la organización).
- Genera `pki/<domain>.csr.pem` para firma ICA.

2. `org:add-controller` (cliente)
- Deriva clave del controlador con otra `passkey + salt_autogenerado + scrypt`.
- Tipo de clave que genera hoy: `ES-384 / P-384`.
- Calcula `employee_id` público (multibase) y su `employee DID`.
- Añade el controlador al `/.well-known/did.json` de la organización.
- Genera `employee/multibase/z<id>/{did.json,jwks.json,vc.json}`.
- Genera `pki/employee-z<id>.csr.pem`.

3. `org:derive-pontusx` (cliente, opcional según ecosistema)
- Deriva clave `ES256K/secp256k1` con separación de contexto para Pontus-X.
- Añade la clave al `/.well-known/jwks.json` principal.
- Añade su `verificationMethod` al `/.well-known/did.json`.

4. `submission:pack` (cliente)
- Empaqueta `.well-known`, `pki/*.csr.pem`, `employee/*`, `onboarding/state/*`, y evidencias.

5. `csr:sign-batch` (ICA, repo privado)
- Firma los CSR de organización/controlador.
- Devuelve certificados y cadena en `pki/*.pem` y `*.chain.pem`.
- Inserta `x5c` en los `jwks.json` publicados (org y empleado).

6. Publicación DCAT (ICA, repo público ICA)
- Cuando la URL API ya está activa/resoluble, ICA publica:
  `dsp/dcat3/animal-index/*.jsonld` + `.sha256` + `.sig`
  y `dsp/dcat3/catalog.jsonld` + `.sha256` + `.sig`.

## Estructura de salida

```text
.
├── .well-known/
│   ├── did.json
│   ├── jwks.json
│   ├── vc.json
│   └── openid-configuration
├── employee/
│   └── multibase/
│       └── z<employeeId>/
│           ├── did.json
│           ├── jwks.json
│           └── vc.json
├── pki/
│   ├── <domain>.csr.pem
│   └── employee-z<employeeId>.csr.pem
├── onboarding/
│   └── state/
│       ├── domain-precheck.json
│       ├── service-kdf.json
│       ├── pontusx-kdf.json
│       ├── controller-z<employeeId>-kdf.json
│       └── submission-<request-id>.json
├── evidence/
│   └── terms-fnmt-signed.pdf
└── .private/        # ignorado por git
    ├── service/
    └── controllers/
```

## Notas

- En onboarding (`org:init-service`, `org:add-controller`) el salt se autogenera siempre.
- `org:init-service` requiere `--sector` (también acepta alias `--category`).
- Para regenerar usa `org:recover-service` y `org:recover-controller` con `passkey + salt + scrypt`.
- `org:derive-pontusx` deriva `ES256K/secp256k1` para compatibilidad Pontus-X.
- El JWKS canónico servido es `/.well-known/jwks.json` (incluye todas las claves activas).
- `vp_token` no se publica en el repositorio público.
- `x5c` en JWKS se añade después de firma ICA del CSR.
