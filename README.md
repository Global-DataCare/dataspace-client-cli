# dataspace-client-cli (public)

CLI público para onboarding de organizaciones en producción.

Las reglas de alcance, custodia, autoridad y validación están enlazadas desde
[`docs/RULES_INDEX.md`](docs/RULES_INDEX.md).

Todos los artefactos generados por el CLI se escriben bajo:
- `output/did_web_<subdomain>.globaldatacare.es/`

## Requisitos

- Node.js 22+
- OpenSSL en `PATH`

## Instalación

```bash
npm install
```

## Suites criptográficas (estado actual y objetivo)

Estado actual en este CLI:
- Firma/JWKS/DID: `ES-384` (`ECDSA P-384`, `crv: P-384`) + `ES256K` (`secp256k1`).
- CSR/X.509: `ES-384` (`ECDSA P-384`, curva `secp384r1`, `crv: P-384`).
- Certificados X.509 emitidos por ICA: cadena basada en `P-384`.
- Perfil operativo actual: legacy-compliant para integración principal de investigación con SMART-on-FHIR y perfiles compatibles Gaia-X.
- Esta implementación no incluye mensajería post-cuántica (ni transporte híbrido PQ) en producción.

Compatibilidad objetivo (pendiente de implementación en este CLI):
- `ML-DSA` (firma post-cuántica).
- `ML-KEM` (encapsulación/establecimiento de secreto post-cuántico).
- Extensiones multi-suite adicionales según perfiles de red.

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
- Formato de scope (`--sector`):
  `<service-category>:<membership-profile>`, por ejemplo
  `health-care:provider` o `animal-research:reader`. Una categoría sin perfil
  utiliza `provider`; las allowlists concretas pertenecen al despliegue.

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
  --sector health-research:provider \
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

6. Derivación/reconstrucción Pontus-X (ES256K/secp256k1, opcional)

```bash
node ./bin/client-cli.js org:derive-pontusx \
  --domain api-orgdemo.globaldatacare.es \
  --passkey "PASSKEY_SERVICIO" \
  [--replace-pontusx]
```

Notas:
- `org:init-service` ya genera ES384 + ES256K en el `/.well-known/jwks.json`.
- Sin flags extra, este comando es aditivo (inserta/actualiza por `kid`).
- Con `--replace-pontusx`, rota ES256K: elimina referencias Pontus-X previas en `jwks.json` y `did.json` y deja solo la nueva.
- Si no pasas `--salt`, usa el salt de `onboarding/state/service-kdf.json`.

## Rotación (política para todas las claves)

Esta política aplica a todas las suites publicadas en JWKS/DID (ES384, ES256K y futuras PQ):

- Sin rotación (`append/update`):
  Se añade la nueva clave (o se actualiza por `kid` si coincide). La clave anterior permanece activa/publicada.
- Con rotación (`replace`):
  La nueva clave pasa a ser la única activa para esa suite/uso; las anteriores se retiran del set activo.

Regla operacional con ICA:

1. Generar nueva clave localmente y su CSR (si requiere X.509 para Gaia-X/Federation).
2. Solicitar challenge de rotación a ICA.
3. Firmar challenge con clave antigua (continuidad) y con clave nueva (proof-of-possession).
4. Enviar a ICA: CSR, pruebas de challenge, metadatos de rotación y expediente legal.
5. ICA valida pruebas y emite certificado de la nueva clave.
6. Publicación:
   - Fase de transición: mantener antigua + nueva en `jwks.json`/`did.json` durante ventana corta.
   - Fase final: retirar antigua del set activo tras confirmación de emisión/propagación.

¿Hay que pedir firma a ICA al rotar?
- Sí, para cualquier clave que deba publicarse con cadena de confianza X.509 (`x5c`) en Gaia-X/OpenID Federation.

¿Deben permanecer las antiguas en `jwks.json`?
- Sí, temporalmente (grace period) para evitar cortes.
- No, de forma indefinida: deben retirarse del set activo al cerrar la rotación.

¿Es obligatorio challenge con clave antigua?
- Recomendado por defecto para continuidad criptográfica.
- Si la clave antigua está comprometida o perdida, ICA debe pasar a flujo excepcional (manual/legal + revocación explícita).

Estado actual en este CLI:
- Rotación `replace` implementada explícitamente para ES256K (Pontus-X) con `org:derive-pontusx --replace-pontusx`.
- Claves de controlador (empleado) se pueden renovar re-ejecutando `org:add-controller` para el mismo `email+role`.
- La política anterior se considera obligatoria para cualquier suite adicional que se active en producción.

7. Empaquetar envío a ICA (incluye CSR y evidencias)

```bash
node ./bin/client-cli.js submission:pack \
  --request-id req-2026-0001 \
  --ica-domain onehealth-ica.accuro.es \
  --domain api-orgdemo.globaldatacare.es \
  --terms-pdf /ruta/terminos-firmados-fnmt.pdf \
  --out submission-req-2026-0001.tgz
```

Notas:
- `--domain` en `submission:pack` es opcional si existe un solo `output/did_web_*` en el repositorio.
- Si hay varios outputs, `--domain` es obligatorio.

## Envío a ICA por Signed URL (GCS)

Sin servicio ICA activo, el envío se hace con URL firmada temporal emitida por la ICA:

- La organización no necesita API key ni credenciales GCP.
- La URL suele venir con caducidad de `24h` (ampliable a `48h` para onboarding manual).

Subida del bundle:

```bash
export REQUEST_ID="req-2026-0001"
export DOMAIN="api-orgdemo.globaldatacare.es"
export BUNDLE="./output/did_web_${DOMAIN}/submission-${REQUEST_ID}.tgz"
export SIGNED_URL="<URL_FIRMADA_POR_ICA>"

curl -X PUT \
  -H "Content-Type: application/gzip" \
  --upload-file "$BUNDLE" \
  "$SIGNED_URL"
```

Después de subir:
- Guarda evidencia local del hash del bundle enviado.
- Espera acuse de recibo de ICA (estado `ingested/validated/approved`).

## Secuencia exacta (qué se crea y en qué orden)

Todos los paths de esta sección son relativos a `output/did_web_<domain>/`.

1. `org:init-service` (cliente)
- Deriva clave de servicio con `passkey + salt_autogenerado + scrypt`.
- Tipo de claves que genera hoy: `ES-384 / P-384` + `ES256K / secp256k1`.
- Genera `/.well-known/jwks.json` (ambas claves públicas de servicio).
- Construye `/.well-known/did.json` base usando esas claves de `jwks.json`.
- Emite `/.well-known/vc.json` (autofirmada por la organización).
- Genera `pki/<domain>.csr.pem` para firma ICA.

2. `org:add-controller` (cliente)
- Deriva clave del controlador con otra `passkey + salt_autogenerado + scrypt`.
- Tipo de clave que genera hoy: `ES-384 / P-384`.
- Calcula `employee_id` público (multibase) y su `employee DID`.
- Añade el controlador al `/.well-known/did.json` de la organización.
- Genera `employee/multibase/z<id>/{did.json,jwks.json,vc.json}`.
- Genera `pki/employee-z<id>.csr.pem`.

3. `org:derive-pontusx` (cliente, opcional de recuperación/migración/rotación)
- Deriva clave `ES256K/secp256k1` con separación de contexto para Pontus-X.
- Modo por defecto: añade/actualiza por `kid` en `/.well-known/jwks.json`.
- Con `--replace-pontusx`: rota clave, eliminando otras ES256K Pontus-X previas en JWKS y DID.

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
output/
└── did_web_<domain>/
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
        ├── service-pontusx/
        └── controllers/
```

## Notas

- En onboarding (`org:init-service`, `org:add-controller`) el salt se autogenera siempre.
- `org:init-service` requiere `--sector` como scope `canal:tipo` (también acepta alias `--category`).
- `domain:precheck` es conservador: solo marca libre cuando todas las consultas DNS dan no-data/not-found de forma consistente.
- La disponibilidad final debe confirmarse con reserva transaccional en ICA (`domain:reserve`).
- Para regenerar usa `org:recover-service` y `org:recover-controller` con `passkey + salt + scrypt`.
- `org:derive-pontusx` deriva/reconstruye `ES256K/secp256k1` para compatibilidad Pontus-X.
- El JWKS canónico servido es `/.well-known/jwks.json` (incluye todas las claves activas).
- `vp_token` no se publica en el repositorio público.
- `x5c` en JWKS se añade después de firma ICA del CSR.
