# Seccion 9: OAuth 2.0 Authorization Server

> Notas del curso de Spring Security 6 — De JWT manual a un servidor de autorizacion OAuth2 profesional con Spring Authorization Server

---

## Objetivo de la seccion

Convertir la aplicacion en un **Authorization Server + Resource Server** OAuth2 completo, reemplazando el JWT manual (seccion 8) por el estandar de la industria:

- Configurar **Spring Authorization Server** con flujo `authorization_code`
- Crear clientes OAuth2 (`partners`) almacenados en BD
- Generar llaves **RSA** (asimetricas) en vez de HMAC (simetrico)
- Implementar **dos SecurityFilterChains** con `@Order` (una para OAuth2, otra para recursos)
- Personalizar el **access token JWT** con claims custom (roles, owner)
- Configurar la app como **Resource Server** que valida sus propios tokens

---

## Fundamentos Teoricos de OAuth 2.0

### ¿Que problema resuelve OAuth2?

Imagina este escenario: tienes una app de edicion de fotos que necesita acceder a las fotos de Google Drive del usuario. Sin OAuth2, la unica forma seria:

```
Usuario: "Aqui tienes mi email y password de Google, accede a mis fotos"
App:     Guarda las credenciales → Login en Google → Accede a todo
```

Esto es terrible porque:
- La app tiene **acceso total** a la cuenta de Google (no solo fotos, tambien emails, contactos, etc.)
- Si la app es hackeada, el atacante tiene las **credenciales completas** del usuario
- El usuario **no puede revocar** el acceso sin cambiar su password (afectando todas las apps)
- No hay forma de dar acceso **temporal** o **limitado**

OAuth2 resuelve esto con un concepto simple: **autorizacion delegada**. En vez de dar tus credenciales, das un **permiso limitado y revocable**.

```
SIN OAuth2:                              CON OAuth2:
┌────────────┐                           ┌────────────┐
│   App de   │  "Dame tu password"       │   App de   │  "Necesito ver tus fotos"
│   fotos    │──────────────────►        │   fotos    │─────────────────────────►
│            │                           │            │
│  Tiene tu  │                           │  Tiene un  │
│  PASSWORD  │  ← Acceso TOTAL          │   TOKEN    │  ← Solo acceso a fotos
│            │  ← Para SIEMPRE          │            │  ← Expira en 8 horas
│            │  ← NO revocable          │            │  ← Revocable en cualquier momento
└────────────┘                           └────────────┘
```

### Analogia: La Tarjeta de Hotel

La mejor forma de entender OAuth2 es con una analogia:

```
TU (huesped)           = Resource Owner  (dueño del recurso)
TUS PERTENENCIAS       = Recursos protegidos (fotos, cuentas, datos)
EL HOTEL               = Authorization Server (quien emite tarjetas)
LA TARJETA MAGNETICA   = Access Token (permiso temporal y limitado)
EL CUARTO              = Resource Server (donde estan los recursos)

Flujo:
1. Llegas al hotel y te IDENTIFICAS (login con credenciales)
2. El hotel VERIFICA tu identidad
3. El hotel te da una TARJETA MAGNETICA que:
   - Solo abre TU cuarto (scope limitado)
   - Expira al final de tu estadia (tiempo de vida)
   - Puede ser DESACTIVADA por el hotel en cualquier momento (revocable)
   - NO contiene tu informacion personal (seguridad)
4. Usas la tarjeta para acceder a tu cuarto

Tu NUNCA le das tu pasaporte al cuarto. El cuarto solo necesita
ver que la tarjeta es valida — no necesita saber quien eres.
```

### OAuth 2.0 NO es autenticacion

Esta es una confusion muy comun. Es importante entender la diferencia:

| Concepto | Pregunta que responde | Ejemplo |
|---|---|---|
| **Autenticacion** (AuthN) | ¿**Quien** eres? | Login con email + password → "Eres Oscar" |
| **Autorizacion** (AuthZ) | ¿**Que** puedes hacer? | "Oscar puede leer cuentas pero no borrarlas" |

**OAuth 2.0 es un protocolo de AUTORIZACION**, no de autenticacion. Su objetivo es responder: "¿Esta app tiene permiso para acceder a estos recursos en nombre de este usuario?"

OAuth2 por si solo **no te dice quien es el usuario**. Para eso existe **OpenID Connect (OIDC)**, que es una capa sobre OAuth2 que agrega autenticacion (identidad del usuario).

```
┌─────────────────────────────────────────────┐
│              OpenID Connect (OIDC)           │
│         "¿Quien es el usuario?"              │
│         → ID Token con datos del usuario     │
│                                              │
│  ┌────────────────────────────────────────┐  │
│  │           OAuth 2.0                    │  │
│  │    "¿Que puede hacer esta app?"        │  │
│  │    → Access Token con permisos         │  │
│  └────────────────────────────────────────┘  │
└─────────────────────────────────────────────┘

OIDC = OAuth2 + capa de identidad
```

### Los 4 Roles de OAuth2

OAuth2 define exactamente 4 actores en cada interaccion:

**1. Resource Owner (Dueño del recurso)**
- Es el **usuario final** (la persona humana)
- Posee los datos/recursos que una app quiere acceder
- Es quien **autoriza o deniega** el acceso
- Ejemplo: tu, cuando Google te pregunta "¿Quieres permitir que esta app vea tus fotos?"

**2. Client (Cliente / Aplicacion)**
- Es la **aplicacion** que quiere acceder a los recursos del usuario
- NO es el usuario — es el software (una web app, una app movil, un CLI)
- Tiene su propio `client_id` y `client_secret` para identificarse ante el Auth Server
- En nuestro proyecto: el partner `debuggeandoideas` es un Client

**3. Authorization Server (Servidor de Autorizacion)**
- Es el **intermediario de confianza** que emite tokens
- Autentica al usuario (login)
- Autentica al cliente (verifica client_id + client_secret)
- Emite access tokens, refresh tokens e ID tokens
- Expone endpoints estandar: `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`
- En nuestro proyecto: nuestra app Spring con `@Order(1)`

**4. Resource Server (Servidor de Recursos)**
- Es el **servidor que tiene los recursos protegidos** (APIs, datos)
- Recibe requests con un access token y **valida** que sea legitimo
- NO emite tokens — solo los valida
- En nuestro proyecto: nuestra misma app Spring con `@Order(2)` (endpoints `/accounts`, `/loans`, etc.)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│   Resource Owner ──────── "Yo autorizo"                                  │
│        │                                                                 │
│        │ se autentica                                                    │
│        ▼                                                                 │
│   Authorization Server ── "Yo emito tokens"                              │
│        │                                                                 │
│        │ emite token                                                     │
│        ▼                                                                 │
│   Client ─────────────── "Yo uso el token para pedir recursos"           │
│        │                                                                 │
│        │ presenta token                                                  │
│        ▼                                                                 │
│   Resource Server ─────── "Yo valido el token y entrego el recurso"      │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

> **Nota:** En nuestro proyecto, el Authorization Server y el Resource Server son la **misma aplicacion Spring** (pero con dos `SecurityFilterChain` separadas). En produccion es comun que sean apps diferentes.

### Tokens: La Moneda de OAuth2

OAuth2 trabaja con diferentes tipos de tokens. Cada uno tiene un proposito especifico:

**Access Token (Token de acceso)**
- Es el token **principal** — lo que el client usa para acceder a recursos protegidos
- Se envia en cada request: `Authorization: Bearer eyJhbG...`
- Tiene **vida corta** (minutos u horas) — en nuestro proyecto: 8 horas
- Contiene **claims**: informacion como el usuario, los scopes, los roles, la expiracion
- Puede ser un JWT (como en nuestro caso) o un token opaco
- Si se compromete, el daño es limitado porque expira pronto

**Refresh Token (Token de actualizacion)**
- Sirve para **obtener un nuevo access token** sin que el usuario haga login de nuevo
- Tiene **vida larga** (dias o semanas)
- Se guarda de forma segura en el backend — nunca se envia a la API de recursos
- El flujo: access token expira → client usa refresh token → Auth Server emite nuevo access token

**ID Token (Token de identidad) — solo con OIDC**
- Contiene informacion sobre la **identidad del usuario** (nombre, email, etc.)
- Es siempre un JWT
- Lo usa el Client para saber quien es el usuario, NO para acceder a recursos

```
┌──────────────────────────────────────────────────────────────────────┐
│                          TOKENS                                      │
│                                                                      │
│  Access Token          Refresh Token          ID Token (OIDC)        │
│  ┌────────────┐        ┌────────────┐        ┌────────────┐         │
│  │ sub: oscar │        │            │        │ name: Oscar│         │
│  │ scope: read│        │ (opaco)    │        │ email: ... │         │
│  │ roles: ADM │        │            │        │ picture: ..│         │
│  │ exp: 8hrs  │        │ exp: 30d   │        │ exp: 1hr   │         │
│  └────────────┘        └────────────┘        └────────────┘         │
│                                                                      │
│  ¿Para que?            ¿Para que?            ¿Para que?              │
│  Acceder a APIs        Renovar el            Saber QUIEN             │
│  protegidas            access token          es el usuario           │
│                        sin re-login                                   │
│                                                                      │
│  ¿Quien lo usa?        ¿Quien lo usa?        ¿Quien lo usa?         │
│  Client → Resource     Client → Auth         Client (frontend)      │
│  Server                Server                                        │
│                                                                      │
│  ¿Vida?                ¿Vida?                ¿Vida?                  │
│  Corta (min/hrs)       Larga (dias)          Corta (min/hrs)         │
└──────────────────────────────────────────────────────────────────────┘
```

### Scopes: Permisos Granulares

Los scopes definen **que puede hacer** un client con el access token. Son como permisos granulares:

```
Sin scopes:
  Token → acceso a TODO (fotos, emails, contactos, calendar...)

Con scopes:
  Token [scope: photos.read] → solo puede LEER fotos
  Token [scope: photos.read photos.write] → puede leer Y escribir fotos
  Token [scope: email] → solo puede ver el email del usuario
```

En nuestro proyecto definimos dos scopes: `read` y `write`. El partner `debuggeandoideas` tiene ambos.

Los scopes se piden al momento de solicitar autorizacion y el usuario puede aceptar o rechazar:

```
┌──────────────────────────────────────────┐
│  "debuggeando ideas" quiere acceder a    │
│   tu cuenta:                             │
│                                          │
│   [x] Leer tus datos (read)             │
│   [x] Modificar tus datos (write)       │
│                                          │
│          [Autorizar]  [Cancelar]         │
└──────────────────────────────────────────┘
         ↑ Pantalla de consentimiento
```

### Clientes Confidenciales vs Publicos

No todas las apps son iguales. OAuth2 distingue dos tipos de clientes segun su capacidad de guardar secretos:

| Tipo | ¿Puede guardar un secreto? | Ejemplos | Autenticacion |
|---|---|---|---|
| **Confidencial** | Si — el codigo vive en un servidor seguro | Backend web (Spring, Django, Rails), servicios internos | `client_id` + `client_secret` |
| **Publico** | No — el codigo es visible para el usuario | Apps moviles, SPA (React, Angular), apps de escritorio | Solo `client_id` + PKCE |

```
Confidencial:                           Publico:
┌─────────────────┐                     ┌─────────────────┐
│  Backend Server │                     │  App en el      │
│                 │                     │  navegador      │
│  client_secret  │ ← Seguro,          │                 │ ← El usuario puede
│  guardado en    │   nadie lo ve      │  client_secret  │   abrir DevTools
│  el servidor    │                     │  ??? NO SEGURO  │   y ver el secreto
└─────────────────┘                     └─────────────────┘

Solucion para publicos: PKCE (Proof Key for Code Exchange)
→ Genera un "code_verifier" aleatorio por cada request
→ No necesita client_secret
```

En nuestro proyecto, el partner usa `client_secret_basic` (envia client_id + client_secret en un header Basic Auth), asi que es un **cliente confidencial**.

### OAuth2 vs OIDC vs SAML — ¿Cual es cual?

| Protocolo | Tipo | Que hace | Formato del token | Uso tipico |
|---|---|---|---|---|
| **OAuth 2.0** | Autorizacion | "¿Esta app puede acceder a estos recursos?" | Access Token (JWT u opaco) | APIs, microservicios |
| **OpenID Connect (OIDC)** | Autenticacion + Autorizacion | OAuth2 + "¿Quien es el usuario?" | Access Token + ID Token (JWT) | Login con Google/GitHub, SSO |
| **SAML 2.0** | Autenticacion | "¿Quien es el usuario?" (empresarial) | XML assertion | SSO corporativo (Active Directory) |

OIDC es lo que usamos en esta seccion (habilitamos OIDC con `.oidc(Customizer.withDefaults())`). Spring Authorization Server soporta ambos.

### El Flujo Authorization Code — Paso a Paso Conceptual

El `authorization_code` es el flujo **mas seguro y recomendado** de OAuth2. Se llama asi porque usa un **codigo intermedio** que luego se intercambia por tokens.

¿Por que un codigo intermedio y no enviar el token directamente? **Seguridad:**

```
SIN codigo intermedio (flujo implicito — OBSOLETO):
  Auth Server ──redirect──► Client (en la URL: token=eyJ...)
  ⚠ El token viaja en la URL → visible en logs, historial, referer headers

CON codigo intermedio (authorization_code):
  Auth Server ──redirect──► Client (en la URL: code=abc123)
  Client ──POST secreto──► Auth Server (code + client_secret → token)
  ✓ El token NUNCA viaja en la URL
  ✓ El code es de un solo uso y expira en segundos
  ✓ El intercambio requiere client_secret (solo el backend lo tiene)
```

Flujo completo conceptual:

```
  Paso 1: El Client redirige al usuario al Auth Server
          "Oye Auth Server, necesito acceso de lectura para este usuario"

  Paso 2: El Auth Server muestra el login
          "Usuario, ¿quien eres? Ingresa email y password"

  Paso 3: El usuario se autentica
          Auth Server valida credenciales contra la BD

  Paso 4: El Auth Server muestra la pantalla de consentimiento
          "Usuario, ¿autorizas a 'debuggeando ideas' a leer tus datos?"

  Paso 5: El usuario acepta

  Paso 6: El Auth Server redirige al Client con un CODIGO temporal
          redirect → https://client.com/callback?code=abc123

  Paso 7: El Client intercambia el codigo por tokens (server-to-server)
          POST /oauth2/token
          code=abc123 + client_id + client_secret
          → Auth Server responde con access_token + refresh_token

  Paso 8: El Client usa el access_token para acceder a recursos
          GET /accounts  |  Authorization: Bearer eyJ...
```

---

## Flujo General de OAuth 2.0

```
 Aplicacion Cliente                                        Dueño del recurso
 ┌─────────────────┐     1. Peticion del cliente           ┌──────────────┐
 │    ┌───┐  ┌───┐ │────────────────────────────────────► │              │
 │    │www│  │app│ │                                       │   Usuario    │
 │    └───┘  └───┘ │     2. Autorizacion                  │  (Resource   │
 │                 │◄────────────────────────────────────  │   Owner)     │
 │                 │                                       └──────────────┘
 │                 │
 │                 │     3. ¿Es un usuario valido?         ┌──────────────┐
 │                 │────────────────────────────────────► │  Servidor de │
 │                 │                                       │ autorizacion │
 │                 │     4. Token de acceso                │  (Auth       │
 │                 │◄────────────────────────────────────  │   Server)    │
 │                 │                                       └──────────────┘
 │                 │
 │                 │     5. Token de acceso                ┌──────────────┐
 │                 │────────────────────────────────────► │  Servidor de │
 │                 │                                       │  recursos    │
 │                 │     6. Recurso protegido              │  (Resource   │
 │                 │◄────────────────────────────────────  │   Server)    │
 └─────────────────┘                                       └──────────────┘
```

**Actores clave:**

| Actor | Rol |
|---|---|
| **Aplicacion Cliente** | La app (web, movil, etc.) que necesita acceder a recursos protegidos |
| **Dueño del recurso** | El usuario final que autoriza el acceso a sus datos |
| **Servidor de autorizacion** | Valida credenciales del usuario y emite tokens de acceso |
| **Servidor de recursos** | Posee los recursos protegidos, valida el token antes de responder |

---

## Ubicacion en la Arquitectura

```
                                      ┌──────────────────────────────────┐
                                      │   Authorization Server           │
  Partner/Client                      │   (SecurityFilterChain @Order 1) │
  (app externa)                       │                                  │
       │                              │  /oauth2/authorize               │
       │ 1. Redirige al login         │  /oauth2/token                   │
       │───────────────────────────►  │  /oauth2/jwks                    │
       │                              │  /.well-known/openid-config      │
       │ 4. Recibe authorization_code │                                  │
       │◄──────────────────────────── │  Firma tokens con RSA privada    │
       │                              └──────────────────────────────────┘
       │
       │ 5. Intercambia code por access_token
       │ 6. Usa access_token para llamar endpoints
       │
       │  GET /accounts                ┌──────────────────────────────────┐
       │  Authorization: Bearer eyJ... │   Resource Server                │
       │───────────────────────────►   │   (SecurityFilterChain @Order 2) │
       │                               │                                  │
       │                               │  Valida JWT con RSA publica      │
       │                               │  hasRole("ADMIN") → revisa claims│
       │                               │  → Controller                    │
       │◄──────────────────────────── │                                  │
       │  {"msj": "accounts"}          └──────────────────────────────────┘
```

Esta seccion es la culminacion de todo el diagrama maestro (ver Seccion 1). Spring Authorization Server encapsula los 10 pasos internamente: los filtros OAuth2 manejan la autenticacion del usuario, la emision de tokens, y la validacion — todo con estandares abiertos.

---

## 1. ¿Por que OAuth2? — JWT Manual vs Authorization Server

### El problema del JWT manual (seccion 8)

| Problema | Detalle |
|---|---|
| **Protocolo propio** | El endpoint `/authenticate` no sigue ningun estandar. Cada app inventa su flujo |
| **HMAC simetrico** | La misma clave firma Y valida. Si tienes multiples servicios, todos necesitan la clave secreta |
| **Sin discovery** | Los clientes deben saber la URL exacta del endpoint de login |
| **Sin refresh tokens** | Cuando el token expira, el usuario debe re-autenticarse completamente |
| **Sin scopes** | No hay forma de limitar lo que un token puede hacer |

### La solucion: OAuth 2.0 Authorization Server

| Beneficio | Detalle |
|---|---|
| **Protocolo estandar** | Flujos definidos (authorization_code, client_credentials, refresh_token). Cualquier cliente OAuth2 lo entiende |
| **RSA asimetrico** | La clave privada firma, la clave publica valida. Los Resource Servers solo necesitan la publica |
| **Discovery automatico** | `/.well-known/openid-configuration` expone todos los endpoints automaticamente |
| **Refresh tokens** | El cliente obtiene un nuevo access_token sin pedir credenciales al usuario |
| **Scopes** | `read`, `write` — limita lo que cada cliente puede hacer |
| **OIDC** | OpenID Connect: ademas de autorizacion, provee identidad del usuario |

### Grant Types (tipos de concesion)

OAuth2 define diferentes flujos segun el tipo de cliente y caso de uso:

| Grant Type | Descripcion |
|---|---|
| **Authorization Code** | Los clientes confidenciales y publicos intercambian un **codigo de autorizacion** por un token de acceso. Es el flujo mas seguro y el que usamos en esta seccion |
| **PKCE** (RFC 7636) | Extension del flujo Authorization Code para **evitar ataques de inyeccion de codigo** de autorizacion y CSRF. Recomendado para apps publicas (SPA, moviles) |
| **Client Credentials** | El cliente obtiene un token de acceso **fuera del contexto de un usuario**. Para comunicacion servidor-a-servidor (no hay usuario involucrado) |
| **Device Code** | Para dispositivos **sin navegador o de entrada restringida** (Smart TV, CLI). El usuario autoriza en otro dispositivo con navegador |
| **Refresh Token** | Intercambia un **token de actualizacion** por un nuevo access token cuando este ha caducado, sin re-autenticar al usuario |

> En esta seccion implementamos `authorization_code` + `refresh_token`. El partner tiene ambos configurados en su campo `grant_types`.

---

## 2. Nuevas Dependencias

### `pom.xml`

```xml
<!-- Authorization Server: convierte tu app en un emisor de tokens OAuth2 -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>1.1.1</version>
</dependency>

<!-- Resource Server: permite validar tokens JWT (Bearer) en requests entrantes -->
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
    <version>6.1.2</version>
</dependency>
```

**Se eliminaron** las 3 dependencias de `jjwt`. Spring Authorization Server usa **Nimbus JOSE + JWT** internamente (viene incluido como dependencia transitiva).

---

## 3. Nueva Tabla: `partners` (Clientes OAuth2)

### Concepto

En OAuth2, un **client** (o "partner") es una **aplicacion externa** que quiere acceder a recursos protegidos en nombre de un usuario. Cada client tiene su propio ID, secreto, permisos, y URLs de redireccion.

### SQL: `create_schema.sql` (nueva tabla)

```sql
create table partners (
    id                    bigserial primary key,
    client_id             varchar(256),    -- Identificador unico del client
    client_name           varchar(256),    -- Nombre legible
    client_secret         varchar(256),    -- Secreto (BCrypt)
    scopes                varchar(256),    -- "read,write"
    grant_types           varchar(256),    -- "authorization_code,refresh_token"
    authentication_methods varchar(256),   -- "client_secret_basic,client_secret_jwt"
    redirect_uri          varchar(256),    -- URL de callback post-login
    redirect_uri_logout   varchar(256)     -- URL de callback post-logout
);
```

### SQL: `data.sql` (client de ejemplo)

```sql
insert into partners(
    client_id, client_name, client_secret, scopes,
    grant_types, authentication_methods, redirect_uri, redirect_uri_logout
) values (
    'debuggeandoideas',
    'debuggeando ideas',
    '$2a$10$9m4JHagydJWZb5zjc3Rd9O9yKuP5xSJsDNQmI8tz2EMbhYh7vKNkq',  -- BCrypt
    'read,write',
    'authorization_code,refresh_token',
    'client_secret_basic,client_secret_jwt',
    'https://oauthdebugger.com/debug',       -- Herramienta para testing OAuth2
    'https://springone.io/authorized'
);
```

**Dato importante:** Los passwords de usuarios Y el client_secret ahora estan en **BCrypt** (ya no `to_be_encoded`). El `PasswordEncoder` volvio a `BCryptPasswordEncoder`.

---

## 4. PartnerEntity y PartnerRepository

### `entites/PartnerEntity.java`

```java
@Entity
@Table(name = "partners")
@Data
public class PartnerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private BigInteger id;
    private String clientId;          // "debuggeandoideas"
    private String clientName;        // "debuggeando ideas"
    private String clientSecret;      // BCrypt hash
    private String scopes;            // "read,write"
    private String grantTypes;        // "authorization_code,refresh_token"
    private String authenticationMethods;  // "client_secret_basic,client_secret_jwt"
    private String redirectUri;       // Callback URL
    private String redirectUriLogout; // Logout callback URL
}
```

### `repositories/PartnerRepository.java`

```java
public interface PartnerRepository extends CrudRepository<PartnerEntity, BigInteger> {
    Optional<PartnerEntity> findByClientId(String clientId);
}
```

---

## 5. PartnerRegisteredClientService — El Puente con Spring Authorization Server

### Concepto

Spring Authorization Server necesita un `RegisteredClientRepository` para buscar clientes OAuth2. Es el equivalente a `UserDetailsService` pero para **aplicaciones cliente** en vez de usuarios.

### Implementacion: `services/PartnerRegisteredClientService.java`

```java
@Service
@AllArgsConstructor
public class PartnerRegisteredClientService implements RegisteredClientRepository {

    private PartnerRepository partnerRepository;

    @Override
    public RegisteredClient findByClientId(String clientId) {
        var partnerOpt = this.partnerRepository.findByClientId(clientId);

        return partnerOpt.map(partner -> {
            // Parsear strings separados por coma a listas de objetos OAuth2
            var authorizationGrantTypes = Arrays.stream(partner.getGrantTypes().split(","))
                    .map(AuthorizationGrantType::new)    // "authorization_code" → objeto
                    .toList();

            var clientAuthenticationMethods = Arrays.stream(partner.getAuthenticationMethods().split(","))
                    .map(ClientAuthenticationMethod::new) // "client_secret_basic" → objeto
                    .toList();

            var scopes = Arrays.stream(partner.getScopes().split(",")).toList();

            // Construir el RegisteredClient que Spring Authorization Server entiende
            return RegisteredClient
                    .withId(partner.getId().toString())
                    .clientId(partner.getClientId())
                    .clientSecret(partner.getClientSecret())
                    .clientName(partner.getClientName())
                    .redirectUri(partner.getRedirectUri())
                    .postLogoutRedirectUri(partner.getRedirectUriLogout())
                    .clientAuthenticationMethod(clientAuthenticationMethods.get(0))
                    .clientAuthenticationMethod(clientAuthenticationMethods.get(1))
                    .scope(scopes.get(0))        // "read"
                    .scope(scopes.get(1))        // "write"
                    .authorizationGrantType(authorizationGrantTypes.get(0))  // authorization_code
                    .authorizationGrantType(authorizationGrantTypes.get(1))  // refresh_token
                    .tokenSettings(this.tokenSettings())
                    .build();
        }).orElseThrow(() -> new BadCredentialsException("Client not exist"));
    }

    private TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(8))  // Access token dura 8 horas
                .build();
    }

    @Override
    public void save(RegisteredClient registeredClient) { }   // No implementado

    @Override
    public RegisteredClient findById(String id) { return null; }  // No implementado
}
```

### Analogia con conceptos anteriores

| OAuth2 (esta seccion) | Autenticacion clasica (secciones 2-8) |
|---|---|
| `RegisteredClientRepository` | `UserDetailsService` |
| `RegisteredClient` | `UserDetails` |
| `PartnerEntity` (BD) | `CustomerEntity` (BD) |
| `clientId` + `clientSecret` | `username` + `password` |
| `scopes` | `authorities` / `roles` |

---

## 6. SecurityConfig — Reescritura Completa

### Concepto: Dos SecurityFilterChains

Esta es la primera vez que hay **dos cadenas de filtros** en la app. Cada una maneja un tipo diferente de request:

```
Request entrante
    │
    ▼
┌──────────────────────────────────────────────────┐
│  ¿Es un request OAuth2?                          │
│  (/oauth2/authorize, /oauth2/token, etc.)        │
│                                                  │
│  SI → SecurityFilterChain @Order(1)              │
│       (Authorization Server)                     │
│                                                  │
│  NO → SecurityFilterChain @Order(2)              │
│       (Resource Server + reglas de acceso)        │
└──────────────────────────────────────────────────┘
```

`@Order(1)` tiene prioridad. Si el request matchea con los endpoints OAuth2, se procesa ahi. Si no, cae al `@Order(2)`.

### 6.1 FilterChain 1: Authorization Server (`@Order(1)`)

```java
@Bean
@Order(1)
SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
    // Aplica la config por defecto del Authorization Server
    // (registra filtros para /oauth2/authorize, /oauth2/token, /oauth2/jwks, etc.)
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

    // Habilita OpenID Connect (endpoints de identity: /userinfo, /connect/register)
    http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

    // Si un request no autenticado llega a un endpoint OAuth2,
    // redirigir al formulario de login
    http.exceptionHandling(e ->
            e.authenticationEntryPoint(
                    new LoginUrlAuthenticationEntryPoint("/login")));

    return http.build();
}
```

**`applyDefaultSecurity(http)`** registra automaticamente:
- `POST /oauth2/token` — intercambio de code por token
- `GET /oauth2/authorize` — inicio del flujo authorization_code
- `GET /oauth2/jwks` — llaves publicas RSA (para que los Resource Servers validen tokens)
- `GET /.well-known/openid-configuration` — discovery de todos los endpoints

### 6.2 FilterChain 2: Resource Server (`@Order(2)`)

```java
@Bean
@Order(2)
SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {
    // Formulario de login (para que el usuario se autentique durante el flujo OAuth2)
    http.formLogin(Customizer.withDefaults());

    // Reglas de acceso por rol (igual que secciones anteriores)
    http.authorizeHttpRequests(auth -> auth
            .requestMatchers(ADMIN_RESOURCES).hasRole(ROLE_ADMIN)  // /accounts/**, /cards/**
            .requestMatchers(USER_RESOURCES).hasRole(ROLE_USER)    // /loans/**, /balance/**
            .anyRequest().permitAll());

    // Habilita validacion de JWT en requests entrantes (Resource Server)
    http.oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));

    return http.build();
}
```

**`.oauth2ResourceServer(oauth -> oauth.jwt(...))`** — activa un filtro automatico (`BearerTokenAuthenticationFilter`) que:
1. Lee el header `Authorization: Bearer <token>`
2. Valida la firma del JWT usando la clave publica RSA
3. Extrae los claims y crea un `JwtAuthenticationToken`
4. Lo guarda en el `SecurityContext`

Ya no necesitas el `JWTValidationFilter` manual de la seccion 8 — Spring lo hace todo.

---

## 7. Criptografia RSA — Llaves Asimetricas

### Encriptacion asimetrica RSA

```
  Servidor A                                                          Servidor B
 ┌──────────┐                                                        ┌──────────┐
 │          │     Texto plano      Texto cifrado      Texto plano    │          │
 │          │    ┌──────────┐     ┌────────────┐     ┌──────────┐    │          │
 │          │───►│          │────►│            │────►│          │───►│          │
 │          │    └──────────┘     └────────────┘     └──────────┘    │          │
 │          │                                                        │          │
 └──────────┘         ▲                                   ▲          └──────────┘
                      │                                   │
                 Encriptacion                        Decriptacion
                      │                                   │
                 ┌─────────┐                        ┌─────────┐
                 │  Llave  │                        │  Llave  │
                 │ PRIVADA │                        │ PUBLICA │
                 └─────────┘                        └─────────┘
```

- El **Servidor A** (Authorization Server) encripta/firma con la **llave privada** — solo el la posee
- El **Servidor B** (Resource Server) decripta/valida con la **llave publica** — puede ser compartida libremente
- Si alguien intercepta la llave publica, **no puede firmar tokens falsos** (necesitaria la privada)

### ¿Por que RSA en vez de HMAC?

| Aspecto | HMAC (seccion 8) | RSA (esta seccion) |
|---|---|---|
| **Tipo** | Simetrico (una clave) | Asimetrico (par de claves) |
| **Firma** | La misma clave firma y valida | Clave privada firma, clave publica valida |
| **Si se compromete** | El atacante puede crear tokens falsos | Solo la publica? No puede firmar. Solo la privada? Puede firmar |
| **Multi-servicio** | TODOS necesitan la clave secreta | Solo el Auth Server tiene la privada. Los demas solo la publica |

### Implementacion: Generacion de llaves

```java
// Genera un par de llaves RSA de 2048 bits
private static KeyPair generateRSA() {
    KeyPair keyPair;
    try {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
    }
    return keyPair;
}

// Envuelve el par en un JWK (JSON Web Key) con un ID unico
private static RSAKey generateKeys() {
    var keyPair = generateRSA();
    var publicKey = (RSAPublicKey) keyPair.getPublic();
    var privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())  // ID unico para esta llave
            .build();
}
```

### JWKSource — Fuente de llaves

```java
@Bean
JWKSource<SecurityContext> jwkSource() {
    var rsa = generateKeys();
    var jwkSet = new JWKSet(rsa);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
}
```

Este bean es usado por:
- El **Authorization Server** para firmar tokens (usa la clave privada)
- El **endpoint `/oauth2/jwks`** para publicar la clave publica (los Resource Servers la descargan)

### JwtDecoder — Validacion de tokens

```java
@Bean
JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
}
```

Crea un decoder que usa la clave publica del `JWKSource` para validar tokens entrantes. El Resource Server (`@Order(2)`) usa este decoder automaticamente.

---

## 8. OAuth2TokenCustomizer — Claims Custom en el Access Token

### Concepto

Por defecto, el access token JWT de Spring Authorization Server solo incluye claims basicos (`sub`, `aud`, `iat`, `exp`, `scope`). Queremos agregar los **roles** del usuario y metadata custom.

### Implementacion

```java
@Bean
OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
    return context -> {
        // Obtener el usuario autenticado y sus authorities
        var authentication = context.getPrincipal();
        var authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());     // {"ROLE_ADMIN"}

        // Solo personalizar ACCESS_TOKENs (no refresh tokens ni ID tokens)
        if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
            context.getClaims().claims(claim ->
                    claim.putAll(Map.of(
                            "roles", authorities,                      // Los roles del usuario
                            "owner", "Debuggeando ideas",              // Metadata custom
                            "date_request", LocalDateTime.now().toString()  // Timestamp
                    )));
        }
    };
}
```

### Resultado: Access Token con claims custom

```json
{
  "sub": "account@debuggeandoideas.com",
  "aud": "debuggeandoideas",
  "scope": ["read", "write"],
  "roles": ["ROLE_ADMIN"],           // ← Agregado por el customizer
  "owner": "Debuggeando ideas",      // ← Agregado por el customizer
  "date_request": "2024-07-01T...", // ← Agregado por el customizer
  "iat": 1719864800,
  "exp": 1719893600
}
```

---

## 9. JwtAuthenticationConverter — Extraer Roles del Token

### El problema

Cuando el Resource Server recibe un JWT, extrae authorities del claim `scope` por defecto (con prefijo `SCOPE_`). Pero nuestros roles estan en el claim `roles` y ya tienen el prefijo `ROLE_`.

### Implementacion

```java
@Bean
JwtAuthenticationConverter jwtAuthenticationConverter() {
    // Configurar de donde extraer las authorities
    var authConverter = new JwtGrantedAuthoritiesConverter();
    authConverter.setAuthoritiesClaimName("roles");  // Leer del claim "roles" (no "scope")
    authConverter.setAuthorityPrefix("");             // Sin prefijo adicional (ya tienen ROLE_)

    var converterResponse = new JwtAuthenticationConverter();
    converterResponse.setJwtGrantedAuthoritiesConverter(authConverter);
    return converterResponse;
}
```

### Sin este converter

```
JWT claim "roles": ["ROLE_ADMIN"]
→ Spring busca "scope" por defecto → no encuentra roles
→ hasRole("ADMIN") falla → 403
```

### Con este converter

```
JWT claim "roles": ["ROLE_ADMIN"]
→ Spring lee "roles" → authorities = [ROLE_ADMIN]
→ hasRole("ADMIN") → busca ROLE_ADMIN → lo encuentra → 200 OK
```

---

## 10. AuthenticationProvider Explicito

```java
@Bean
AuthenticationProvider authenticationProvider(PasswordEncoder encoder,
                                              CustomerUserDetails userDetails) {
    var authProvider = new DaoAuthenticationProvider();
    authProvider.setPasswordEncoder(encoder);          // BCryptPasswordEncoder
    authProvider.setUserDetailsService(userDetails);   // CustomerUserDetails
    return authProvider;
}
```

En secciones anteriores, Spring creaba el `DaoAuthenticationProvider` automaticamente. Aqui se declara explicitamente porque Spring Authorization Server necesita un `AuthenticationProvider` bien definido para autenticar usuarios durante el flujo OAuth2 (cuando el usuario hace login en el formulario).

---

## 11. Flujo Completo: Authorization Code

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────────────┐
│   Partner    │     │  Auth Server     │     │  Usuario (navegador)    │
│   (Client)   │     │  (tu Spring app) │     │                         │
└──────┬──────┘     └────────┬─────────┘     └────────────┬────────────┘
       │                     │                             │
       │ 1. Redirige al Auth Server                        │
       │────────────────────►│                             │
       │  GET /oauth2/authorize?                           │
       │    response_type=code&                            │
       │    client_id=debuggeandoideas&                    │
       │    scope=read write&                              │
       │    redirect_uri=https://oauthdebugger.com/debug   │
       │                     │                             │
       │                     │ 2. Muestra formulario login │
       │                     │────────────────────────────►│
       │                     │                             │
       │                     │ 3. Usuario envia credenciales
       │                     │◄────────────────────────────│
       │                     │  (account@..., password)    │
       │                     │                             │
       │                     │ 4. DaoAuthProvider valida    │
       │                     │    → CustomerUserDetails     │
       │                     │    → PostgreSQL → OK         │
       │                     │                             │
       │                     │ 5. Pantalla de consentimiento
       │                     │────────────────────────────►│
       │                     │  "¿Autorizar scopes read,   │
       │                     │   write para debuggeando    │
       │                     │   ideas?"                   │
       │                     │                             │
       │                     │ 6. Usuario acepta           │
       │                     │◄────────────────────────────│
       │                     │                             │
       │ 7. Redirect con authorization_code                │
       │◄────────────────────│                             │
       │  302 → https://oauthdebugger.com/debug?code=xyz  │
       │                     │                             │
       │ 8. Intercambia code por tokens                    │
       │────────────────────►│                             │
       │  POST /oauth2/token                               │
       │  grant_type=authorization_code                    │
       │  code=xyz                                         │
       │  client_id + client_secret (Basic Auth)           │
       │                     │                             │
       │ 9. Recibe tokens    │                             │
       │◄────────────────────│                             │
       │  {                  │                             │
       │    "access_token": "eyJhbG...",                   │
       │    "refresh_token": "abc123...",                   │
       │    "token_type": "Bearer",                        │
       │    "expires_in": 28800                            │
       │  }                  │                             │
       │                     │                             │
       │ 10. Usa el access_token                           │
       │────────────────────►│                             │
       │  GET /accounts                                    │
       │  Authorization: Bearer eyJhbG...                  │
       │                     │                             │
       │ 11. Resource Server valida JWT                    │
       │     → RSA publica → firma OK                      │
       │     → roles: [ROLE_ADMIN] → hasRole("ADMIN") OK   │
       │                     │                             │
       │ 12. Respuesta       │                             │
       │◄────────────────────│                             │
       │  {"msj": "accounts"}│                             │
```

---

## 12. Archivos Eliminados vs Nuevos

### Eliminados (JWT manual ya no es necesario)

| Archivo eliminado | Reemplazo en OAuth2 |
|---|---|
| `services/JWTService.java` | Spring Authorization Server genera y firma tokens internamente |
| `services/JWTUserDetailService.java` | Renombrado a `CustomerUserDetails` |
| `security/JWTValidationFilter.java` | `BearerTokenAuthenticationFilter` automatico de Resource Server |
| `components/JwtAuthenticationEntryPoint.java` | `LoginUrlAuthenticationEntryPoint` (redirige a /login) |
| `controllers/AuthenticationController.java` | `/oauth2/token` del Authorization Server |
| `entites/JWTRequest.java` | No necesario (el flujo OAuth2 usa redirects, no JSON body) |
| `entites/JWTResponse.java` | No necesario (Spring serializa la respuesta del token) |
| `security/CsrfCookieFilter.java` | No necesario en este flujo |
| `security/MyAuthenticationProvider.java` | `DaoAuthenticationProvider` explicito |

### Nuevos

| Archivo nuevo | Que hace |
|---|---|
| `entites/PartnerEntity.java` | Entidad JPA para clientes OAuth2 |
| `repositories/PartnerRepository.java` | `findByClientId()` para buscar partners |
| `services/PartnerRegisteredClientService.java` | Implementa `RegisteredClientRepository` — el "UserDetailsService" para clientes OAuth2 |
| `services/CustomerUserDetails.java` | UserDetailsService para usuarios (renombrado de JWTUserDetailService) |

---

## 13. Endpoints que Spring Authorization Server Expone Automaticamente

| Endpoint | Metodo | Que hace |
|---|---|---|
| `/oauth2/authorize` | GET | Inicia el flujo authorization_code (redirige a login) |
| `/oauth2/token` | POST | Intercambia code/refresh_token por access_token |
| `/oauth2/jwks` | GET | Publica las llaves RSA publicas (JWKS) |
| `/.well-known/openid-configuration` | GET | Discovery: lista todos los endpoints y capacidades |
| `/oauth2/revoke` | POST | Revoca un token |
| `/oauth2/introspect` | POST | Inspecciona si un token es valido |
| `/userinfo` | GET | Retorna info del usuario autenticado (OIDC) |
| `/login` | GET/POST | Formulario de login (Spring lo genera automaticamente) |

No escribes codigo para ninguno de estos endpoints — Spring Authorization Server los registra con `applyDefaultSecurity(http)`.

---

## 14. Resumen Visual

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    OAUTH2 AUTHORIZATION SERVER                           │
│                                                                          │
│  SecurityFilterChain @Order(1) — Authorization Server                    │
│  ├── /oauth2/authorize → inicia flujo OAuth2                             │
│  ├── /oauth2/token     → emite access_token + refresh_token              │
│  ├── /oauth2/jwks      → publica llaves RSA publicas                     │
│  └── OIDC endpoints    → OpenID Connect                                  │
│                                                                          │
│  SecurityFilterChain @Order(2) — Resource Server                         │
│  ├── BearerTokenAuthenticationFilter (automatico)                        │
│  │   → Valida JWT con RSA publica                                        │
│  │   → JwtAuthenticationConverter: lee claim "roles"                     │
│  ├── /accounts, /cards → hasRole("ADMIN")                                │
│  ├── /loans, /balance  → hasRole("USER")                                 │
│  └── formLogin         → para el flujo OAuth2                            │
│                                                                          │
│  Beans clave:                                                            │
│  ├── JWKSource         → par de llaves RSA (privada firma, publica valida)│
│  ├── JwtDecoder        → valida tokens con la publica                    │
│  ├── OAuth2TokenCustomizer → agrega roles al access_token                │
│  ├── JwtAuthenticationConverter → extrae roles del JWT                   │
│  ├── DaoAuthenticationProvider → autentica usuarios en el flujo OAuth2   │
│  ├── PartnerRegisteredClientService → busca clientes OAuth2 en BD        │
│  ├── CustomerUserDetails → busca usuarios en BD                          │
│  └── BCryptPasswordEncoder → passwords y client secrets encriptados      │
│                                                                          │
│  BD:                                                                     │
│  ├── customers (email, pwd BCrypt, roles)                                │
│  ├── roles (ROLE_ADMIN, ROLE_USER)                                       │
│  └── partners (clientId, clientSecret BCrypt, scopes, grantTypes)        │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 15. Evolucion Completa del Curso (Secciones 1-9)

```
Sec 1  application.properties     → 1 usuario hardcodeado
Sec 2  InMemory / JDBC / Custom   → usuarios en PostgreSQL (UserDetailsService)
Sec 3  NoOpPasswordEncoder        → BCryptPasswordEncoder
Sec 4  DaoAuthProvider auto       → AuthenticationProvider custom
Sec 5  Sin CORS/CSRF              → CorsFilter + CsrfFilter + CsrfCookieFilter
Sec 6  .authenticated()           → hasRole("ADMIN") / hasRole("USER")
Sec 7  Sin filtros custom         → ApiKeyFilter (addFilterBefore)
Sec 8  Sesiones (stateful)        → JWT manual (stateless, HMAC)
Sec 9  JWT manual                 → OAuth2 Authorization Server (RSA, estandar)

Autenticacion:  properties → BD → BCrypt → AuthProvider → JWT → OAuth2
Autorizacion:   todo abierto → authenticated → roles → scopes
Tokens:         cookie sesion → JWT HMAC manual → JWT RSA OAuth2
```

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `pom.xml` | +`oauth2-authorization-server` + `oauth2-resource-server`, elimina `jjwt` |
| `db/sql/create_schema.sql` | Nueva tabla `partners` para clientes OAuth2 |
| `db/sql/data.sql` | Passwords BCrypt + partner de ejemplo |
| `entites/PartnerEntity.java` | **Nuevo** — entidad JPA para clientes OAuth2 |
| `repositories/PartnerRepository.java` | **Nuevo** — `findByClientId()` |
| `services/PartnerRegisteredClientService.java` | **Nuevo** — `RegisteredClientRepository` custom |
| `services/CustomerUserDetails.java` | **Renombrado** — UserDetailsService (antes JWTUserDetailService) |
| `security/SecurityConfig.java` | **Reescrito completo** — 2 FilterChains, RSA, OAuth2, Resource Server, TokenCustomizer, JwtConverter |
| `AppSecurityApplication.java` | Elimina `@EnableWebSecurity(debug=true)` |
