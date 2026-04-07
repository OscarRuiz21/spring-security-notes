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
