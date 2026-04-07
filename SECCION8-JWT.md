# Seccion 8: Autenticacion con JWT (JSON Web Tokens)

> Notas del curso de Spring Security 6 — De sesiones en servidor a tokens stateless firmados

---

## Objetivo de la seccion

Reemplazar la autenticacion basada en **sesiones HTTP** (stateful) por **JWT** (stateless), implementando:

- Un `JWTService` que genera y valida tokens con la libreria **jjwt**
- Un `JWTValidationFilter` que intercepta cada request y valida el Bearer token
- Un `AuthenticationController` con endpoint `/authenticate` para emitir tokens
- Un `JwtAuthenticationEntryPoint` para manejar respuestas 401 limpias
- `SessionCreationPolicy.STATELESS` para eliminar las sesiones del servidor

---

## Ubicacion en la Arquitectura

```
                        ┌────────────────┐
                        │ Password       │
                        │ Encoder        │
                        └───────▲────────┘
                                │ 5
                                │
  1  Request    ┌───────────────┴──────────────┐   3   ┌─────────────────┐
  + Bearer JWT  │       Security Filters       │──────►│  Auth Manager   │
  ────────────► │                              │       │                 │
                │  ┌────────────────────────┐  │       └──┬──────────▲──┘
                │  │ JWTValidationFilter    │  │ ◄── ESTAS AQUI     │
                │  │ (valida JWT, carga     │  │         4│         7│
                │  │  usuario, setea        │  │          ▼          │
                │  │  SecurityContext)       │  │   ┌────────────────┴──┐
                │  └────────────────────────┘  │   │  DaoAuthProvider   │
                │  ┌────────────────────────┐  │   └──────────┬────────┘
                │  │ AuthorizationFilter    │  │              │ 6
                │  │ (hasRole)              │  │              ▼
                │  └────────────────────────┘  │   ┌──────────────────┐
                └──────────────────────────────┘   │ JWTUserDetail    │
                                                   │ Service          │
                                                   └──────────────────┘
```

Esta seccion toca multiples piezas del diagrama maestro (ver Seccion 1). Hay **dos flujos** separados:
- **Login** (`POST /authenticate`): recorre los pasos 1→3→4→5→6→7→8 del diagrama para validar credenciales y emitir un JWT
- **Request protegido** (con `Bearer` token): el `JWTValidationFilter` hace los pasos 6+9 directamente (carga usuario + setea SecurityContext), saltandose el flujo clasico de AuthManager

---

## 1. ¿Por que JWT? — Stateful vs Stateless

### El problema de las sesiones (stateful)

Hasta la seccion 7, la autenticacion funcionaba asi:

```
1. Usuario hace login → servidor crea una SESION en memoria
   (HttpSession con un ID unico, ej: JSESSIONID=abc123)

2. Servidor envia cookie: Set-Cookie: JSESSIONID=abc123

3. En cada request, el navegador envia la cookie
   → Servidor busca la sesion abc123 en memoria
   → Encuentra al usuario → lo considera autenticado
```

**Problemas de este modelo:**

| Problema | Impacto |
|---|---|
| **Memoria del servidor** | Cada sesion activa consume RAM. 10,000 usuarios = 10,000 sesiones en memoria |
| **Escalabilidad horizontal** | Si tienes 3 servidores, la sesion esta en uno solo. Si el load balancer envia al usuario a otro servidor, pierde la sesion |
| **Sticky sessions** | La solucion anterior requiere que el LB siempre envie al usuario al mismo servidor — mata el balanceo |
| **CSRF** | Las cookies se envian automaticamente → vulnerable a CSRF |

### La solucion: JWT (stateless)

```
1. Usuario hace login → servidor genera un TOKEN firmado (JWT)
   → Lo envia en la respuesta como JSON: { "jwt": "eyJhbGci..." }

2. El servidor NO guarda nada en memoria (sin sesion)

3. En cada request, el CLIENTE envia el token en el header:
   Authorization: Bearer eyJhbGci...
   → Servidor valida la FIRMA del token (no busca en memoria)
   → La firma es valida → lo considera autenticado
```

**Beneficios:**

| Beneficio | Detalle |
|---|---|
| **Sin estado en servidor** | No consume RAM. 10,000 usuarios = 0 sesiones en memoria |
| **Escalabilidad horizontal** | Cualquier servidor puede validar el token (solo necesita la clave secreta) |
| **Sin CSRF** | El token va en un header, no en una cookie → CSRF no aplica |
| **Cross-domain** | El token se puede usar con multiples APIs/dominios |

---

## 2. Anatomia de un JWT

### Estructura

Un JWT tiene 3 partes separadas por puntos:

```
eyJhbGciOiJIUzI1NiJ9.eyJST0xFUyI6IltST0xFX0FETUlOXSIsInN1YiI6ImFjY291bnRAZGVidWdnZWFuZG9pZGVhcy5jb20iLCJpYXQiOjE3MTk4NjQ4MDAsImV4cCI6MTcxOTg4MjgwMH0.abc123signature
└──────── HEADER ────────┘└──────────────────────── PAYLOAD ─────────────────────────────────────────────────────────────┘└──── SIGNATURE ─────┘
```

| Parte | Contenido | Codificacion |
|---|---|---|
| **Header** | Algoritmo y tipo de token | Base64URL |
| **Payload** | Claims (datos): subject, roles, expiracion, etc. | Base64URL |
| **Signature** | HMAC-SHA256(header + payload, SECRET) | Binario → Base64URL |

### Payload decodificado (ejemplo del curso)

```json
{
  "ROLES": "[ROLE_ADMIN]",       // Claim custom: roles del usuario
  "sub": "account@debuggeandoideas.com",  // Subject: quien es
  "iat": 1719864800,             // Issued At: cuando se emitio
  "exp": 1719882800              // Expiration: cuando expira (iat + 5 horas)
}
```

### ¿Que hace la FIRMA?

```
FIRMA = HMAC-SHA256(
    base64(header) + "." + base64(payload),
    "jxgEQe.XHuPq8VdbyYFNkAN.dudQ0903YUn4"   ← clave secreta
)
```

Si alguien modifica el payload (ej: cambia `ROLE_USER` por `ROLE_ADMIN`), la firma ya no coincide. El servidor detecta la alteracion y rechaza el token. **Sin la clave secreta, es imposible generar una firma valida.**

---

## 3. Dependencias: jjwt (libreria JWT)

### `pom.xml`

```xml
<!-- API publica de jjwt (interfaces y clases que usas en tu codigo) -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>

<!-- Implementacion interna de jjwt (no la usas directamente) -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>

<!-- Serializacion JSON con Jackson (para leer/escribir claims) -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

**¿Por que 3 dependencias?** jjwt sigue el patron de separar API (`jjwt-api`, la que importas en tu codigo) de implementacion (`jjwt-impl`, `jjwt-jackson`, en scope `runtime`). Esto permite cambiar la implementacion sin tocar tu codigo.

---

## 4. JWTService — Generacion y Validacion de Tokens

### Implementacion completa: `services/JWTService.java`

```java
@Service
public class JWTService {

    // Token valido por 5 horas (5 * 60 minutos * 60 segundos)
    public static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

    // Clave secreta para firmar tokens (en produccion: variable de entorno)
    public static final String JWT_SECRET = "jxgEQe.XHuPq8VdbyYFNkAN.dudQ0903YUn4";

    // ──────────── LEER TOKENS ────────────

    // Parsea el JWT y extrae TODOS los claims
    private Claims getAllClaimsFromToken(String token) {
        final var key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
        return Jwts
                .parserBuilder()
                .setSigningKey(key)       // Clave para VERIFICAR la firma
                .build()
                .parseClaimsJws(token)    // Parsea y valida firma + expiracion
                .getBody();               // Retorna los claims
    }

    // Extractor generico: dado un token y una funcion, extrae un claim especifico
    public <T> T getClaimsFromToken(String token, Function<Claims, T> claimsResolver) {
        final var claims = this.getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // Extrae el "sub" (subject = username)
    public String getUsernameFromToken(String token) {
        return this.getClaimsFromToken(token, Claims::getSubject);
    }

    // Extrae la fecha de expiracion
    private Date getExpirationDateFromToken(String token) {
        return this.getClaimsFromToken(token, Claims::getExpiration);
    }

    // ¿El token ya expiro?
    private Boolean isTokenExpired(String token) {
        final var expirationDate = this.getExpirationDateFromToken(token);
        return expirationDate.before(new Date());
    }

    // ──────────── GENERAR TOKENS ────────────

    // Genera un JWT a partir de un UserDetails (post-autenticacion)
    public String generateToken(UserDetails userDetails) {
        final Map<String, Object> claims = Collections.singletonMap(
                "ROLES", userDetails.getAuthorities().toString()  // "[ROLE_ADMIN]"
        );
        return this.getToken(claims, userDetails.getUsername());
    }

    // Construye el JWT con jjwt Builder
    private String getToken(Map<String, Object> claims, String subject) {
        final var key = Keys.hmacShaKeyFor(JWT_SECRET.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .setClaims(claims)                    // Claims custom (ROLES)
                .setSubject(subject)                  // "account@debuggeandoideas.com"
                .setIssuedAt(new Date())              // Momento de emision
                .setExpiration(new Date(              // Expira en 5 horas
                        System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(key)                        // Firma con HMAC-SHA256
                .compact();                           // Serializa a String
    }

    // ──────────── VALIDAR TOKENS ────────────

    // Valida que el username del token coincida con el UserDetails Y que no haya expirado
    public Boolean validateToken(String token, UserDetails userDetails) {
        final var usernameFromUserDetails = userDetails.getUsername();
        final var usernameFromJWT = this.getUsernameFromToken(token);

        return (usernameFromUserDetails.equals(usernameFromJWT))
                && !this.isTokenExpired(token);
    }
}
```

### Flujo de los metodos

```
GENERAR:
   UserDetails → generateToken() → getToken() → Jwts.builder()...compact() → "eyJhbG..."

VALIDAR:
   "eyJhbG..." → getAllClaimsFromToken() → Jwts.parserBuilder()...parseClaimsJws()
                  → claims.getSubject() → "account@..."
                  → ¿coincide con UserDetails? && ¿no expirado? → true/false
```

---

## 5. JWTUserDetailService — Cargar Usuarios para JWT

### Implementacion: `services/JWTUserDetailService.java`

```java
@Service
@AllArgsConstructor
public class JWTUserDetailService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.customerRepository.findByEmail(username)
                .map(customer -> {
                    final var authorities = customer.getRoles()
                            .stream()
                            .map(role -> new SimpleGrantedAuthority(role.getName()))
                            .toList();
                    return new User(customer.getEmail(), customer.getPassword(), authorities);
                }).orElseThrow(() -> new UsernameNotFoundException("User not exist"));
    }
}
```

**Es practicamente identico al `CustomerUserDetails` de la seccion 2**, pero adaptado para el flujo JWT. Se usa en dos momentos:
1. En el `AuthenticationController` para cargar el usuario y generar el token
2. En el `JWTValidationFilter` para cargar el usuario y validar el token

> **Nota:** `MyAuthenticationProvider` (seccion 4-7) fue **eliminado** en esta rama. Se vuelve al modelo de `UserDetailsService` + `DaoAuthenticationProvider` automatico de Spring, porque el `JWTValidationFilter` necesita un `UserDetailsService` para cargar usuarios por username.

---

## 6. DTOs de Request/Response

### `JWTRequest.java`

```java
@Data
public class JWTRequest {
    private String username;   // Email del usuario
    private String password;   // Password en texto plano
}
```

### `JWTResponse.java`

```java
@Data
@AllArgsConstructor
public class JWTResponse {
    private String jwt;   // El token generado
}
```

Simples POJOs para serializar/deserializar el JSON del endpoint `/authenticate`.

---

## 7. AuthenticationController — Endpoint de Login

### Implementacion: `controllers/AuthenticationController.java`

```java
@RestController
@AllArgsConstructor
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final JWTUserDetailService jwtUserDetailService;
    private final JWTService jwtService;

    @PostMapping("/authenticate")
    public ResponseEntity<?> postToken(@RequestBody JWTRequest request) {
        // 1. Valida credenciales (lanza excepcion si fallan)
        this.authenticate(request);

        // 2. Carga el UserDetails completo (con authorities)
        final var userDetails = this.jwtUserDetailService
                .loadUserByUsername(request.getUsername());

        // 3. Genera el JWT firmado
        final var token = this.jwtService.generateToken(userDetails);

        // 4. Retorna el token como JSON
        return ResponseEntity.ok(new JWTResponse(token));
    }

    private void authenticate(JWTRequest request) {
        try {
            // Delega al AuthenticationManager (que usa DaoAuthProvider internamente)
            this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
        } catch (BadCredentialsException | DisabledException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
}
```

### Flujo del endpoint `/authenticate`

```
POST /authenticate
Body: { "username": "account@debuggeandoideas.com", "password": "to_be_encoded" }
        │
        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  AuthenticationController.postToken()                                   │
│                                                                         │
│  1. authenticate(request)                                               │
│     → authenticationManager.authenticate(UPAT("account@...", "to_be_"))│
│     → DaoAuthenticationProvider:                                        │
│       → JWTUserDetailService.loadUserByUsername("account@...")           │
│       → PostgreSQL → CustomerEntity con ROLE_ADMIN                      │
│       → passwordEncoder.matches("to_be_encoded", "to_be_encoded")       │
│       → OK ✅                                                           │
│                                                                         │
│  2. jwtUserDetailService.loadUserByUsername("account@...")               │
│     → UserDetails { authorities: [ROLE_ADMIN] }                         │
│                                                                         │
│  3. jwtService.generateToken(userDetails)                               │
│     → claims: { ROLES: "[ROLE_ADMIN]", sub: "account@..." }            │
│     → firma con HMAC-SHA256 + secret                                    │
│     → "eyJhbGciOiJIUzI1NiJ9.eyJST0xFUy..."                           │
│                                                                         │
│  4. ResponseEntity.ok(new JWTResponse("eyJhbGci..."))                   │
└─────────────────────────────────────────────────────────────────────────┘
        │
        ▼
Response: { "jwt": "eyJhbGciOiJIUzI1NiJ9..." }
```

### ¿Por que se inyecta el `AuthenticationManager`?

En secciones anteriores, el `AuthenticationManager` era interno (nunca lo usabas directamente). Ahora necesitas llamarlo explicitamente desde el controller para validar credenciales antes de emitir un token. Por eso se expone como bean en SecurityConfig:

```java
@Bean
AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
    return configuration.getAuthenticationManager();
}
```

---

## 8. JWTValidationFilter — El Filtro que Valida Tokens

### Implementacion: `security/JWTValidationFilter.java`

```java
@Component
@AllArgsConstructor
@Slf4j
public class JWTValidationFilter extends OncePerRequestFilter {

    private final JWTService jwtService;
    private final JWTUserDetailService jwtUserDetailService;

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTHORIZATION_HEADER_BEARER = "Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Leer el header Authorization
        final var requestTokenHeader = request.getHeader(AUTHORIZATION_HEADER);
        String username = null;
        String jwt = null;

        // 2. ¿Viene un Bearer token?
        if (Objects.nonNull(requestTokenHeader)
                && requestTokenHeader.startsWith(AUTHORIZATION_HEADER_BEARER)) {

            // 3. Extraer el token (quitar "Bearer ")
            jwt = requestTokenHeader.substring(7);

            try {
                // 4. Extraer el username del token (valida firma implicitamente)
                username = jwtService.getUsernameFromToken(jwt);
            } catch (IllegalArgumentException e) {
                log.error(e.getMessage());       // Token malformado
            } catch (ExpiredJwtException e) {
                log.warn(e.getMessage());         // Token expirado
            }
        }

        // 5. Si hay username Y no hay autenticacion previa en el SecurityContext
        if (Objects.nonNull(username)
                && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {

            // 6. Cargar el usuario desde la BD
            final var userDetails = this.jwtUserDetailService.loadUserByUsername(username);

            // 7. Validar: ¿username coincide? ¿no expirado?
            if (this.jwtService.validateToken(jwt, userDetails)) {

                // 8. Crear token AUTENTICADO y setearlo en el SecurityContext
                var usernameAndPassAuthToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());

                usernameAndPassAuthToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                // 9. ← ESTO es el paso 9 del diagrama maestro
                SecurityContextHolder.getContext().setAuthentication(usernameAndPassAuthToken);
            }
        }

        // 10. Siempre continuar la cadena (incluso si no habia token)
        filterChain.doFilter(request, response);
    }
}
```

### Desglose de las decisiones clave

#### ¿Por que `@Component` (bean) en vez de `new` como los filtros anteriores?

Porque necesita inyeccion de dependencias (`JWTService` y `JWTUserDetailService`). Los filtros anteriores (`ApiKeyFilter`, `CsrfCookieFilter`) no dependian de beans de Spring, asi que se creaban con `new`. Este necesita el contexto de Spring, por eso es `@Component` y se inyecta en `SecurityConfig`.

#### ¿Por que verificar `Objects.isNull(SecurityContextHolder.getContext().getAuthentication())`?

Para evitar procesar el JWT si el usuario ya fue autenticado por otro mecanismo (ej: HTTP Basic en el mismo request). Si ya hay un `Authentication` en el contexto, no necesita hacer nada.

#### ¿Por que `filterChain.doFilter()` se llama SIEMPRE?

A diferencia del `ApiKeyFilter` (seccion 7) que lanzaba excepcion si faltaba la API Key, este filtro deja pasar el request incluso sin token. ¿Por que? Porque algunos endpoints son publicos (`/welcome`, `/about_us`, `/authenticate`). El `AuthorizationFilter` al final de la cadena se encarga de decidir si el request necesitaba autenticacion.

#### `WebAuthenticationDetailsSource`

```java
usernameAndPassAuthToken.setDetails(
    new WebAuthenticationDetailsSource().buildDetails(request));
```

Agrega metadata del request (IP, session ID) al token de autenticacion. No es estrictamente necesario, pero es una buena practica para logging y auditoria.

---

## 9. JwtAuthenticationEntryPoint — Respuesta 401 Limpia

### Implementacion: `components/JwtAuthenticationEntryPoint.java`

```java
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException)
            throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}
```

### ¿Para que?

Sin esto, cuando un request sin token llega a un endpoint protegido, Spring redirige a `/login` (comportamiento de Form Login). Con `JwtAuthenticationEntryPoint`, retorna un **401 Unauthorized** limpio — que es lo correcto para una API REST.

---

## 10. SecurityConfig — Los Cambios Clave

```java
@Bean
@Autowired
SecurityFilterChain securityFilterChain(HttpSecurity http,
        JWTValidationFilter jwtValidationFilter) throws Exception {

    // NUEVO: Sin sesiones — cada request se autentica por su token
    http.sessionManagement(sess ->
            sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    // ... (CORS, CSRF, reglas de acceso iguales)

    // NUEVO: JWTValidationFilter DESPUES de BasicAuthenticationFilter
    http.addFilterAfter(jwtValidationFilter, BasicAuthenticationFilter.class);

    // NUEVO: /authenticate excluido de CSRF (es un endpoint publico de login)
    http.csrf(csrf -> csrf
            .ignoringRequestMatchers("/welcome", "/about_us", "/authenticate")
            // ...
    );

    return http.build();
}

// NUEVO: Exponer el AuthenticationManager como bean
@Bean
AuthenticationManager authenticationManager(
        AuthenticationConfiguration configuration) throws Exception {
    return configuration.getAuthenticationManager();
}
```

### `SessionCreationPolicy.STATELESS`

La linea mas importante de esta seccion:

```java
http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
```

Le dice a Spring: **no crees sesiones HTTP nunca.** Cada request se autentica de forma independiente por su JWT. Esto:
- Elimina la cookie `JSESSIONID`
- Reduce el consumo de memoria del servidor a cero
- Hace que CSRF no sea necesario (no hay cookies de sesion que explotar)

### Archivos eliminados

- **`MyAuthenticationProvider.java`** — Se vuelve al `DaoAuthenticationProvider` automatico de Spring (necesario para que `AuthenticationManager` funcione con `UserDetailsService`)
- **`ApiKeyFilter.java`** — Reemplazado conceptualmente por `JWTValidationFilter`

---

## 11. Flujo Completo — Dos Fases

### Fase 1: Obtener el token

```
POST /authenticate
Body: { "username": "account@debuggeandoideas.com", "password": "to_be_encoded" }
        │
        ▼
  AuthenticationController
  → authenticationManager.authenticate(credenciales)
  → DaoAuthProvider → JWTUserDetailService → PostgreSQL → OK
  → jwtService.generateToken(userDetails)
  → Response: { "jwt": "eyJhbGci..." }
```

### Fase 2: Usar el token en requests protegidos

```
GET /accounts
Header: Authorization: Bearer eyJhbGci...
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│  JWTValidationFilter                                             │
│                                                                  │
│  1. Lee header: "Bearer eyJhbGci..."                             │
│  2. Extrae JWT: "eyJhbGci..."                                    │
│  3. getUsernameFromToken → "account@debuggeandoideas.com"        │
│     (valida firma implicitamente — si la firma es invalida,      │
│      parseClaimsJws lanza SignatureException)                    │
│  4. loadUserByUsername → UserDetails { [ROLE_ADMIN] }            │
│  5. validateToken → username coincide + no expirado → true       │
│  6. Crea UPAT(userDetails, null, [ROLE_ADMIN])                   │
│  7. SecurityContextHolder.setAuthentication(UPAT)                │
│                                                                  │
│  → El request ahora tiene Authentication en el contexto ✅       │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  AuthorizationFilter                                             │
│  hasRole("ADMIN") → [ROLE_ADMIN] → SI ✅                         │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       ▼
            AccountsController → {"msj": "accounts"}
```

---

## 12. Cadena de Filtros Actualizada

```
┌──────────────────────────────────────────────────────────────────┐
│  SECURITY FILTER CHAIN — Seccion 8                               │
│                                                                  │
│  CorsFilter                                                      │
│  CsrfFilter                                                      │
│  BasicAuthenticationFilter   ← sigue activo (para /authenticate) │
│  ★ JWTValidationFilter       ← NUEVO (valida Bearer tokens)      │
│  ★ CsrfCookieFilter          ← de seccion 5                      │
│  AuthorizationFilter                                             │
│                                                                  │
│  Eliminados:                                                     │
│  ✗ ApiKeyFilter              ← reemplazado por JWTValidationFilter│
│  ✗ MyAuthenticationProvider  ← vuelve DaoAuthProvider automatico │
└──────────────────────────────────────────────────────────────────┘
```

---

## 13. Seguridad del JWT — Lo que es seguro y lo que no

| Aspecto | Estado en el curso | En produccion |
|---|---|---|
| **Clave secreta** | Hardcodeada en codigo | Variable de entorno o vault (nunca en codigo) |
| **Algoritmo** | HMAC-SHA256 (simetrico) | RS256 (asimetrico) si multiples servicios validan |
| **Duracion del token** | 5 horas | 15-60 minutos + refresh token |
| **Refresh tokens** | No implementado | Necesario para tokens de corta duracion |
| **Revocacion** | No implementada | Blacklist en Redis o BD |
| **HTTPS** | No configurado | Obligatorio (el token viaja en el header) |

---

## 14. ¿Que cambio respecto a la seccion 7?

| Archivo | Cambio |
|---|---|
| `pom.xml` | +3 dependencias jjwt (api, impl, jackson) |
| `services/JWTService.java` | **Nuevo** — genera y valida tokens JWT |
| `services/JWTUserDetailService.java` | **Nuevo** — UserDetailsService para el flujo JWT |
| `security/JWTValidationFilter.java` | **Nuevo** — filtro que valida Bearer tokens |
| `components/JwtAuthenticationEntryPoint.java` | **Nuevo** — respuesta 401 limpia |
| `controllers/AuthenticationController.java` | **Nuevo** — endpoint POST /authenticate |
| `entites/JWTRequest.java` | **Nuevo** — DTO de request |
| `entites/JWTResponse.java` | **Nuevo** — DTO de response |
| `security/SecurityConfig.java` | +STATELESS, +JWTValidationFilter, +AuthenticationManager bean, /authenticate excluido de CSRF |
| `security/ApiKeyFilter.java` | **Eliminado** |
| `security/MyAuthenticationProvider.java` | **Eliminado** |

---

## 15. ¿Que viene en la siguiente seccion?

En la **Seccion 9** (final) se implementa **OAuth 2.0 Authorization Server** con Spring Authorization Server:

- El servidor se convierte en un **emisor de tokens OAuth2** profesional
- Se crean `PartnerEntity` y `PartnerRegisteredClientService` para gestionar clientes OAuth
- Se reescribe completamente el `SecurityConfig` con la configuracion del Authorization Server
- Se pasa de tokens JWT manuales a un flujo OAuth2 estandar

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `services/JWTService.java` | Genera, parsea y valida tokens JWT con jjwt |
| `services/JWTUserDetailService.java` | UserDetailsService que carga usuarios de PostgreSQL |
| `security/JWTValidationFilter.java` | Filtro que intercepta Bearer tokens y setea SecurityContext |
| `components/JwtAuthenticationEntryPoint.java` | Retorna 401 limpio en vez de redirect a /login |
| `controllers/AuthenticationController.java` | POST /authenticate — valida credenciales y emite JWT |
| `entites/JWTRequest.java` | DTO: { username, password } |
| `entites/JWTResponse.java` | DTO: { jwt } |
| `security/SecurityConfig.java` | STATELESS + JWTValidationFilter + AuthenticationManager bean |
