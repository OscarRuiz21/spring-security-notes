# Spring Security 6 — Notas y Codigo Incremental

Notas detalladas + proyecto funcional que cubre Spring Security 6 desde cero hasta un **OAuth2 Authorization Server** con Spring Authorization Server.

Cada seccion tiene su propia **branch** con el codigo incremental y un archivo `.md` con la teoria, diagramas de arquitectura y explicaciones linea por linea.

---

## Diagrama Maestro: Arquitectura de Autenticacion

Todas las secciones giran alrededor de este flujo de 10 pasos:

```
                        ┌────────────────┐
                        │   Password     │
                        │   Encoder      │  ← SECCION 3
                        └───────▲────────┘
                                │
                                5  Valida password
                                │
  1  Request    ┌───────────────┴──────────────┐  3  Delega    ┌─────────────────┐
  ────────────► │                              │ ────────────► │                 │
  Usuario       │       Security Filters       │               │  Auth Manager   │
                │                              │ ◄──────────── │  (ProviderMgr)  │
  ◄──────────── │      ← SECCION 1, 5, 7      │  8  Retorna   └──┬──────────▲───┘
  10 Response   │              │               │    resultado      │          │
                └──────┬───────┼───────────────┘                  4│         7│
                       │       │                                   ▼          │
                       2│      9│                            ┌────────────────┴───┐
                        ▼       ▼                            │   Auth Providers   │
                 ┌────────┐  ┌──────────────┐                │   ← SECCION 4      │
                 │ Auth   │  │  Security    │                └──────────┬─────────┘
                 │ Token  │  │  Context     │                           │
                 └────────┘  └──────────────┘                          6│
                                                                        ▼
                                                              ┌──────────────────┐
                                                              │ UserDetails      │
                                                              │ Manager/Service  │ ← SECCION 2
                                                              └──────────────────┘
```

| Paso | Que sucede | Seccion |
|:---:|---|:---:|
| 1 | Request HTTP llega a la cadena de filtros | 1, 5, 7 |
| 2 | Filtro extrae credenciales y crea `UsernamePasswordAuthenticationToken` | 1 |
| 3 | Filtro delega al `AuthenticationManager` | 4 |
| 4 | `ProviderManager` itera por los `AuthenticationProvider` | 4 |
| 5 | Provider usa `PasswordEncoder` para comparar passwords | 3 |
| 6 | Provider carga datos del usuario via `UserDetailsService` | 2 |
| 7 | Provider retorna `Authentication` autenticado | 4 |
| 8 | Manager retorna resultado al filtro | 1 |
| 9 | Filtro guarda `Authentication` en `SecurityContextHolder` | 1 |
| 10 | Request pasa al Controller (o se rechaza) | 1, 6 |

---

## Secciones

### Seccion 1 — Fundamentos de Spring Security
`Branch: 01/basics-security`

Que hace Spring Security al agregar la dependencia, cadena de filtros (`DelegatingFilterProxy` → `FilterChainProxy` → `SecurityFilterChain`), endpoints protegidos vs publicos, `formLogin` + `httpBasic`, usuario por defecto via properties.

```java
http.authorizeHttpRequests(auth ->
        auth.requestMatchers("/loans", "/balance", "/accounts", "/cards")
                .authenticated()
                .anyRequest().permitAll())
        .formLogin(Customizer.withDefaults())
        .httpBasic(Customizer.withDefaults());
```

---

### Seccion 2 — Usuarios Custom: InMemory, JDBC y JPA
`Branch: 02/custom-users-inMemory-jdbc`

Tres formas de gestionar usuarios: `InMemoryUserDetailsManager`, `JdbcUserDetailsManager`, y `UserDetailsService` custom con JPA. Entidad `CustomerEntity`, repositorio con `findByEmail()`, Docker Compose con PostgreSQL.

```java
@Service
public class CustomerUserDetails implements UserDetailsService {
    public UserDetails loadUserByUsername(String username) {
        return customerRepository.findByEmail(username)
                .map(customer -> new User(customer.getEmail(), customer.getPassword(), authorities))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
```

---

### Seccion 3 — Password Encoders
`Branch: 03/password-encoders`

Historia del almacenamiento de passwords (texto plano → SHA → salt → BCrypt), interfaz `PasswordEncoder` (`encode` + `matches`), `BCryptPasswordEncoder` (salt integrado, work factor adaptativo), comparativa con Argon2, SCrypt, PBKDF2.

```java
// Una linea cambia la seguridad de toda la app
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();  // Hash irreversible + salt aleatorio
}
```

---

### Seccion 4 — Authentication Providers
`Branch: 04/authentication-providers`

`AuthenticationProvider` custom vs `DaoAuthenticationProvider` automatico. Control total del flujo: extraer credenciales, buscar en BD, comparar passwords, crear token autenticado. Contrato de `authenticate()` y `supports()`.

```java
@Component
public class MyAuthenticationProvider implements AuthenticationProvider {
    public Authentication authenticate(Authentication authentication) {
        // Tu controlas TODO: buscar usuario, validar password, crear token
        if (passwordEncoder.matches(pwd, customerPwd)) {
            return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
        }
        throw new BadCredentialsException("Invalid credentials");
    }
}
```

---

### Seccion 5 — CORS y CSRF
`Branch: 05/cors-csrf`

Same-Origin Policy, `CorsConfigurationSource`, Preflight requests. Ataques CSRF, `CookieCsrfTokenRepository.withHttpOnlyFalse()`, filtro custom `CsrfCookieFilter` (`OncePerRequestFilter`), cuando activar/desactivar cada proteccion.

```java
http.cors(cors -> corsConfigurationSource());
http.csrf(csrf -> csrf
        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        .ignoringRequestMatchers("/welcome", "/about_us"))
    .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
```

---

### Seccion 6 — Roles y Authorities
`Branch: 06/roles-authorities`

`hasRole("ADMIN")` vs `hasAuthority("ROLE_ADMIN")` y el prefijo `ROLE_`. Nueva entidad `RoleEntity` con `@OneToMany`. Autorizacion por endpoint. `@PreAuthorize` y `@EnableMethodSecurity` (seguridad a nivel de metodo).

```java
auth
    .requestMatchers("/loans", "/balance").hasRole("USER")
    .requestMatchers("/accounts", "/cards").hasRole("ADMIN")
    .anyRequest().permitAll()
```

| Endpoint | ROLE_ADMIN | ROLE_USER | Anonimo |
|---|:---:|:---:|:---:|
| `/accounts` | 200 | 403 | 401 |
| `/loans` | 403 | 200 | 401 |
| `/welcome` | 200 | 200 | 200 |

---

### Seccion 7 — Filtros Custom
`Branch: 07/filters`

`addFilterBefore`, `addFilterAfter`, `addFilterAt`. `ApiKeyFilter` como `OncePerRequestFilter`. Orden completo de los ~15 filtros de la cadena. `@EnableWebSecurity(debug = true)` para ver la cadena en consola.

```java
// Se ejecuta ANTES de la autenticacion
http.addFilterBefore(new ApiKeyFilter(), BasicAuthenticationFilter.class);
```

```
Cadena: ... → CorsFilter → CsrfFilter → [ApiKeyFilter] → BasicAuthFilter → [CsrfCookieFilter] → AuthorizationFilter
```

---

### Seccion 8 — Autenticacion con JWT
`Branch: 08/jwt`

Stateful (sesiones) → Stateless (tokens). `JWTService` con jjwt (generacion, validacion, firma HMAC-SHA256). `JWTValidationFilter` (Bearer token). `AuthenticationController` (`POST /authenticate`). `SessionCreationPolicy.STATELESS`.

```
Fase 1: POST /authenticate → valida credenciales → genera JWT → { "jwt": "eyJhbG..." }
Fase 2: GET /accounts + Authorization: Bearer eyJhbG... → valida firma → extrae roles → 200 OK
```

```java
http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
http.addFilterAfter(jwtValidationFilter, BasicAuthenticationFilter.class);
```

---

### Seccion 9 — OAuth2 Authorization Server
`Branch: 09/oauth2-authorization-server`

Spring Authorization Server + Resource Server en la misma app. Flujo `authorization_code` completo. RSA asimetrico (`JWKSource`, `JwtDecoder`). `RegisteredClientRepository` con partners en BD. `OAuth2TokenCustomizer` (roles en access token). Dos `SecurityFilterChain` con `@Order`.

```java
@Bean @Order(1)  // Authorization Server (emite tokens)
SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) { ... }

@Bean @Order(2)  // Resource Server (valida tokens y protege endpoints)
SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) { ... }
```

```
Partner → /oauth2/authorize → Login → Consent → code → /oauth2/token → access_token (JWT RSA)
       → GET /accounts + Bearer token → Resource Server valida → 200 OK
```

---

## Evolucion del Proyecto

```
Sec 1   properties user           1 usuario hardcodeado
Sec 2   InMemory / JDBC / JPA    Usuarios en PostgreSQL
Sec 3   NoOpPasswordEncoder       BCryptPasswordEncoder
Sec 4   DaoAuthProvider auto      AuthenticationProvider custom
Sec 5   Sin proteccion web        CORS + CSRF + filtro custom
Sec 6   .authenticated()          hasRole("ADMIN") / hasRole("USER")
Sec 7   Sin filtros custom        ApiKeyFilter (addFilterBefore)
Sec 8   Sesiones (stateful)       JWT manual (HMAC, stateless)
Sec 9   JWT manual                OAuth2 Authorization Server (RSA)
```

---

## Stack Tecnologico

| Tecnologia | Version | Uso |
|---|---|---|
| Java | 17 | Lenguaje |
| Spring Boot | 3.1.1 | Framework base |
| Spring Security | 6.x | Autenticacion y autorizacion |
| Spring Authorization Server | 1.1.1 | OAuth2 Authorization Server (sec. 9) |
| PostgreSQL | 15.2 | Base de datos |
| Docker Compose | 3.8 | Infraestructura local |
| jjwt | 0.11.5 | JWT manual (sec. 8) |
| Lombok | 1.18.28 | Reduccion de boilerplate |

---

## Como Navegar

```bash
# Ver todas las secciones disponibles
git branch

# Ir a una seccion especifica (ej: JWT)
git checkout 08/jwt

# Ver que cambio respecto a la seccion anterior
git diff 07/filters..08/jwt --stat

# Ver el codigo + notas de esa seccion
ls *.md src/main/java/com/javaoscar/app_security/
```

Cada branch contiene:
- **Codigo fuente** incremental del proyecto Spring Boot
- **SECCION{N}-*.md** con teoria, diagramas ASCII y explicaciones linea por linea

---

## Estructura del Proyecto

```
spring-security-notes/
├── README.md
├── SECCION1-Basics-Security.md
├── SECCION2-Custom-Users-InMemory-JDBC.md
├── ...
├── SECCION9-OAuth2-Authorization-Server.md
├── pom.xml
├── docker-compose.yml
├── db/sql/
│   ├── create_schema.sql
│   └── data.sql
└── src/main/java/com/javaoscar/app_security/
    ├── AppSecurityApplication.java
    ├── controllers/
    ├── entites/
    ├── repositories/
    ├── security/
    └── services/
```
