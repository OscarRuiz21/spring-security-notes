# Seccion 7: Filtros Custom en la Cadena de Seguridad

> Notas del curso de Spring Security 6 — Como agregar tus propios filtros al SecurityFilterChain y controlar su orden de ejecucion

---

## Objetivo de la seccion

Entender la cadena de filtros a profundidad e insertar un **filtro personalizado** (`ApiKeyFilter`) que valida una API Key antes de la autenticacion:

- Como crear filtros custom con `OncePerRequestFilter`
- Como posicionarlos en la cadena: `addFilterBefore`, `addFilterAfter`, `addFilterAt`
- El orden completo de los filtros de Spring Security
- Como usar `@EnableWebSecurity(debug = true)` para ver la cadena en accion

---

## Ubicacion en la Arquitectura

```
  1  Request    ┌──────────────────────────────────────────────────┐
  ────────────► │               Security Filters                   │
  Usuario       │                                                  │
                │  ┌──────────────┐                                │
                │  │ CorsFilter   │                                │
                │  └──────┬───────┘                                │
                │         ▼                                        │
                │  ┌──────────────┐                                │
                │  │ CsrfFilter   │                                │
                │  └──────┬───────┘                                │
                │         ▼                                        │
                │  ┌──────────────┐                                │
                │  │ ApiKeyFilter │ ◄── ESTAS AQUI (NUEVO)         │
                │  └──────┬───────┘                                │
                │         ▼                                        │
                │  ┌──────────────────────┐                        │
                │  │ BasicAuthFilter      │──── 3 → AuthManager    │
                │  └──────┬───────────────┘                        │
                │         ▼                                        │
                │  ┌──────────────────────┐                        │
                │  │ CsrfCookieFilter     │                        │
                │  └──────┬───────────────┘                        │
                │         ▼                                        │
                │  ┌──────────────────────┐                        │
                │  │ AuthorizationFilter  │                        │
                │  └──────────────────────┘                        │
                └──────────────────────────────────────────────────┘
```

Esta seccion profundiza en el **paso 1** del diagrama maestro (ver Seccion 1): los Security Filters son una **cadena ordenada** y puedes insertar tus propios filtros en cualquier posicion. El `ApiKeyFilter` se inserta **antes** del `BasicAuthenticationFilter` como una capa adicional de validacion.

---

## 1. ¿Por que agregar filtros custom?

### Concepto

Spring Security viene con ~15 filtros por defecto (CORS, CSRF, autenticacion, autorizacion, etc.). Pero hay casos donde necesitas logica adicional que no esta cubierta:

| Caso de uso | Filtro custom |
|---|---|
| Validar una API Key antes de autenticar | `ApiKeyFilter` (esta seccion) |
| Logging de todos los requests | `RequestLoggingFilter` |
| Rate limiting | `RateLimitFilter` |
| Validar un JWT propio | `JWTValidationFilter` (seccion 8) |
| Agregar headers custom a la respuesta | `CsrfCookieFilter` (seccion 5) |
| Validar tenant en apps multi-tenant | `TenantFilter` |

Los filtros custom se insertan en la cadena existente en una posicion que tu eliges.

---

## 2. Tres formas de posicionar un filtro

### `addFilterBefore(filter, referenceFilter)`

Inserta tu filtro **ANTES** del filtro de referencia.

```java
http.addFilterBefore(new ApiKeyFilter(), BasicAuthenticationFilter.class);
// Orden: ... → CsrfFilter → ApiKeyFilter → BasicAuthFilter → ...
```

**Caso de uso:** Validaciones que deben ocurrir ANTES de la autenticacion (API keys, rate limiting, IP whitelist).

### `addFilterAfter(filter, referenceFilter)`

Inserta tu filtro **DESPUES** del filtro de referencia.

```java
http.addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
// Orden: ... → BasicAuthFilter → CsrfCookieFilter → ...
```

**Caso de uso:** Logica que requiere que la autenticacion ya haya ocurrido (logging con info del usuario, headers de respuesta).

### `addFilterAt(filter, referenceFilter)`

Inserta tu filtro **EN LA MISMA POSICION** que el filtro de referencia. **No lo reemplaza** — ambos se ejecutan, pero el orden entre ellos no esta garantizado.

```java
http.addFilterAt(new MyAuthFilter(), BasicAuthenticationFilter.class);
// Orden: ambos en la misma posicion (no recomendado generalmente)
```

**Caso de uso:** Raro. Solo cuando quieres un filtro al mismo nivel logico que otro.

### Resumen visual

```
addFilterBefore(X, Basic):    ... → CsrfFilter → [X] → BasicAuthFilter → ...
addFilterAfter(X, Basic):     ... → CsrfFilter → BasicAuthFilter → [X] → ...
addFilterAt(X, Basic):        ... → CsrfFilter → [X + BasicAuthFilter] → ...
                                                  (orden no garantizado)
```

---

## 3. Implementacion: `ApiKeyFilter.java`

### Concepto

El `ApiKeyFilter` es una capa de seguridad adicional: antes de que Spring Security intente autenticar al usuario (con HTTP Basic o Form Login), verifica que el request traiga una **API Key valida** en un header HTTP. Si no la trae o es incorrecta, el request se rechaza inmediatamente sin llegar siquiera a la autenticacion.

### Codigo completo

```java
package com.javaoscar.app_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

public class ApiKeyFilter extends OncePerRequestFilter {

    // API Key esperada (hardcoded para el ejemplo)
    private static final String API_KEY = "myKey";

    // Nombre del header HTTP donde debe venir la key
    private static final String API_KEY_HEADER = "api_key";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        try {
            // 1. Leer el header "api_key" del request
            final var apiKeyOpt = Optional.of(request.getHeader(API_KEY_HEADER));

            // 2. Si no viene el header → excepcion
            final var apiKey = apiKeyOpt
                    .orElseThrow(() -> new BadCredentialsException("No header api key"));

            // 3. Si viene pero no coincide → excepcion
            if (!apiKey.equals(API_KEY)) {
                throw new BadCredentialsException("Invalid api key");
            }

        } catch (Exception e) {
            // 4. Cualquier error → rechazar con BadCredentialsException
            throw new BadCredentialsException("Invalid api key");
        }

        // 5. Solo si paso todas las validaciones → continua con el siguiente filtro
        filterChain.doFilter(request, response);
    }
}
```

### Desglose

#### ¿Por que `OncePerRequestFilter`?

Ya lo vimos en la seccion 5 con `CsrfCookieFilter`: garantiza ejecucion exactamente **una vez** por request. Es la clase base recomendada para cualquier filtro custom en Spring Security.

#### ¿Por que `BadCredentialsException`?

Es una subclase de `AuthenticationException`. Spring Security la intercepta y la convierte en una respuesta `401 Unauthorized`. Si usaras una excepcion generica, el comportamiento seria diferente (posiblemente un 500 Internal Server Error).

#### El patron try-catch completo

```java
try {
    // Validaciones...
} catch (Exception e) {
    throw new BadCredentialsException("Invalid api key");
}
```

El `catch(Exception)` cubre un caso especifico: si `request.getHeader("api_key")` retorna `null`, `Optional.of(null)` lanza `NullPointerException`. El catch lo convierte en un `BadCredentialsException` limpio.

> **Nota:** `Optional.of(null)` lanza excepcion. Lo correcto seria `Optional.ofNullable(request.getHeader(...))`. El try-catch compensa este error, pero en produccion usarias `ofNullable` directamente.

#### `filterChain.doFilter(request, response)`

**La linea mas importante de cualquier filtro.** Si no la llamas, la cadena se DETIENE — el request nunca llega al siguiente filtro ni al controller. Es el equivalente a "pasar la pelota al siguiente".

```
Si llamas filterChain.doFilter():    Tu filtro → Siguiente filtro → ... → Controller
Si NO llamas filterChain.doFilter(): Tu filtro → FIN (el request muere aqui)
```

En este caso, si la API Key es invalida, la excepcion se lanza ANTES de `filterChain.doFilter()`, asi que la cadena se interrumpe.

---

## 4. Registro en SecurityConfig

### Antes (Seccion 6)

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    var requestHandler = new CsrfTokenRequestAttributeHandler();
    // ... (sin ApiKeyFilter)
```

### Ahora (Seccion 7)

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // NUEVO: ApiKeyFilter ANTES de BasicAuthenticationFilter
    http.addFilterBefore(new ApiKeyFilter(), BasicAuthenticationFilter.class);

    var requestHandler = new CsrfTokenRequestAttributeHandler();
    // ... (resto igual)
```

**Una sola linea** agrega el filtro a toda la cadena. Cada request que entre a la app pasara primero por `ApiKeyFilter` antes de intentar autenticarse.

### Limpieza del SecurityConfig

Tambien se limpio codigo comentado de secciones anteriores (las alternativas de `hasAuthority`, `@EnableMethodSecurity`, etc.). El config queda mas limpio y enfocado.

---

## 5. `@EnableWebSecurity(debug = true)`

### Antes

```java
@EnableWebSecurity
```

### Ahora

```java
@EnableWebSecurity(debug = true)
```

### ¿Que hace?

Imprime en consola la **cadena completa de filtros** que Spring Security aplica a cada request. Ejemplo de output:

```
Security filter chain: [
  DisableEncodeUrlFilter
  WebAsyncManagerIntegrationFilter
  SecurityContextHolderFilter
  HeaderWriterFilter
  CorsFilter
  CsrfFilter
  LogoutFilter
  ApiKeyFilter                        ← TU FILTRO CUSTOM (antes de BasicAuth)
  BasicAuthenticationFilter
  CsrfCookieFilter                    ← TU FILTRO CUSTOM (despues de BasicAuth)
  RequestCacheAwareFilter
  SecurityContextHolderAwareRequestFilter
  AnonymousAuthenticationFilter
  ExceptionTranslationFilter
  AuthorizationFilter
]
```

**Solo para desarrollo.** En produccion, `debug = true` expone informacion sensible sobre la configuracion de seguridad en los logs. Nunca lo dejes activado en produccion.

### ¿Para que sirve?

- **Debugging:** Verificar que tus filtros estan en la posicion correcta
- **Aprendizaje:** Ver TODOS los filtros que Spring Security registra por defecto
- **Diagnostico:** Si un request es rechazado inesperadamente, ver en que filtro falla

---

## 6. Orden Completo de los Filtros

### La cadena por defecto + filtros custom

```
┌──────────────────────────────────────────────────────────────────┐
│  SECURITY FILTER CHAIN — Orden de ejecucion                     │
│                                                                  │
│  ┌────────────────────────────────────┐                          │
│  │ 1. DisableEncodeUrlFilter          │  Previene session ID     │
│  │ 2. SecurityContextHolderFilter     │  Carga SecurityContext   │
│  │ 3. HeaderWriterFilter              │  Headers de seguridad    │
│  ├────────────────────────────────────┤                          │
│  │ 4. CorsFilter                      │  Valida CORS (sec. 5)   │
│  │ 5. CsrfFilter                      │  Valida CSRF (sec. 5)   │
│  │ 6. LogoutFilter                    │  Maneja /logout          │
│  ├────────────────────────────────────┤                          │
│  │ 7. ★ ApiKeyFilter                  │  TU FILTRO (sec. 7)     │
│  │    addFilterBefore(BasicAuth)      │  Valida API Key          │
│  ├────────────────────────────────────┤                          │
│  │ 8. BasicAuthenticationFilter       │  HTTP Basic auth         │
│  │    (o UsernamePasswordAuthFilter)  │  (o Form Login)          │
│  ├────────────────────────────────────┤                          │
│  │ 9. ★ CsrfCookieFilter             │  TU FILTRO (sec. 5)     │
│  │    addFilterAfter(BasicAuth)       │  Expone CSRF token       │
│  ├────────────────────────────────────┤                          │
│  │ 10. AnonymousAuthenticationFilter  │  Crea auth anonima      │
│  │ 11. ExceptionTranslationFilter     │  Traduce excepciones     │
│  │ 12. AuthorizationFilter            │  hasRole(), hasAuth()    │
│  └────────────────────────────────────┘                          │
│                                                                  │
│  Si TODOS pasan → request llega al Controller                    │
│  Si CUALQUIERA falla → 401/403 (nunca llega al Controller)      │
└──────────────────────────────────────────────────────────────────┘
```

### ¿Que pasa si un filtro falla?

```
Filtro falla (lanza excepcion)
        │
        ▼
ExceptionTranslationFilter captura la excepcion
        │
        ├── AuthenticationException (401) → redirige a /login o envia 401
        │                                   (BadCredentialsException es de este tipo)
        │
        └── AccessDeniedException (403) → envia 403 Forbidden
```

El `ExceptionTranslationFilter` esta casi al final de la cadena, pero **captura excepciones** que lanzaron filtros anteriores. Es el "catch global" de la cadena de seguridad.

---

## 7. Flujo Completo — Request con y sin API Key

### Request SIN API Key

```
GET /accounts
Header: Authorization: Basic ZGVidWdnZXI6aWRlYXM=
(SIN header api_key)
        │
        ▼
CorsFilter → OK
CsrfFilter → OK (GET no requiere CSRF)
        │
        ▼
┌─────────────────────────────────────────────────┐
│  ApiKeyFilter                                   │
│  request.getHeader("api_key") → null            │
│  Optional.of(null) → NullPointerException       │
│  catch → BadCredentialsException                │
│  → 401 Unauthorized ❌                           │
│                                                 │
│  filterChain.doFilter() NUNCA se llama          │
│  → BasicAuthFilter NUNCA se ejecuta             │
│  → El controller NUNCA se ejecuta               │
└─────────────────────────────────────────────────┘
```

### Request CON API Key valida

```
GET /accounts
Header: api_key: myKey
Header: Authorization: Basic ZGVidWdnZXI6aWRlYXM=
        │
        ▼
CorsFilter → OK
CsrfFilter → OK
        │
        ▼
┌─────────────────────────────────────────────────┐
│  ApiKeyFilter                                   │
│  request.getHeader("api_key") → "myKey"         │
│  "myKey".equals("myKey") → true                 │
│  → filterChain.doFilter() ✅                     │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  BasicAuthenticationFilter                      │
│  Decodifica "ZGVidWdnZXI6aWRlYXM="             │
│  → username: account@..., password: to_be_encoded│
│  → MyAuthenticationProvider.authenticate()       │
│  → OK ✅                                         │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────┐
│  AuthorizationFilter                            │
│  hasRole("ADMIN") → [ROLE_ADMIN] → SI ✅        │
└────────────────────┬────────────────────────────┘
                     │
                     ▼
         AccountsController → {"msj": "accounts"}
```

---

## 8. API Key en la Vida Real

### ¿Cuando usar API Keys?

| Escenario | Mecanismo recomendado |
|---|---|
| Identificar al **cliente/aplicacion** que llama a tu API | **API Key** |
| Identificar al **usuario** que hace la accion | **Autenticacion** (JWT, Basic, OAuth) |
| Ambos: saber que app Y que usuario | **API Key + Autenticacion** (como en esta seccion) |

### Lo que NO es seguro en este ejemplo

En produccion, la API Key NO deberia estar hardcodeada:

```java
// ❌ MAL — hardcodeado en el codigo
private static final String API_KEY = "myKey";

// ✅ MEJOR — leerla de configuracion
@Value("${app.security.api-key}")
private String apiKey;

// ✅ AUN MEJOR — validar contra una BD de API keys
// para soportar multiples clientes con keys diferentes
private final ApiKeyRepository apiKeyRepository;
```

---

## 9. ¿Que cambio respecto a la seccion 6?

| Archivo | Cambio |
|---|---|
| `security/ApiKeyFilter.java` | **Nuevo** — filtro custom que valida API Key en header |
| `security/SecurityConfig.java` | `addFilterBefore(ApiKeyFilter, BasicAuthFilter)` + limpieza de codigo comentado |
| `AppSecurityApplication.java` | `@EnableWebSecurity(debug = true)` para ver la cadena de filtros |

---

## 10. Resumen Visual

```
┌─────────────────────────────────────────────────────────────────────┐
│                     FILTROS EN LA CADENA                             │
│                                                                     │
│  @EnableWebSecurity(debug = true) → imprime la cadena en consola    │
│                                                                     │
│  Tres formas de insertar filtros:                                   │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  addFilterBefore(X, Ref) → X se ejecuta ANTES que Ref         │ │
│  │  addFilterAfter(X, Ref)  → X se ejecuta DESPUES que Ref       │ │
│  │  addFilterAt(X, Ref)     → X se ejecuta al MISMO NIVEL que Ref│ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Cadena actual:                                                     │
│  ... → CorsFilter → CsrfFilter → [ApiKeyFilter] →                  │
│        BasicAuthFilter → [CsrfCookieFilter] →                      │
│        AuthorizationFilter → Controller                             │
│                                                                     │
│  Si ApiKeyFilter falla → 401 (nunca llega a BasicAuth)              │
│  Si BasicAuth falla    → 401 (nunca llega a AuthorizationFilter)    │
│  Si Authorization falla → 403 (nunca llega al Controller)           │
│                                                                     │
│  ★ Filtros custom de este curso:                                    │
│  ├── ApiKeyFilter (sec 7)       — addFilterBefore(BasicAuth)        │
│  └── CsrfCookieFilter (sec 5)  — addFilterAfter(BasicAuth)         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. ¿Que viene en la siguiente seccion?

En la **Seccion 8** se implementa **autenticacion con JWT** (JSON Web Tokens):

- Se reemplaza el filtro `ApiKeyFilter` por un `JWTValidationFilter`
- Se crea un `JWTService` para generar y validar tokens
- Se agrega un `AuthenticationController` con endpoint `/authenticate` que emite JWTs
- Se pasa de autenticacion **stateful** (sesiones) a **stateless** (tokens)

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `security/ApiKeyFilter.java` | **Nuevo** — `OncePerRequestFilter` que valida API Key en header `api_key` |
| `security/SecurityConfig.java` | `addFilterBefore(ApiKeyFilter, BasicAuthFilter)` + limpieza |
| `AppSecurityApplication.java` | `@EnableWebSecurity(debug = true)` para debugging de la cadena |
