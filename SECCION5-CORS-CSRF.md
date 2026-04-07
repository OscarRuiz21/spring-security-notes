# Seccion 5: CORS y CSRF

> Notas del curso de Spring Security 6 — Proteccion contra ataques de origen cruzado y falsificacion de peticiones

---

## Objetivo de la seccion

Configurar dos protecciones web fundamentales dentro de la cadena de filtros:

- **CORS (Cross-Origin Resource Sharing)**: Controlar que dominios pueden llamar a tu API
- **CSRF (Cross-Site Request Forgery)**: Proteger contra peticiones falsificadas que explotan la sesion del usuario
- Implementar un **filtro custom** (`CsrfCookieFilter`) que expone el token CSRF como header HTTP
- Entender cuando activar, desactivar o personalizar cada proteccion

---

## Ubicacion en la Arquitectura

```
  1  Request    ┌──────────────────────────────────────────┐
  ────────────► │            Security Filters              │
  Usuario       │                                          │
                │  ┌─────────────┐  ┌────────────────────┐ │
                │  │ CorsFilter  │  │ CsrfFilter         │ │ ◄── ESTAS AQUI
                │  │             │  │ + CsrfCookieFilter │ │
                │  └─────────────┘  └────────────────────┘ │
                │  ┌──────────────────────────────────────┐ │
                │  │ BasicAuthFilter / FormLoginFilter    │ │
                │  └──────────────────────────────────────┘ │
                │  ┌──────────────────────────────────────┐ │
                │  │ AuthorizationFilter                  │ │
                │  └──────────────────────────────────────┘ │
                └──────────────────────────────────────────┘
```

Esta seccion cubre el **paso 1** del diagrama maestro (ver Seccion 1) a mayor profundidad: los Security Filters no son un solo filtro, sino una **cadena ordenada**. CORS y CSRF son filtros que se ejecutan **antes** de la autenticacion. Si un request no pasa CORS o CSRF, nunca llega al `AuthenticationManager`.

---

## 1. CORS — Cross-Origin Resource Sharing

### ¿Que es el problema?

Los navegadores implementan la **Same-Origin Policy**: JavaScript en `http://mi-frontend.com` NO puede hacer requests a `http://mi-api.com` porque son origenes diferentes (distinto dominio, puerto o protocolo).

```
http://mi-frontend.com:4200       http://mi-api.com:8080
┌──────────────────────┐          ┌──────────────────────┐
│  Angular / React     │          │  Spring Boot API     │
│                      │          │                      │
│  fetch("/api/loans") │───✗───►  │  /api/loans          │
│                      │ BLOQUEADO│                      │
│  El NAVEGADOR bloquea│ por Same │                      │
│  la respuesta        │ Origin   │                      │
└──────────────────────┘ Policy   └──────────────────────┘
```

**Importante:** El servidor SI procesa el request y SI envia la respuesta. Es el **navegador** el que la bloquea si no tiene los headers CORS correctos. Herramientas como Postman o curl no aplican Same-Origin Policy — solo navegadores.

### ¿Que es CORS?

CORS es un mecanismo donde el **servidor** dice al navegador: "Tranquilo, yo PERMITO requests desde ese origen". Lo hace via headers HTTP en la respuesta:

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://mi-frontend.com:4200
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
```

### Preflight Request (peticion de verificacion previa)

Para requests "complejos" (PUT, DELETE, headers custom), el navegador envia PRIMERO un request **OPTIONS** preguntando si el servidor acepta:

```
1. Navegador envia automáticamente:
   OPTIONS /api/loans HTTP/1.1
   Origin: http://mi-frontend.com:4200
   Access-Control-Request-Method: POST
   Access-Control-Request-Headers: Authorization

2. Servidor responde:
   HTTP/1.1 200 OK
   Access-Control-Allow-Origin: http://mi-frontend.com:4200
   Access-Control-Allow-Methods: POST
   Access-Control-Allow-Headers: Authorization

3. Solo si el preflight pasa → el navegador envia el request real:
   POST /api/loans HTTP/1.1
   Origin: http://mi-frontend.com:4200
   Authorization: Basic ZGVidWdnZXI6aWRlYXM=
```

### Implementacion: `SecurityConfig.java` — `corsConfigurationSource()`

```java
@Bean
CorsConfigurationSource corsConfigurationSource() {
    var config = new CorsConfiguration();

    // ¿Que ORIGENES pueden llamar a mi API?
    //config.setAllowedOrigins(List.of("http://localhost:4200", "http://my-app.com"));
    config.setAllowedOrigins(List.of("*"));       // "*" = cualquier origen (solo para desarrollo)

    // ¿Que METODOS HTTP se permiten?
    //config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    config.setAllowedMethods(List.of("*"));       // "*" = todos los metodos

    // ¿Que HEADERS puede enviar el cliente?
    config.setAllowedHeaders(List.of("*"));       // "*" = todos los headers

    // Registra esta configuracion para TODAS las rutas
    var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);

    return source;
}
```

**Linea por linea:**

- **`setAllowedOrigins(List.of("*"))`**: En desarrollo se usa `"*"` (acepta todo). En produccion, deberias listar explicitamente los dominios permitidos: `List.of("https://mi-app.com", "https://admin.mi-app.com")`.
- **`setAllowedMethods`**: Que verbos HTTP acepta. Si tu API es solo lectura, podrias limitar a `List.of("GET")`.
- **`setAllowedHeaders`**: Headers que el cliente puede enviar. `Authorization` es critico para enviar el token JWT o Basic Auth.
- **`registerCorsConfiguration("/**", config)`**: Aplica esta politica a TODAS las rutas. Podrias tener politicas diferentes por ruta.

### Activacion en el SecurityFilterChain

```java
http.cors(cors -> corsConfigurationSource());
```

Esta linea conecta la configuracion CORS con la cadena de filtros. Spring Security agrega un `CorsFilter` al principio de la cadena que procesa los headers antes que cualquier otro filtro.

### Configuracion para produccion vs desarrollo

| Configuracion | Desarrollo | Produccion |
|---|---|---|
| `allowedOrigins` | `"*"` | `"https://mi-app.com"` |
| `allowedMethods` | `"*"` | `"GET", "POST", "PUT", "DELETE"` |
| `allowedHeaders` | `"*"` | `"Authorization", "Content-Type"` |
| `allowCredentials` | No configurado | `true` (necesario con cookies) |

> **Seguridad:** `"*"` en `allowedOrigins` + `allowCredentials(true)` es una combinacion **prohibida** por la spec CORS. Si necesitas enviar cookies, DEBES listar origenes explicitos.

---

## 2. CSRF — Cross-Site Request Forgery

### ¿Que es el ataque?

CSRF explota el hecho de que el **navegador envia automaticamente las cookies** (incluyendo la cookie de sesion) con cada request al mismo dominio. Un atacante puede hacer que tu navegador envie un request a tu banco SIN que tu lo sepas:

```
1. Usuario hace login en banco.com → navegador guarda cookie de sesion

2. Usuario visita sitio-malicioso.com que tiene:
   <img src="https://banco.com/api/transferir?destino=atacante&monto=10000" />

3. El navegador envia el request a banco.com
   Y AUTOMATICAMENTE adjunta la cookie de sesion
   → El banco cree que el usuario hizo la transferencia
   → El atacante recibe el dinero

4. El usuario NUNCA vio un formulario, NUNCA hizo clic
   Su navegador hizo el request solo por cargar la imagen
```

### ¿Como protege CSRF?

El servidor genera un **token unico** por sesion. Para cualquier request que modifique datos (POST, PUT, DELETE), el cliente DEBE incluir este token. Como el atacante no tiene acceso al token (esta en otra pestaña/dominio), no puede fabricar el request completo.

```
SIN proteccion CSRF:
   POST /api/transferir
   Cookie: JSESSIONID=abc123    ← el navegador la envia automatico
   → El servidor la acepta (no sabe si fue el usuario o un atacante)

CON proteccion CSRF:
   POST /api/transferir
   Cookie: JSESSIONID=abc123
   Header: X-XSRF-TOKEN=random-token-xyz    ← ESTO el atacante NO lo tiene
   → El servidor valida: ¿el token coincide con el de la sesion?
   → SI → acepta el request
   → NO → 403 Forbidden
```

### ¿Cuando desactivar CSRF?

| Escenario | CSRF | Por que |
|---|---|---|
| App con formularios HTML (server-side rendering) | **Activar** | Usa cookies de sesion → vulnerable a CSRF |
| API REST pura que usa JWT en header Authorization | **Desactivar** | No usa cookies → CSRF no aplica |
| SPA (Angular/React) que consume API | **Activar con cookies** | La SPA puede leer la cookie CSRF y enviar el token como header |
| Comunicacion entre microservicios | **Desactivar** | No hay navegador → no hay ataque CSRF posible |

**Regla general:** Si tu app depende de **cookies de sesion** para autenticacion, necesitas CSRF. Si usa **tokens en headers** (JWT Bearer), no lo necesitas.

---

## 3. Implementacion: Configuracion CSRF

### SecurityConfig — Bloque CSRF completo

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

    // 1. Handler que pone el token CSRF como atributo del request
    var requestHandler = new CsrfTokenRequestAttributeHandler();
    requestHandler.setCsrfRequestAttributeName("_csrf");

    http.authorizeHttpRequests(auth ->
                    auth.requestMatchers("/loans", "/balance", "/accounts", "/cards")
                            .authenticated()
                            .anyRequest().permitAll())
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());

    // 2. Activar CORS
    http.cors(cors -> corsConfigurationSource());

    // 3. Configurar CSRF
    http.csrf(csrf -> csrf
                    // Handler que resuelve el token del request
                    .csrfTokenRequestHandler(requestHandler)

                    // Endpoints publicos NO necesitan token CSRF
                    .ignoringRequestMatchers("/welcome", "/about_us")

                    // Almacena el token en una COOKIE (no en la sesion)
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))

            // 4. Filtro custom que expone el token como header HTTP
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);

    return http.build();
}
```

### Desglose de cada pieza

#### `CsrfTokenRequestAttributeHandler`

```java
var requestHandler = new CsrfTokenRequestAttributeHandler();
requestHandler.setCsrfRequestAttributeName("_csrf");
```

Hace dos cosas:
1. Pone el `CsrfToken` como atributo del request con el nombre `_csrf` (accesible en formularios Thymeleaf como `${_csrf.token}`)
2. Resuelve (valida) el token que viene en el request contra el token esperado

#### `ignoringRequestMatchers("/welcome", "/about_us")`

Los endpoints publicos no necesitan proteccion CSRF porque no modifican datos sensibles. Sin esta linea, incluso un `GET /welcome` requeriria token CSRF.

#### `CookieCsrfTokenRepository.withHttpOnlyFalse()`

En vez de guardar el token CSRF en la sesion del servidor (el default), lo guarda en una **cookie**:

```
Set-Cookie: XSRF-TOKEN=random-token-xyz; Path=/; HttpOnly=false
```

**¿Por que `HttpOnly=false`?** Para que JavaScript pueda leer la cookie. Una SPA (Angular/React) necesita:
1. Leer el token de la cookie `XSRF-TOKEN`
2. Copiarlo al header `X-XSRF-TOKEN` en cada request POST/PUT/DELETE

**¿No es inseguro que JavaScript lea la cookie?** No, porque la misma Same-Origin Policy que da origen a CORS tambien protege aqui: JavaScript de `sitio-malicioso.com` NO puede leer cookies de `banco.com`. Solo JavaScript del mismo dominio puede leerla.

#### `addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)`

Agrega nuestro filtro custom **despues** del `BasicAuthenticationFilter` en la cadena. El orden importa: el token CSRF debe estar disponible DESPUES de la autenticacion.

```
Orden en la cadena de filtros:

  1. CorsFilter               ← Valida CORS
  2. CsrfFilter               ← Valida token CSRF (Spring lo agrega automatico)
  3. BasicAuthenticationFilter ← Autentica con HTTP Basic
  4. CsrfCookieFilter         ← Nuestro filtro: expone token como header ← NUEVO
  5. AuthorizationFilter       ← Verifica permisos
```

---

## 4. CsrfCookieFilter — El Filtro Custom

### Concepto

El `CsrfFilter` de Spring genera y valida el token, pero no lo **expone** como header HTTP en la respuesta. Nuestro filtro custom toma el token y lo pone como header para que el frontend pueda leerlo facilmente.

### Implementacion: `CsrfCookieFilter.java`

```java
package com.javaoscar.app_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

// Extiende OncePerRequestFilter: garantiza que se ejecuta UNA vez por request
// (algunos filtros Servlet pueden ejecutarse multiples veces por forwards/includes)
public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Obtener el token CSRF del request (fue puesto ahi por CsrfFilter)
        var csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

        // 2. Si el token tiene un header name configurado, ponerlo como header de respuesta
        if (Objects.nonNull(csrfToken.getHeaderName())) {
            response.setHeader(csrfToken.getHeaderName(), csrfToken.getToken());
            // Resultado: la respuesta HTTP incluye:
            // X-XSRF-TOKEN: random-token-xyz
        }

        // 3. Continuar con el siguiente filtro de la cadena
        filterChain.doFilter(request, response);
    }
}
```

### ¿Que es `OncePerRequestFilter`?

Es una clase base de Spring que garantiza que `doFilterInternal()` se ejecuta **exactamente una vez** por request HTTP. En el mundo Servlet, un filtro puede ejecutarse multiples veces si hay forwards internos o includes. `OncePerRequestFilter` previene esto.

Todos los filtros internos de Spring Security extienden de `OncePerRequestFilter`: `CsrfFilter`, `BasicAuthenticationFilter`, `AuthorizationFilter`, etc.

### Flujo del CSRF con el filtro custom

```
GET /accounts (primera vez, sin sesion)
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  CsrfFilter (de Spring)                                        │
│  → Genera token: "abc-random-xyz"                               │
│  → Lo pone como atributo del request                            │
│  → Lo envia como cookie:                                        │
│    Set-Cookie: XSRF-TOKEN=abc-random-xyz; HttpOnly=false        │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  BasicAuthenticationFilter                                      │
│  → Autentica al usuario (si hay header Authorization)           │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  CsrfCookieFilter (NUESTRO)                                    │
│  → Lee el token del atributo del request                        │
│  → Lo pone como header de la respuesta:                         │
│    X-XSRF-TOKEN: abc-random-xyz                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
              AccountsController.accounts()
              → Respuesta incluye header X-XSRF-TOKEN


POST /accounts (request que modifica datos)
        │
        ▼
   El frontend lee el header/cookie y lo envia como:
   Header: X-XSRF-TOKEN: abc-random-xyz
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  CsrfFilter (de Spring)                                        │
│  → Busca el token en el request (header X-XSRF-TOKEN)          │
│  → Lo compara con el token de la cookie/sesion                  │
│  → ¿Coinciden? → SI → continua                                 │
│  → ¿No coinciden? → 403 Forbidden                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. MyAuthenticationProvider — Cambio menor

```java
// Antes (seccion 4):
final var authorities = Collections.singletonList(new SimpleGrantedAuthority(customer.getRole()));

// Ahora (seccion 5):
final var authorities = List.of(new SimpleGrantedAuthority(customer.getRole()));
```

Solo un cambio de estilo: `Collections.singletonList()` → `List.of()`. Funcionalmente identicos. `List.of()` es la forma moderna de Java 9+ y produce una lista inmutable.

---

## 6. Resumen Visual — CORS y CSRF en la Cadena de Filtros

```
Request HTTP desde Angular (http://localhost:4200)
    │
    │  POST http://localhost:8080/accounts
    │  Origin: http://localhost:4200
    │  Cookie: XSRF-TOKEN=abc-random-xyz
    │  Header: X-XSRF-TOKEN=abc-random-xyz
    │  Header: Authorization: Basic ZGVidWdnZXI6aWRlYXM=
    │
    ▼
┌────────────────────────────────────────────────────────────────────┐
│  SECURITY FILTER CHAIN                                             │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 1. CorsFilter                                                │  │
│  │    ¿El Origin esta en allowedOrigins?                         │  │
│  │    → "http://localhost:4200" esta en List.of("*")? → SI      │  │
│  │    ¿El metodo POST esta en allowedMethods?                   │  │
│  │    → POST esta en List.of("*")? → SI                        │  │
│  │    → PASA ✅                                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                │                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 2. CsrfFilter                                                │  │
│  │    ¿"/accounts" esta en ignoringRequestMatchers?              │  │
│  │    → NO (solo /welcome y /about_us estan excluidos)          │  │
│  │    → Busca token: header X-XSRF-TOKEN = "abc-random-xyz"    │  │
│  │    → Compara con cookie XSRF-TOKEN = "abc-random-xyz"       │  │
│  │    → ¿Coinciden? → SI → PASA ✅                               │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                │                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 3. BasicAuthenticationFilter                                  │  │
│  │    → Decodifica "ZGVidWdnZXI6aWRlYXM=" → "debugger:ideas"   │  │
│  │    → Autentica via MyAuthenticationProvider                  │  │
│  │    → PASA ✅                                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                │                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 4. CsrfCookieFilter (NUESTRO)                                │  │
│  │    → Pone el token CSRF como header de respuesta              │  │
│  │    → X-XSRF-TOKEN: nuevo-token-para-proximo-request          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                │                                   │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ 5. AuthorizationFilter                                        │  │
│  │    ¿"/accounts" requiere autenticacion? → SI                  │  │
│  │    ¿Hay Authentication en el SecurityContext? → SI            │  │
│  │    → PASA ✅                                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                │                                   │
└────────────────────────────────┼───────────────────────────────────┘
                                 │
                                 ▼
                  AccountsController.accounts()
                  → {"msj": "accounts"}
```

---

## 7. Tabla: ¿Que protege cada mecanismo?

| Ataque | Sin proteccion | Con CORS | Con CSRF |
|---|---|---|---|
| **Script en sitio-malicioso.com llama a tu API** | Funciona | **Bloqueado** por el navegador (Origin no permitido) | No aplica (CORS lo frena primero) |
| **Formulario oculto en sitio-malicioso.com hace POST** | Funciona (el navegador envia cookies) | No aplica (formularios HTML no hacen preflight) | **Bloqueado** (no tiene el token CSRF) |
| **Atacante con Postman/curl** | Funciona | No aplica (no es navegador) | No aplica (no es navegador) |

**Conclusion:** CORS protege contra **JavaScript malicioso en el navegador**. CSRF protege contra **formularios/imagenes maliciosas que explotan cookies**. Ninguno protege contra ataques fuera del navegador (para eso existen autenticacion, autorizacion, rate limiting, etc.).

---

## 8. ¿Que cambio respecto a la seccion 4?

| Archivo | Cambio |
|---|---|
| `security/SecurityConfig.java` | **Reescrito**: agrega CORS config, CSRF config, CsrfCookieFilter, limpia codigo comentado |
| `security/CsrfCookieFilter.java` | **Nuevo** — filtro custom que expone el token CSRF como header |
| `security/MyAuthenticationProvider.java` | Cambio menor: `Collections.singletonList` → `List.of` |

---

## 9. ¿Que viene en la siguiente seccion?

En la **Seccion 6** se agregan **Roles y Authorities** para control de acceso granular:

- Diferencia entre `hasRole()` y `hasAuthority()`
- Nueva entidad `RoleEntity` con relacion ManyToMany
- Reglas de acceso por rol en el `SecurityFilterChain`
- Pasar de "¿estas autenticado?" a "¿que puedes hacer?"

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `security/SecurityConfig.java` | Configuracion CORS + CSRF + registro del filtro custom en la cadena |
| `security/CsrfCookieFilter.java` | **Nuevo** — `OncePerRequestFilter` que expone token CSRF como header HTTP |
| `security/MyAuthenticationProvider.java` | Cambio menor de estilo (`List.of` en vez de `Collections.singletonList`) |
