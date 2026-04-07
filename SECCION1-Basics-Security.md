# Seccion 1: Fundamentos de Spring Security

> Notas del curso de Spring Security 6 — Configuracion basica y primeros conceptos

---

## Objetivo de la seccion

Entender **que hace Spring Security desde el momento en que agregas la dependencia**, como funciona la cadena de filtros por debajo, y como personalizar las primeras reglas de acceso para decidir:

- Que endpoints requieren **autenticacion** (usuario y contraseña)
- Que endpoints son **publicos** (cualquiera puede acceder)
- Que mecanismos de autenticacion se habilitan (**Form Login** y **HTTP Basic**)

---

## Diagrama Maestro: Arquitectura de Autenticacion de Spring Security

Este diagrama representa el flujo completo de autenticacion. Cada seccion del curso profundiza en una pieza de esta arquitectura. Referencialo constantemente para entender donde encaja cada concepto nuevo.

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
  👤            │                              │ ◄──────────── │  (ProviderMgr)  │
  ◄──────────── │      ← SECCION 1 y 5        │  8  Retorna   └──┬──────────▲───┘
  10 Response   │              │               │    resultado      │          │
  🔑            └──────┬───────┼───────────────┘                  4│Itera    7│Retorna
                       │       │                                   │providers │auth
                       2│      9│                                   ▼          │
                        │       │                            ┌─────────────────┴──┐
                        ▼       ▼                            │   Auth Providers   │
                 ┌────────┐  ┌──────────────┐                │                    │ ← SECCION 4
                 │ Auth   │  │  Security    │                │  ← SECCION 4       │
                 │ Token  │  │  Context     │                └──────────┬─────────┘
                 │(UPAT)  │  │  Holder      │                           │
                 └────────┘  └──────────────┘                          6│Carga usuario
                                                                        │
                                                                        ▼
                                                              ┌──────────────────┐
                                                              │ UserDetails      │
                                                              │ Manager/Service  │ ← SECCION 2
                                                              └──────────────────┘
```

### Los 10 pasos del flujo

| Paso | De → A | Que sucede | Seccion |
|---|---|---|---|
| **1** | Usuario → Security Filters | El request HTTP llega a la cadena de filtros | 1 |
| **2** | Security Filters → Authentication Token | El filtro extrae credenciales y crea un `UsernamePasswordAuthenticationToken` (NO autenticado) | 1 |
| **3** | Security Filters → Auth Manager | El filtro delega la autenticacion al `AuthenticationManager` | 1, 4 |
| **4** | Auth Manager → Auth Providers | El `ProviderManager` itera por sus providers hasta encontrar uno que soporte el token | 4 |
| **5** | Auth Providers → Password Encoder | El provider usa el `PasswordEncoder` para comparar el password recibido con el almacenado | 3, 4 |
| **6** | Auth Providers → UserDetails Service | El provider carga los datos del usuario desde la fuente de datos (BD, memoria, etc.) | 2 |
| **7** | Auth Providers → Auth Manager | El provider retorna un `Authentication` autenticado (con authorities) o lanza excepcion | 4 |
| **8** | Auth Manager → Security Filters | El manager retorna el resultado al filtro que inicio la autenticacion | 1 |
| **9** | Security Filters → Security Context | El filtro guarda el `Authentication` exitoso en el `SecurityContextHolder` para el resto del request | 1 |
| **10** | Security Filters → Usuario | El filtro deja pasar el request al controller (o redirige tras login exitoso) | 1 |

> **Esta seccion (1) cubre:** Los Security Filters, el SecurityFilterChain, y la configuracion basica — los pasos **1, 2, 8, 9, 10** del diagrama. Es la capa externa que orquesta todo el flujo.

---

## 1. ¿Que pasa al agregar la dependencia?

### Concepto

Spring Security funciona con un principio de "**seguro por defecto**". El momento en que agregas `spring-boot-starter-security` al `pom.xml`, **TODOS** los endpoints de tu aplicacion quedan protegidos automaticamente. No necesitas escribir ni una linea de codigo de seguridad para que esto ocurra.

### Dependencia: `pom.xml`

```xml
<!-- La unica dependencia necesaria para activar Spring Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### ¿Que hace Spring Boot automaticamente al detectar esta dependencia?

1. **Activa `@EnableWebSecurity`** — registra la cadena de filtros de seguridad como un `@Bean` global
2. **Publica un `UserDetailsService`** — crea un usuario por defecto con username `user` y un password aleatorio que imprime en consola:
   ```
   Using generated security password: 8a7f3b2e-1c4d-4e5f-a6b7-8c9d0e1f2a3b
   ```
3. **Registra un `AuthenticationEventPublisher`** — para publicar eventos de autenticacion (login exitoso, fallido, etc.)
4. **Protege TODOS los endpoints** — cualquier request recibe un `401 Unauthorized` o redireccion al formulario de login

### ¿Por que "seguro por defecto"?

Es una decision de diseño intencional. Es **mucho mas seguro** que te olvides de abrir un endpoint publico (y tengas que ir a abrirlo despues), a que te olvides de proteger un endpoint sensible y quede expuesto en produccion.

> **Principio:** En Spring Security, todo esta cerrado hasta que TU decides abrirlo. Nunca al reves.

---

## 2. La Arquitectura: Cadena de Filtros

### Concepto

Spring Security NO vive dentro de tus controllers. Vive **antes** de ellos, como una serie de filtros que interceptan cada request HTTP antes de que llegue a tu codigo.

### ¿Como funciona?

```
Request HTTP (GET /accounts)
        │
        ▼
┌──────────────────────────────────────────────────────────────────┐
│                     SERVLET CONTAINER (Tomcat)                   │
│                                                                  │
│   ┌──────────────────────────────────────────────────────────┐   │
│   │              DelegatingFilterProxy                       │   │
│   │  "Puente" entre el mundo Servlet y el mundo Spring.      │   │
│   │  Tomcat no sabe de Beans de Spring, asi que este filtro  │   │
│   │  Servlet delega el trabajo al Bean de Spring Security.   │   │
│   └──────────────────────┬───────────────────────────────────┘   │
│                          │                                       │
│   ┌──────────────────────▼───────────────────────────────────┐   │
│   │              FilterChainProxy                            │   │
│   │  El "director" de Spring Security. Tiene una lista de    │   │
│   │  SecurityFilterChain beans y ejecuta la PRIMERA que      │   │
│   │  coincida con el request.                                │   │
│   │                                                          │   │
│   │  Beneficios:                                             │   │
│   │  - Punto central para debugging                          │   │
│   │  - Limpia el SecurityContext al terminar (evita leaks)   │   │
│   │  - Aplica HttpFirewall contra ataques comunes            │   │
│   └──────────────────────┬───────────────────────────────────┘   │
│                          │                                       │
│   ┌──────────────────────▼───────────────────────────────────┐   │
│   │          SecurityFilterChain (TU configuracion)          │   │
│   │                                                          │   │
│   │  Filtro 1: CsrfFilter                                   │   │
│   │  Filtro 2: UsernamePasswordAuthenticationFilter          │   │
│   │            (formLogin)                                   │   │
│   │  Filtro 3: BasicAuthenticationFilter                     │   │
│   │            (httpBasic)                                   │   │
│   │  Filtro 4: AuthorizationFilter                           │   │
│   │            (authorizeHttpRequests)                        │   │
│   │  ... (~15 filtros por defecto ...                        │   │
│   └──────────────────────┬───────────────────────────────────┘   │
│                          │                                       │
└──────────────────────────┼───────────────────────────────────────┘
                           │  (Solo si paso todos los filtros)
                           ▼
                  ┌──────────────────┐
                  │  TU CONTROLLER   │
                  │  AccountsController
                  │  .accounts()     │
                  └──────────────────┘
```

### Las 3 capas clave

| Capa | Responsabilidad | Vive en... |
|---|---|---|
| **DelegatingFilterProxy** | Conecta Tomcat (Servlet) con Spring (Beans). Tomcat no entiende de `@Bean`, asi que este filtro actua como puente | El contenedor Servlet |
| **FilterChainProxy** | Orquesta multiples `SecurityFilterChain`. Elige cual cadena aplica a cada request. Es el "cerebro" de Spring Security | Spring Context |
| **SecurityFilterChain** | La cadena de filtros que TU defines con `HttpSecurity`. Cada filtro hace UNA cosa: uno valida CSRF, otro valida credenciales, otro checa permisos, etc. | Tu clase `@Configuration` |

### ¿Por que una CADENA de filtros en vez de un solo filtro?

Porque cada aspecto de seguridad es independiente:

- **CSRF** no tiene nada que ver con **autenticacion**
- **Autenticacion** (¿quien eres?) no tiene nada que ver con **autorizacion** (¿que puedes hacer?)
- **HTTP Basic** es un mecanismo distinto a **Form Login**

Separarlos en filtros individuales permite **activar/desactivar** cada uno de forma independiente. Quieres desactivar CSRF para tu API REST pero mantener Form Login? Solo tocas la configuracion de CSRF sin afectar nada mas.

---

## 3. El Proyecto Base: Controllers

### Concepto

El proyecto simula una aplicacion bancaria con 6 endpoints. La idea es clasificarlos en dos grupos:

- **Protegidos** (requieren login): operaciones sensibles como cuentas, balance, prestamos, tarjetas
- **Publicos** (sin login): paginas informativas como "about us" y "welcome"

### 3.1 Controllers protegidos

Estos 4 endpoints contienen informacion financiera sensible. Un usuario anonimo NO deberia poder acceder.

```java
// AccountsController.java
@RestController
@RequestMapping(path = "/accounts")
public class AccountsController {

    @GetMapping
    public Map<String, String> accounts() {
        return Collections.singletonMap("msj", "accounts");
    }
}
```

```java
// BalanceController.java
@RestController
@RequestMapping(path = "/balance")
public class BalanceController {

    @GetMapping
    public Map<String, String> balance() {
        return Collections.singletonMap("msj", "balance");
    }
}
```

```java
// LoansController.java
@RestController
@RequestMapping(path = "/loans")
public class LoansController {

    @GetMapping
    public Map<String, String> loans() {
        return Collections.singletonMap("msj", "loans");
    }
}
```

```java
// CardsController.java
@RestController
@RequestMapping(path = "/cards")
public class CardsController {

    @GetMapping
    public Map<String, String> cards() {
        return Collections.singletonMap("msj", "cards");
    }
}
```

Todos siguen el mismo patron: `@RestController` + un unico `@GetMapping` que devuelve un JSON simple. En una app real, aqui iria la logica de negocio (consultar BD, validar datos, etc.).

### 3.2 Controllers publicos

Estos 2 endpoints son informativos. Cualquiera deberia poder verlos sin necesidad de iniciar sesion.

```java
// WelcomeController.java — Pagina de bienvenida
@RestController
@RequestMapping(path = "/welcome")
public class WelcomeController {

    @GetMapping
    public Map<String, String> welcome() {
        return Collections.singletonMap("msj", "welcome");
    }
}
```

```java
// AboutUsController.java — Informacion de la empresa
@RestController
@RequestMapping(path = "/about_us")
public class AboutUsController {

    @GetMapping
    public Map<String, String> about() {
        return Collections.singletonMap("msj", "about");
    }
}
```

---

## 4. Configuracion de Seguridad Personalizada

### Concepto

Sin configuracion custom, Spring Security protege **TODO**. Pero nosotros queremos un comportamiento mas fino:

| Endpoint | Comportamiento deseado |
|---|---|
| `/loans` | Requiere autenticacion |
| `/balance` | Requiere autenticacion |
| `/accounts` | Requiere autenticacion |
| `/cards` | Requiere autenticacion |
| `/welcome` | Publico |
| `/about_us` | Publico |

Para lograr esto, creamos nuestra propia `SecurityFilterChain` que **reemplaza** la configuracion por defecto de Spring Boot.

### Implementacion: `SecurityConfig.java`

```java
package com.javaoscar.app_security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration    // Le dice a Spring: "esta clase tiene beans de configuracion"
public class SecurityConfig {

    @Bean         // Registra este metodo como un bean en el contexto de Spring
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->
                auth.requestMatchers("/loans", "/balance", "/accounts", "/cards")
                        .authenticated()           // Estos 4 → necesitan login
                        .anyRequest().permitAll())  // Todo lo demas → publico
                .formLogin(Customizer.withDefaults())   // Habilita formulario de login
                .httpBasic(Customizer.withDefaults());   // Habilita HTTP Basic
        return http.build();
    }
}
```

### Desglose linea por linea

#### `@Configuration`
Marca la clase como fuente de configuracion de Spring. Spring la escanea al arrancar y ejecuta los metodos anotados con `@Bean`.

#### `SecurityFilterChain securityFilterChain(HttpSecurity http)`
- **`HttpSecurity`**: Es el objeto "constructor" que Spring te inyecta. Con el defines TODA la seguridad de tu app usando el patron Builder.
- **`SecurityFilterChain`**: Lo que retornas. Es la cadena de filtros compilada que Spring Security usara para interceptar cada request.
- **¿Por que `throws Exception`?** Porque `http.build()` puede lanzar excepciones si la configuracion es invalida.

#### `authorizeHttpRequests(auth -> ...)`
Abre el bloque de reglas de autorizacion. Todo lo que va dentro define QUIEN puede acceder a QUE.

```java
auth.requestMatchers("/loans", "/balance", "/accounts", "/cards")
    .authenticated()
```

- **`requestMatchers(...)`**: "Para estos paths..." — acepta uno o varios patrones de URL.
- **`.authenticated()`**: "...el usuario debe estar autenticado". No importa QUE rol tenga, solo que haya hecho login.

```java
    .anyRequest().permitAll()
```

- **`anyRequest()`**: "Para CUALQUIER otro request que no haya matcheado arriba..."
- **`.permitAll()`**: "...dejalo pasar sin pedir credenciales".

> **El orden importa.** Spring evalua las reglas de arriba hacia abajo. Las reglas mas especificas van PRIMERO. Si pones `anyRequest().permitAll()` primero, todas las demas reglas se ignorarian porque todo matchea con `anyRequest()`.

#### `formLogin(Customizer.withDefaults())`

Habilita el mecanismo de **Form Login**:
- Spring genera automaticamente una pagina de login en `/login`
- Si un usuario no autenticado intenta acceder a `/accounts`, Spring lo **redirige** a `/login`
- Despues de autenticarse, lo redirige de vuelta a `/accounts`
- Si falla el login → redireccion a `/login?error`

**`Customizer.withDefaults()`** significa: "Usa la configuracion por defecto de este mecanismo, no quiero personalizar nada."

#### `httpBasic(Customizer.withDefaults())`

Habilita el mecanismo de **HTTP Basic Authentication**:
- El cliente envia credenciales en el header HTTP: `Authorization: Basic base64(user:password)`
- No hay redireccion ni pagina de login — es un intercambio directo entre cliente y servidor
- Ideal para APIs, Postman, curl, o comunicacion entre servicios

**¿Por que habilitar AMBOS?** Porque sirven para clientes diferentes:

| Mecanismo | Caso de uso | Como funciona |
|---|---|---|
| **Form Login** | Navegadores (humanos) | Redirige a una pagina HTML de login |
| **HTTP Basic** | APIs / Postman / curl (programas) | Credenciales en el header, sin HTML |

Si solo habilitas Form Login, las llamadas desde Postman no funcionarian bien. Si solo habilitas HTTP Basic, los usuarios del navegador no tendrian pagina de login.

#### `return http.build()`

Compila toda la configuracion en un objeto `SecurityFilterChain` inmutable. A partir de aqui, Spring Security usa esta cadena para filtrar cada request que entre a tu app.

---

## 5. Clase Principal y `@EnableWebSecurity`

### Implementacion: `AppSecurityApplication.java`

```java
@SpringBootApplication
@EnableWebSecurity       // Activa el sistema completo de Spring Security
public class AppSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(AppSecurityApplication.class, args);
    }
}
```

### ¿Que hace `@EnableWebSecurity`?

Activa **toda la infraestructura** de seguridad web de Spring:

1. Registra el `FilterChainProxy` como filtro global en Tomcat
2. Habilita la importacion de configuraciones de seguridad (`HttpSecurity`, etc.)
3. Publica beans internos necesarios (gerentes de autenticacion, proveedores, etc.)

### ¿Es obligatorio ponerlo?

En Spring Boot, tecnicamente **no**, porque el auto-configurador (`SecurityAutoConfiguration`) ya lo agrega por ti. Pero en el curso se pone explicitamente por dos razones:
- **Claridad**: queda documentado en el codigo que esta app usa seguridad web
- **Control**: si en algun punto desactivas la auto-configuracion, el `@EnableWebSecurity` asegura que la seguridad siga activa

---

## 6. Usuario por Defecto via Properties

### Implementacion: `application.properties`

```properties
spring.security.user.name=debugger
spring.security.user.password=ideas
spring.security.user.roles={ROLE_VIEWER}
```

### ¿Que hace esto?

Reemplaza el usuario generado automaticamente por Spring Boot (`user` + password aleatorio) con uno fijo:

| Propiedad | Valor | Que hace |
|---|---|---|
| `spring.security.user.name` | `debugger` | Username para autenticarse |
| `spring.security.user.password` | `ideas` | Password en texto plano (solo para desarrollo) |
| `spring.security.user.roles` | `{ROLE_VIEWER}` | Rol asignado al usuario |

### ¿Donde almacena Spring este usuario?

Internamente, Spring Boot crea un `InMemoryUserDetailsManager` con este unico usuario. No hay base de datos, no hay archivo externo — vive **en memoria** del proceso Java. Si reinicias la app, se recrea.

### ¿Es seguro?

**NO para produccion.** Tiene dos problemas graves:

1. **Password en texto plano**: cualquiera que lea el archivo `application.properties` (o el repositorio Git) ve la contraseña
2. **Un solo usuario hardcodeado**: no escala para multiples usuarios con diferentes permisos

Esto se usa exclusivamente para **desarrollo y aprendizaje**. En las siguientes secciones se reemplazara por usuarios en base de datos con passwords encriptados.

---

## 7. Flujo Completo de un Request

### Caso 1: Request a endpoint PROTEGIDO sin autenticacion

```
Usuario (navegador)
    │
    │  GET http://localhost:8080/accounts
    │  (sin credenciales)
    ▼
┌─────────────────────────────────────────────────────┐
│  SecurityFilterChain                                │
│                                                     │
│  1. AuthorizationFilter evalua:                     │
│     ¿"/accounts" matchea con requestMatchers()?     │
│     → SI → ¿Esta autenticado? → NO                 │
│                                                     │
│  2. Como tiene formLogin habilitado:                │
│     → Redirige HTTP 302 a /login                    │
│                                                     │
│  3. Spring genera la pagina de login HTML            │
└─────────────────────────────────────────────────────┘
    │
    ▼
Usuario ve el formulario de login
    │
    │  POST /login (username=debugger, password=ideas)
    ▼
┌─────────────────────────────────────────────────────┐
│  UsernamePasswordAuthenticationFilter               │
│                                                     │
│  1. Extrae username y password del form              │
│  2. Crea un UsernamePasswordAuthenticationToken     │
│  3. Lo pasa al AuthenticationManager                │
│  4. AuthenticationManager pregunta al               │
│     InMemoryUserDetailsManager:                     │
│     "¿Existe 'debugger' con password 'ideas'?"      │
│  5. → SI → Crea Authentication exitoso              │
│  6. Guarda en SecurityContext                        │
│  7. Redirige al URL original: /accounts             │
└─────────────────────────────────────────────────────┘
    │
    ▼
AccountsController.accounts() → {"msj": "accounts"}
```

### Caso 2: Request a endpoint PUBLICO

```
Usuario (cualquiera)
    │
    │  GET http://localhost:8080/welcome
    ▼
┌─────────────────────────────────────────────────────┐
│  SecurityFilterChain                                │
│                                                     │
│  AuthorizationFilter evalua:                        │
│  ¿"/welcome" matchea con requestMatchers()?         │
│  → NO → cae en anyRequest().permitAll()             │
│  → Deja pasar sin pedir credenciales                │
└─────────────────────────────────────────────────────┘
    │
    ▼
WelcomeController.welcome() → {"msj": "welcome"}
```

### Caso 3: Request via Postman/curl con HTTP Basic

```
Postman / curl
    │
    │  GET http://localhost:8080/balance
    │  Header: Authorization: Basic ZGVidWdnZXI6aWRlYXM=
    │          (base64 de "debugger:ideas")
    ▼
┌─────────────────────────────────────────────────────┐
│  SecurityFilterChain                                │
│                                                     │
│  BasicAuthenticationFilter:                         │
│  1. Detecta header "Authorization: Basic ..."       │
│  2. Decodifica Base64 → "debugger:ideas"            │
│  3. Valida contra InMemoryUserDetailsManager        │
│  4. → OK → Continua la cadena de filtros            │
│                                                     │
│  AuthorizationFilter:                               │
│  ¿"/balance" requiere autenticacion? → SI           │
│  ¿Hay Authentication valido? → SI                   │
│  → Deja pasar                                       │
└─────────────────────────────────────────────────────┘
    │
    ▼
BalanceController.balance() → {"msj": "balance"}
```

---

## 8. Conceptos Clave de esta Seccion

### `requestMatchers` vs `anyRequest`

| Metodo | Que hace | Ejemplo |
|---|---|---|
| `requestMatchers("/path1", "/path2")` | Selecciona URLs especificas | `requestMatchers("/loans", "/balance")` |
| `anyRequest()` | Selecciona TODO lo que no haya matcheado antes | Siempre va AL FINAL |

**Regla de oro:** Especifico primero, generico despues. `anyRequest()` es el "default" — siempre va ultimo.

### `authenticated()` vs `permitAll()`

| Metodo | Significado |
|---|---|
| `.authenticated()` | El usuario DEBE tener una sesion activa (haber hecho login) |
| `.permitAll()` | Cualquiera puede acceder, autenticado o no |

Existen otros metodos que se veran en secciones posteriores: `hasRole()`, `hasAuthority()`, `denyAll()`, etc.

### `Customizer.withDefaults()` — ¿Que es?

Es la forma en Spring Security 6 de decir: "Habilita este mecanismo con su configuracion por defecto".

```java
// Spring Security 6 (lambda DSL)
.formLogin(Customizer.withDefaults())

// Equivalente a:
.formLogin(form -> {})   // Lambda vacia = "no personalizo nada, usa defaults"
```

En versiones antiguas de Spring Security (pre-6.x) se usaba el estilo encadenado:
```java
// ESTILO VIEJO (deprecated en Spring Security 6):
http.formLogin().and().httpBasic();
```

Spring Security 6 elimino el `.and()` y migro a lambdas para cada modulo de configuracion. `Customizer.withDefaults()` es parte de este nuevo estilo.

---

## 9. Lo que Spring Security da "gratis" (sin escribir configuracion)

Incluso en esta seccion basica, Spring Security ya esta haciendo mucho trabajo invisible:

| Proteccion | Como funciona | ¿Esta activa? |
|---|---|---|
| **Proteccion CSRF** | Genera y valida tokens anti-CSRF en formularios | Si (por defecto) |
| **Headers de seguridad** | Agrega `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control`, etc. | Si (por defecto) |
| **Proteccion contra Session Fixation** | Crea una nueva sesion HTTP despues del login para evitar robo de sesion | Si (por defecto) |
| **HttpFirewall** | Rechaza requests con caracteres sospechosos en la URL (`//`, `..`, `;`, etc.) | Si (via FilterChainProxy) |
| **Limpieza del SecurityContext** | Despues de cada request, limpia el contexto de seguridad para evitar memory leaks | Si (via FilterChainProxy) |
| **Pagina de login auto-generada** | Si habilitas `formLogin` sin personalizar, genera una pagina HTML funcional | Si |
| **Logout** | Endpoint `/logout` disponible automaticamente cuando usas `formLogin` | Si |

No escribiste una sola linea para nada de esto. Todo viene incluido por defecto.

---

## 10. Resumen Visual — Arquitectura de la Seccion

```
┌──────────────────────────────────────────────────────────────────┐
│                     APLICACION BANCARIA                          │
│                                                                  │
│   application.properties                                         │
│   ├── user.name = debugger                                       │
│   ├── user.password = ideas         → InMemoryUserDetailsManager │
│   └── user.roles = ROLE_VIEWER                                   │
│                                                                  │
│   SecurityConfig.java                                            │
│   └── SecurityFilterChain:                                       │
│       ├── /loans, /balance,                                      │
│       │   /accounts, /cards     → .authenticated()               │
│       ├── anyRequest()          → .permitAll()                   │
│       ├── formLogin             → para navegadores               │
│       └── httpBasic             → para APIs / Postman            │
│                                                                  │
│   Controllers:                                                   │
│   ├── /accounts  (protegido)     ├── /welcome   (publico)        │
│   ├── /balance   (protegido)     └── /about_us  (publico)        │
│   ├── /loans     (protegido)                                     │
│   └── /cards     (protegido)                                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 11. Antes vs Despues (Sin Security vs Con Security)

### Sin `spring-boot-starter-security`

| Aspecto | Comportamiento |
|---|---|
| Acceso a endpoints | Cualquiera accede a todo |
| Headers de seguridad | No hay ninguno |
| CSRF | Sin proteccion |
| Login | No existe |
| Session Fixation | Sin proteccion |

### Con `spring-boot-starter-security` + esta configuracion

| Aspecto | Comportamiento |
|---|---|
| Acceso a `/accounts`, `/balance`, `/loans`, `/cards` | Requiere login (usuario: debugger / password: ideas) |
| Acceso a `/welcome`, `/about_us` | Libre para todos |
| Headers de seguridad | Automaticos (X-Frame-Options, X-Content-Type-Options, etc.) |
| CSRF | Activo por defecto |
| Login | Form Login (navegador) + HTTP Basic (API) |
| Logout | Disponible en `/logout` |

---

## 12. ¿Que viene en la siguiente seccion?

En la **Seccion 2** se reemplaza el usuario unico de `application.properties` por usuarios almacenados en **base de datos (MySQL)**, implementando:

- `UserDetailsService` personalizado que consulta la BD
- Entidad JPA `CustomerEntity` para representar usuarios
- Docker Compose para levantar MySQL
- Scripts SQL para crear el esquema y datos iniciales

Es el paso natural: de un usuario hardcodeado a multiples usuarios persistentes.

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `pom.xml` | Dependencias: `spring-boot-starter-web` + `spring-boot-starter-security` |
| `AppSecurityApplication.java` | `@SpringBootApplication` + `@EnableWebSecurity` — punto de entrada |
| `security/SecurityConfig.java` | `SecurityFilterChain` — define que endpoints son protegidos y cuales publicos |
| `application.properties` | Usuario por defecto: `debugger` / `ideas` con `ROLE_VIEWER` |
| `controllers/AccountsController.java` | Endpoint protegido: `/accounts` |
| `controllers/BalanceController.java` | Endpoint protegido: `/balance` |
| `controllers/LoansController.java` | Endpoint protegido: `/loans` |
| `controllers/CardsController.java` | Endpoint protegido: `/cards` |
| `controllers/WelcomeController.java` | Endpoint publico: `/welcome` |
| `controllers/AboutUsController.java` | Endpoint publico: `/about_us` |
