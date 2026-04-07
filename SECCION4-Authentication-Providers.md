# Seccion 4: Authentication Providers

> Notas del curso de Spring Security 6 — Tomar control total del proceso de autenticacion con un AuthenticationProvider custom

---

## Objetivo de la seccion

Reemplazar el flujo automatico de `DaoAuthenticationProvider` + `UserDetailsService` por un **`AuthenticationProvider` custom** que hace la autenticacion directamente, entendiendo:

- La diferencia entre **delegar** la autenticacion (via `UserDetailsService`) y **hacerla tu mismo** (via `AuthenticationProvider`)
- Como funciona la cadena `AuthenticationManager` → `ProviderManager` → `AuthenticationProvider`
- Los dos metodos del contrato: `authenticate()` y `supports()`
- Cuando conviene cada enfoque

---

## Ubicacion en la Arquitectura

```
                        ┌────────────────┐
                        │ Password       │
                        │ Encoder        │
                        └───────▲────────┘
                                │ 5
  Auth Manager ──── 4 ──►┌─────┴────────────┐──── 7 ──► Auth Manager
                         │  Auth Providers  │ ◄── ESTAS AQUI
                         └─────┬────────────┘
                               │ 6
                               ▼
                        ┌──────────────────┐
                        │ UserDetails      │
                        │ Manager/Service  │
                        └──────────────────┘
```

Esta seccion cubre los **pasos 4, 5, 6 y 7** del diagrama maestro (ver Seccion 1): el `AuthenticationProvider` es el nucleo de la autenticacion. Recibe el token del `AuthManager` (4), carga el usuario (6), valida el password (5), y retorna el resultado (7). Aqui se toma control total de esos 4 pasos en una sola clase.

---

## 1. Dos niveles de personalizacion

### Concepto

En las secciones 2-3 personalizamos **donde buscar usuarios** (`UserDetailsService` custom), pero el PROCESO de autenticacion (buscar usuario → comparar password → crear token) lo hacia `DaoAuthenticationProvider` automaticamente.

Ahora subimos un nivel: controlamos el **proceso completo**.

```
NIVEL 1 — UserDetailsService (secciones 2-3):
   "Spring, yo te digo DONDE buscar al usuario. Tu haces el resto."

   DaoAuthenticationProvider (de Spring):
   1. Llama a tu UserDetailsService.loadUserByUsername()  ← tu codigo
   2. Llama a passwordEncoder.matches()                   ← automatico
   3. Crea el Authentication token                        ← automatico
   4. Lanza excepciones si falla                          ← automatico


NIVEL 2 — AuthenticationProvider (esta seccion):
   "Spring, yo controlo TODO el proceso de autenticacion."

   MyAuthenticationProvider (tu codigo):
   1. Extraer username y password del request              ← tu codigo
   2. Buscar al usuario en la BD                           ← tu codigo
   3. Comparar passwords                                   ← tu codigo
   4. Crear el Authentication token                        ← tu codigo
   5. Lanzar excepciones si falla                          ← tu codigo
```

### ¿Cuando usar cada nivel?

| Nivel | Usa cuando... | Ejemplo |
|---|---|---|
| **UserDetailsService** | Solo necesitas cambiar la **fuente de datos** (BD, LDAP, API) pero el flujo estandar de username+password te sirve | La mayoria de las apps web |
| **AuthenticationProvider** | Necesitas **logica custom** en el proceso de autenticacion | Multi-factor auth, validar contra API externa, logica de bloqueo de cuenta, autenticacion por certificado, audit logging custom |

---

## 2. La Arquitectura de Autenticacion

### Concepto

Spring Security tiene una cadena de responsabilidad para la autenticacion:

```
Request con credenciales (username + password)
        │
        ▼
┌───────────────────────────────────────────────────────────────┐
│  Authentication Filter                                        │
│  (UsernamePasswordAuthenticationFilter o BasicAuthFilter)      │
│                                                               │
│  Extrae las credenciales del request y crea un                │
│  UsernamePasswordAuthenticationToken (NO autenticado)         │
│  → { principal: "super_user@...", credentials: "ideas" }     │
└──────────────────────────┬────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────────┐
│  AuthenticationManager (interfaz)                             │
│  └── ProviderManager (implementacion)                        │
│                                                               │
│      Tiene una LISTA de AuthenticationProviders.              │
│      Itera por cada uno y pregunta:                           │
│      "¿Soportas este tipo de Authentication?"                 │
│                                                               │
│      Provider 1: supports(UsernamePasswordAuthToken)? → NO   │
│      Provider 2: supports(UsernamePasswordAuthToken)? → SI   │
│        → Llama a provider2.authenticate(token)               │
│        → Si retorna Authentication → EXITO                    │
│        → Si lanza excepcion → FALLO                          │
└──────────────────────────┬────────────────────────────────────┘
                           │
                           ▼
                   SecurityContextHolder
                   (guarda el Authentication exitoso)
```

### ¿Que es el `ProviderManager`?

Es la implementacion por defecto de `AuthenticationManager`. Su trabajo es simple pero crucial: **iterar** por una lista de `AuthenticationProvider` hasta encontrar uno que soporte el tipo de token recibido.

**¿Por que una lista?** Porque una app puede tener multiples formas de autenticarse:
- Provider 1: username + password (formulario web)
- Provider 2: OAuth2 token (login con Google)
- Provider 3: certificado X.509 (mutual TLS)

Cada provider solo responde por su tipo de token. El `ProviderManager` los orquesta.

---

## 3. La Interfaz `AuthenticationProvider`

### Concepto

```java
public interface AuthenticationProvider {

    // Ejecuta la autenticacion. Recibe un token NO autenticado,
    // y retorna un token AUTENTICADO (con authorities) o lanza excepcion.
    Authentication authenticate(Authentication authentication) throws AuthenticationException;

    // ¿Este provider soporta este tipo de token?
    // Si retorna false, el ProviderManager lo salta y prueba el siguiente.
    boolean supports(Class<?> authentication);
}
```

**Contrato de `authenticate()`:**
- Recibe un `Authentication` NO autenticado (tiene username y password, pero no authorities ni estado "autenticado")
- Si las credenciales son validas → retorna un `Authentication` AUTENTICADO (con authorities y `isAuthenticated() = true`)
- Si las credenciales son invalidas → lanza `AuthenticationException` (como `BadCredentialsException`)
- Si este provider no puede manejar este tipo → retorna `null` (el ProviderManager prueba el siguiente)

**Contrato de `supports()`:**
- Retorna `true` si este provider puede intentar autenticar tokens de la clase dada
- Retornar `true` NO garantiza que la autenticacion sera exitosa — solo que puede intentarlo

---

## 4. Implementacion: `MyAuthenticationProvider.java`

```java
package com.javaoscar.app_security.security;

import com.javaoscar.app_security.repositories.CustomerRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component          // Se registra como bean → Spring lo detecta automaticamente
@AllArgsConstructor // Lombok: genera constructor para inyeccion de dependencias
public class MyAuthenticationProvider implements AuthenticationProvider {

    private CustomerRepository customerRepository;  // Para buscar en la BD
    private PasswordEncoder passwordEncoder;         // Para comparar passwords

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        // 1. Extraer credenciales del token NO autenticado
        final var username = authentication.getName();              // "super_user@..."
        final var pwd = authentication.getCredentials().toString(); // "to_be_encoded"

        // 2. Buscar al usuario en PostgreSQL
        final var customerFromDb = this.customerRepository.findByEmail(username);

        // 3. Si no existe → excepcion (misma excepcion para user no encontrado
        //    Y password incorrecto — no revelar cual fue el error)
        final var customer = customerFromDb
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        final var customerPwd = customer.getPassword();

        // 4. Comparar passwords usando el PasswordEncoder
        if (passwordEncoder.matches(pwd, customerPwd)) {

            // 5. EXITO: crear token AUTENTICADO con las authorities
            final var authorities = Collections.singletonList(
                    new SimpleGrantedAuthority(customer.getRole())
            );
            return new UsernamePasswordAuthenticationToken(username, pwd, authorities);

        } else {
            // 6. FALLO: password incorrecto
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // "Yo manejo tokens de tipo UsernamePasswordAuthenticationToken"
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
```

### Desglose detallado

#### `@Component` en vez de `@Service`

Ambos funcionan como bean de Spring. La diferencia es **semantica**: `@Service` implica logica de negocio, `@Component` implica un componente generico de infraestructura. Un authentication provider es infraestructura de seguridad, no logica de negocio, asi que `@Component` es mas apropiado.

**Lo importante:** `@Component` hace que Spring lo registre como bean. El `ProviderManager` busca automaticamente todos los beans que implementen `AuthenticationProvider` y los agrega a su lista.

#### `authentication.getName()` y `authentication.getCredentials()`

El objeto `Authentication` que recibe tiene 2 datos:
- **`getName()`** → el username (lo que el usuario escribio en el campo "username" del formulario)
- **`getCredentials()`** → el password (lo que escribio en el campo "password")

En este punto, el token esta en estado "no autenticado": tiene credenciales pero no tiene authorities ni ha sido validado.

#### ¿Por que `BadCredentialsException` para AMBOS casos?

```java
// Usuario no encontrado:
.orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

// Password incorrecto:
throw new BadCredentialsException("Invalid credentials");
```

**Seguridad por oscuridad:** Si dijeras "usuario no encontrado" vs "password incorrecto", un atacante sabria si el email existe en tu BD. Con el mismo mensaje generico para ambos, no revelas informacion.

#### El token retornado: `UsernamePasswordAuthenticationToken`

```java
// Constructor con 3 argumentos → crea token AUTENTICADO
return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
```

Este constructor es diferente al de 2 argumentos:

| Constructor | Estado | Uso |
|---|---|---|
| `new UPAT(principal, credentials)` | `isAuthenticated() = false` | Lo crea el Filter ANTES de autenticar |
| `new UPAT(principal, credentials, authorities)` | `isAuthenticated() = true` | Lo crea el Provider DESPUES de autenticar |

El tercer parametro (`authorities`) marca la diferencia: si tiene authorities, Spring lo considera autenticado.

#### `supports()` — El filtro de tipo

```java
public boolean supports(Class<?> authentication) {
    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
}
```

`isAssignableFrom` checa si el tipo recibido ES o HEREDA de `UsernamePasswordAuthenticationToken`. Este provider solo maneja autenticacion de tipo username+password. Si llegara un token de otro tipo (ej: `BearerTokenAuthenticationToken` de OAuth2), retorna `false` y el `ProviderManager` busca otro provider.

---

## 5. ¿Que se elimino?

### `CustomerUserDetails.java` — ELIMINADO

El archivo completo se borro. Ya no necesitamos `UserDetailsService` porque ahora `MyAuthenticationProvider` hace todo el trabajo directamente:

```
ANTES (Seccion 2-3):
   DaoAuthenticationProvider (Spring)
       ├── Llama a CustomerUserDetails.loadUserByUsername()
       ├── Llama a passwordEncoder.matches()
       └── Crea el token autenticado

AHORA (Seccion 4):
   MyAuthenticationProvider (tu codigo)
       ├── Busca en CustomerRepository directamente
       ├── Llama a passwordEncoder.matches()
       └── Crea el token autenticado
```

La responsabilidad de cargar el usuario se movio de una clase dedicada (`UserDetailsService`) a dentro del provider. Es mas control pero menos separacion de responsabilidades.

---

## 6. SecurityConfig — Cambios

```java
@Bean
PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();  // Volvio a NoOp para simplificar el ejemplo
}
```

**Nota:** El `PasswordEncoder` volvio a `NoOpPasswordEncoder` en esta rama. Esto es un detalle del repo del curso — en produccion usarias `BCryptPasswordEncoder` como en la seccion 3. El concepto de esta seccion es el `AuthenticationProvider`, no el encoder.

El `SecurityFilterChain` no cambio — sigue con las mismas reglas de la seccion 1.

---

## 7. Flujo Completo con el Provider Custom

```
POST /login (username=super_user@debuggeandoideas.com, password=to_be_encoded)
        │
        ▼
┌───────────────────────────────────────────────────────────────────┐
│  UsernamePasswordAuthenticationFilter                             │
│  → Crea: UPAT("super_user@...", "to_be_encoded")                 │
│    (NO autenticado — sin authorities)                             │
└──────────────────────────┬────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────────────┐
│  ProviderManager                                                  │
│  → Busca providers que soporten UPAT.class                        │
│  → Encuentra: MyAuthenticationProvider                            │
│  → Llama: myAuthProvider.authenticate(token)                     │
└──────────────────────────┬────────────────────────────────────────┘
                           │
                           ▼
┌───────────────────────────────────────────────────────────────────┐
│  MyAuthenticationProvider.authenticate()                          │
│                                                                   │
│  1. username = "super_user@debuggeandoideas.com"                  │
│  2. pwd = "to_be_encoded"                                         │
│  3. customerRepository.findByEmail("super_user@...")              │
│     → PostgreSQL: SELECT * FROM customers WHERE email = ?         │
│     → CustomerEntity { password: "to_be_encoded", role: "admin" } │
│                                                                   │
│  4. passwordEncoder.matches("to_be_encoded", "to_be_encoded")     │
│     → true                                                        │
│                                                                   │
│  5. return UPAT("super_user@...", "to_be_encoded",                │
│                  [SimpleGrantedAuthority("admin")])                │
│     (AUTENTICADO — con authorities)                               │
└──────────────────────────┬────────────────────────────────────────┘
                           │
                           ▼
               SecurityContextHolder
               → Guarda el Authentication
               → El usuario esta logueado
```

---

## 8. DaoAuthenticationProvider vs AuthenticationProvider Custom

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  OPCION A: DaoAuthenticationProvider (secciones 2-3)                │
│                                                                     │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ DaoAuthProvider   │───>│ UserDetailsService│───>│ BD           │  │
│  │ (Spring auto)     │    │ (tu codigo)       │    │ (PostgreSQL) │  │
│  │                   │    │                   │    │              │  │
│  │ Compara passwords │    │ Carga al usuario  │    │ customers    │  │
│  │ Crea token        │    │ Traduce a         │    │              │  │
│  │ Lanza excepciones │    │ UserDetails       │    │              │  │
│  └──────────────────┘    └──────────────────┘    └──────────────┘  │
│                                                                     │
│  Tu escribes: 1 clase (UserDetailsService)                          │
│  Spring hace: comparar passwords, crear token, manejar errores      │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  OPCION B: AuthenticationProvider custom (esta seccion)             │
│                                                                     │
│  ┌──────────────────┐                            ┌──────────────┐  │
│  │ MyAuthProvider    │───────────────────────────>│ BD           │  │
│  │ (tu codigo)       │                            │ (PostgreSQL) │  │
│  │                   │                            │              │  │
│  │ Busca usuario     │                            │ customers    │  │
│  │ Compara passwords │                            │              │  │
│  │ Crea token        │                            │              │  │
│  │ Lanza excepciones │                            │              │  │
│  └──────────────────┘                            └──────────────┘  │
│                                                                     │
│  Tu escribes: 1 clase (AuthenticationProvider) — CONTROL TOTAL      │
│  Spring hace: nada (solo orquesta via ProviderManager)              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

| Aspecto | DaoAuthenticationProvider + UserDetailsService | AuthenticationProvider custom |
|---|---|---|
| **Codigo que escribes** | Solo cargar usuario (`loadUserByUsername`) | Todo: cargar, comparar, crear token |
| **Separacion de responsabilidades** | Alta (cada pieza hace una cosa) | Baja (todo en una clase) |
| **Flexibilidad** | Media (el flujo esta predefinido) | Total (tu defines el flujo completo) |
| **Multi-factor auth** | Dificil de implementar | Natural — agregas la logica al `authenticate()` |
| **Logica de bloqueo de cuentas** | Requiere evento listener externo | Natural — agregas contadores en `authenticate()` |
| **Auditing custom** | Requiere evento listener externo | Natural — agregas logs en `authenticate()` |
| **Recomendado para** | Username + password estandar | Flujos de autenticacion no convencionales |

---

## 9. ¿Que cambio respecto a la seccion 3?

| Archivo | Cambio |
|---|---|
| `security/MyAuthenticationProvider.java` | **Nuevo** — el authentication provider custom |
| `security/CustomerUserDetails.java` | **Eliminado** — ya no se necesita UserDetailsService |
| `security/SecurityConfig.java` | `BCryptPasswordEncoder` → `NoOpPasswordEncoder` (simplificacion del ejemplo) |

**La transicion clave:** Se paso de un modelo de 2 piezas (Spring controla + tu cargas datos) a un modelo de 1 pieza (tu controlas todo).

---

## 10. Resumen Visual

```
┌─────────────────────────────────────────────────────────────────────┐
│                      FLUJO DE AUTENTICACION                         │
│                                                                     │
│  Request → Filter → ProviderManager → MyAuthenticationProvider      │
│                                        │                            │
│                                        ├── 1. Extrae credenciales   │
│                                        ├── 2. Busca en BD           │
│                                        ├── 3. Compara password      │
│                                        ├── 4. Crea authorities      │
│                                        └── 5. Retorna token         │
│                                              autenticado            │
│                                                                     │
│  Clases activas:                                                    │
│  ┌────────────────────────┐  ┌────────────────────────────────────┐ │
│  │ SecurityConfig         │  │ MyAuthenticationProvider           │ │
│  │ ├── SecurityFilterChain│  │ ├── authenticate() — TODA la      │ │
│  │ └── PasswordEncoder    │  │ │   logica de autenticacion       │ │
│  │     (NoOp)             │  │ └── supports() — solo UPAT        │ │
│  └────────────────────────┘  └────────────────────────────────────┘ │
│                                                                     │
│  Clases eliminadas:                                                 │
│  ├── CustomerUserDetails (UserDetailsService) — ya no necesario     │
│  └── DaoAuthenticationProvider — reemplazado por tu provider        │
│                                                                     │
│  Clases que se mantienen:                                           │
│  ├── CustomerEntity (JPA)                                           │
│  ├── CustomerRepository (findByEmail)                               │
│  └── MyPasswordEncoder (sigue comentado/desactivado)                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. ¿Que viene en la siguiente seccion?

En la **Seccion 5** se agrega proteccion contra dos ataques web comunes:

- **CORS (Cross-Origin Resource Sharing)**: controlar que dominios pueden llamar a tu API
- **CSRF (Cross-Site Request Forgery)**: proteger formularios contra peticiones falsificadas
- Se implementa un `CsrfCookieFilter` personalizado
- Se reconfigura el `SecurityFilterChain` significativamente

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `security/MyAuthenticationProvider.java` | **Nuevo** — implementa `AuthenticationProvider` con control total de autenticacion |
| `security/CustomerUserDetails.java` | **Eliminado** — ya no se necesita `UserDetailsService` |
| `security/SecurityConfig.java` | `PasswordEncoder` volvio a `NoOpPasswordEncoder` (simplificacion del ejemplo) |
| `entites/CustomerEntity.java` | Sin cambios — sigue mapeando la tabla `customers` |
| `repositories/CustomerRepository.java` | Sin cambios — sigue proveyendo `findByEmail()` |
