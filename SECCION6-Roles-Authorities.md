# Seccion 6: Roles y Authorities

> Notas del curso de Spring Security 6 — Pasar de "¿estas autenticado?" a "¿que puedes hacer?"

---

## Objetivo de la seccion

Implementar **control de acceso granular** basado en roles, evolucionando de un modelo donde "autenticado = acceso a todo" a uno donde cada usuario tiene permisos especificos:

- Entender la diferencia critica entre **Role** y **Authority** (y el prefijo `ROLE_`)
- Crear una nueva entidad `RoleEntity` con relacion OneToMany en la BD
- Configurar `hasRole()` y `hasAuthority()` en el `SecurityFilterChain`
- Conocer la alternativa de seguridad a nivel de metodo con `@PreAuthorize`

---

## Ubicacion en la Arquitectura

```
  Auth Providers                                  Security Filters
  ┌───────────────────┐                           ┌─────────────────────────────────┐
  │ authenticate() {  │                           │  AuthorizationFilter            │
  │   ...             │                           │                                 │
  │   authorities:    │──── 7  Retorna ──────────►│  hasRole("ADMIN")? ── SI → PASA │
  │   [ROLE_ADMIN]    │    token con roles        │  hasRole("USER")?  ── NO → 403  │
  │ }                 │                           │                                 │ ◄── ESTAS AQUI
  └───────────────────┘                           └─────────────────────────────────┘
```

Esta seccion conecta dos partes del diagrama maestro (ver Seccion 1): los **roles que el AuthenticationProvider pone en el token** (paso 7) y la **evaluacion que hace el AuthorizationFilter** dentro de los Security Filters. Hasta ahora el AuthorizationFilter solo preguntaba "¿esta autenticado?". Ahora pregunta "¿tiene el rol correcto?".

---

## 1. Role vs Authority — La Diferencia Fundamental

### Concepto

En Spring Security, **Role** y **Authority** son casi lo mismo, con una diferencia clave: el **prefijo `ROLE_`**.

```
Authority = un permiso generico (cualquier String)
   Ejemplo: "VIEW_ACCOUNTS", "DELETE_USER", "db", "read"

Role = una authority con el prefijo "ROLE_"
   Ejemplo: "ROLE_ADMIN", "ROLE_USER", "ROLE_MANAGER"
```

Internamente, ambos son `SimpleGrantedAuthority`. La diferencia esta en como Spring los interpreta:

### `hasRole()` vs `hasAuthority()`

```java
// hasRole("ADMIN") internamente busca: "ROLE_ADMIN"
.requestMatchers("/accounts").hasRole("ADMIN")
// Spring agrega "ROLE_" automaticamente:
// → busca una GrantedAuthority cuyo string sea "ROLE_ADMIN"

// hasAuthority("ROLE_ADMIN") busca exactamente: "ROLE_ADMIN"
.requestMatchers("/accounts").hasAuthority("ROLE_ADMIN")
// No agrega nada, busca el string tal cual

// hasAuthority("VIEW_ACCOUNTS") busca exactamente: "VIEW_ACCOUNTS"
.requestMatchers("/accounts").hasAuthority("VIEW_ACCOUNTS")
// Util para permisos granulares que no son roles
```

### Tabla comparativa

| Metodo | Tu escribes | Spring busca en authorities | Caso de uso |
|---|---|---|---|
| `hasRole("ADMIN")` | `"ADMIN"` | `"ROLE_ADMIN"` | Roles amplios (admin, user, manager) |
| `hasRole("USER")` | `"USER"` | `"ROLE_USER"` | Roles amplios |
| `hasAuthority("ROLE_ADMIN")` | `"ROLE_ADMIN"` | `"ROLE_ADMIN"` | Cuando quieres ser explicito |
| `hasAuthority("VIEW_ACCOUNTS")` | `"VIEW_ACCOUNTS"` | `"VIEW_ACCOUNTS"` | Permisos granulares |
| `hasAnyRole("ADMIN", "USER")` | `"ADMIN", "USER"` | `"ROLE_ADMIN"` o `"ROLE_USER"` | Varios roles permitidos |
| `hasAnyAuthority("VIEW_ACCOUNTS", "VIEW_CARDS")` | ... | Cualquiera de las dos | Varios permisos |

**Regla practica:**
- Si tus permisos son **amplios** (admin vs user) → usa `hasRole()`
- Si tus permisos son **granulares** (ver cuentas, editar tarjetas, borrar prestamos) → usa `hasAuthority()`
- **Lo mas importante:** Que el String almacenado en la BD coincida con lo que Spring busca. Si usas `hasRole("ADMIN")`, la BD debe tener `"ROLE_ADMIN"`.

---

## 2. Nuevo Esquema de Base de Datos

### Concepto

En la seccion 2, el rol era un simple String en la tabla `customers` (columna `rol`). Ahora se separa en una tabla dedicada `roles` con relacion **uno-a-muchos**: un cliente puede tener multiples roles.

### Antes (Seccion 2-5)

```
TABLE customers
┌────┬─────────────────────────────┬──────────────┬───────┐
│ id │ email                       │ pwd          │ rol   │
├────┼─────────────────────────────┼──────────────┼───────┤
│  1 │ super_user@debuggeandoideas │ to_be_encoded│ admin │ ← Un solo rol como String
│  2 │ basic_user@debuggeandoideas │ to_be_encoded│ user  │
└────┴─────────────────────────────┴──────────────┴───────┘
```

### Ahora (Seccion 6)

```
TABLE customers                          TABLE roles
┌────┬──────────────────────────┬──────────────┐   ┌────┬────────────┬──────────────┬─────────────┐
│ id │ email                    │ pwd          │   │ id │ role_name  │ description  │ id_customer │
├────┼──────────────────────────┼──────────────┤   ├────┼────────────┼──────────────┼─────────────┤
│  1 │ account@debuggeandoideas │ to_be_encoded│   │  1 │ ROLE_ADMIN │ view account │      1      │──┐
│  2 │ cards@debuggeandoideas   │ to_be_encoded│   │  2 │ ROLE_ADMIN │ view cards   │      2      │──┤ FK
│  3 │ loans@debuggeandoideas   │ to_be_encoded│   │  3 │ ROLE_USER  │ view loans   │      3      │──┤
│  4 │ balance@debuggeandoideas │ to_be_encoded│   │  4 │ ROLE_USER  │ view balance │      4      │──┘
└────┴──────────────────────────┴──────────────┘   └────┴────────────┴──────────────┴─────────────┘
```

### SQL: `create_schema.sql`

```sql
create table customers(
    id    bigserial primary key,
    email varchar(70) not null,
    pwd   varchar(500) not null
    -- Ya NO tiene columna 'rol'
);

create table roles(
    id          bigserial primary key,
    role_name   varchar(50),            -- "ROLE_ADMIN", "ROLE_USER"
    description varchar(100),           -- Descripcion legible
    id_customer bigint,                 -- FK a customers
    constraint fk_customer foreign key(id_customer) references customers(id)
);
```

### SQL: `data.sql`

```sql
-- 4 usuarios (uno por endpoint protegido)
insert into customers (email, pwd) values
    ('account@debuggeandoieas.com', 'to_be_encoded'),
    ('cards@debuggeandoieas.com', 'to_be_encoded'),
    ('loans@debuggeandoieas.com', 'to_be_encoded'),
    ('balance@debuggeandoieas.com', 'to_be_encoded');

-- Asignar roles (nota: incluyen el prefijo ROLE_)
insert into roles(role_name, description, id_customer) values
    ('ROLE_ADMIN', 'can view account endpoint', 1),   -- account@ es ADMIN
    ('ROLE_ADMIN', 'can view cards endpoint', 2),      -- cards@ es ADMIN
    ('ROLE_USER', 'can view loans endpoint', 3),       -- loans@ es USER
    ('ROLE_USER', 'can view balance endpoint', 4);     -- balance@ es USER
```

**Dato clave:** Los roles en BD se guardan CON el prefijo `ROLE_` (`ROLE_ADMIN`, `ROLE_USER`). Esto es necesario porque cuando usas `hasRole("ADMIN")`, Spring busca `"ROLE_ADMIN"` en las authorities del token.

---

## 3. Nueva Entidad: `RoleEntity.java`

```java
package com.javaoscar.app_security.entites;

import jakarta.persistence.*;
import lombok.Data;

import java.math.BigInteger;

@Entity
@Table(name = "roles")
@Data
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // ID autoincremental
    private BigInteger id;

    @Column(name = "role_name")   // Columna 'role_name' en BD → campo 'name' en Java
    private String name;          // "ROLE_ADMIN" o "ROLE_USER"

    private String description;   // Descripcion legible del rol
}
```

Una entidad simple que mapea la tabla `roles`. No tiene referencia a `CustomerEntity` (la relacion se maneja desde el lado del customer).

---

## 4. CustomerEntity Actualizado

### Antes (Seccion 2-5)

```java
@Column(name = "rol")
private String role;        // Un solo rol como String: "admin"
```

### Ahora (Seccion 6)

```java
@Id
@GeneratedValue(strategy = GenerationType.IDENTITY)  // NUEVO: autoincremental
private BigInteger id;
private String email;
@Column(name = "pwd")
private String password;

@OneToMany(fetch = FetchType.EAGER)     // Relacion 1:N con roles
@JoinColumn(name = "id_customer")       // FK en tabla roles
private List<RoleEntity> roles;         // Lista de roles (puede tener varios)
```

### Desglose de los cambios

#### `@GeneratedValue(strategy = GenerationType.IDENTITY)`

Nuevo en esta seccion. Le dice a JPA: "El ID lo genera la BD (bigserial), no lo asignes tu". Antes no estaba y habia que setear el ID manualmente.

#### `@OneToMany(fetch = FetchType.EAGER)`

- **`@OneToMany`**: Un customer tiene MUCHOS roles
- **`FetchType.EAGER`**: Cuando cargues un customer, carga TAMBIEN sus roles inmediatamente (no de forma lazy). Esto es necesario porque el `MyAuthenticationProvider` necesita los roles en el momento de autenticar — si fueran lazy, podria fallar fuera de la transaccion JPA.

#### `@JoinColumn(name = "id_customer")`

Le dice a JPA: "La foreign key esta en la tabla `roles`, en la columna `id_customer`". Esto define el lado "dueño" de la relacion sin necesidad de un campo en `RoleEntity`.

---

## 5. MyAuthenticationProvider — Multiples Roles

### Antes (Seccion 5)

```java
// Un solo rol (String directo)
final var authorities = List.of(new SimpleGrantedAuthority(customer.getRole()));
```

### Ahora (Seccion 6)

```java
// Multiples roles (lista de RoleEntity)
final var roles = customer.getRoles();
final var authorities = roles
        .stream()
        .map(role -> new SimpleGrantedAuthority(role.getName()))
        .collect(Collectors.toList());
return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
```

### ¿Que hace este cambio?

```
CustomerEntity.getRoles() retorna:
   [RoleEntity{name: "ROLE_ADMIN"}, RoleEntity{name: "ROLE_MANAGER"}]

.stream().map(role -> new SimpleGrantedAuthority(role.getName()))
   → [SimpleGrantedAuthority("ROLE_ADMIN"), SimpleGrantedAuthority("ROLE_MANAGER")]

El token autenticado ahora tiene:
   UsernamePasswordAuthenticationToken {
       principal: "account@debuggeandoideas.com",
       authorities: [ROLE_ADMIN, ROLE_MANAGER]  ← multiples roles
   }
```

Esto conecta directamente con el **paso 7** del diagrama maestro: el token que el provider retorna al AuthManager ahora incluye la lista completa de roles del usuario.

---

## 6. SecurityConfig — Autorizacion por Rol

### Antes (Seccion 5)

```java
auth.requestMatchers("/loans", "/balance", "/accounts", "/cards")
        .authenticated()    // Solo pregunta: ¿esta autenticado?
```

### Ahora (Seccion 6)

```java
auth
    .requestMatchers("/loans", "/balance").hasRole("USER")     // Solo USER
    .requestMatchers("/accounts", "/cards").hasRole("ADMIN")   // Solo ADMIN
    .anyRequest().permitAll()                                   // El resto publico
```

### Alternativas comentadas (para referencia)

El codigo incluye alternativas comentadas que muestran el enfoque con authorities:

```java
// Enfoque con hasAuthority (mas granular):
//.requestMatchers("/loans").hasAuthority("VIEW_LOANS")
//.requestMatchers("/balance").hasAuthority("VIEW_BALANCE")
//.requestMatchers("/cards").hasAuthority("VIEW_CARDS")
//.requestMatchers("/accounts").hasAnyAuthority("VIEW_ACCOUNT", "VIEW_CARDS")
```

Estas lineas muestran que podrias tener permisos super-granulares como `VIEW_LOANS`, `VIEW_BALANCE`, etc., en vez de roles amplios. Para eso, los Strings en la BD no tendrian el prefijo `ROLE_`.

### Resultado: Matriz de acceso

| Endpoint | ROLE_ADMIN | ROLE_USER | Sin autenticar |
|---|---|---|---|
| `/accounts` | ✅ Acceso | ❌ 403 Forbidden | ❌ 401 Unauthorized |
| `/cards` | ✅ Acceso | ❌ 403 Forbidden | ❌ 401 Unauthorized |
| `/loans` | ❌ 403 Forbidden | ✅ Acceso | ❌ 401 Unauthorized |
| `/balance` | ❌ 403 Forbidden | ✅ Acceso | ❌ 401 Unauthorized |
| `/welcome` | ✅ Acceso | ✅ Acceso | ✅ Acceso |
| `/about_us` | ✅ Acceso | ✅ Acceso | ✅ Acceso |

**Nota la diferencia entre 401 y 403:**
- **401 Unauthorized**: No estas autenticado (no hiciste login)
- **403 Forbidden**: Estas autenticado pero NO tienes el rol necesario

---

## 7. Seguridad a Nivel de Metodo: `@PreAuthorize`

### Concepto

Hasta ahora, todas las reglas de acceso estan en `SecurityConfig.java` (centralizadas). Existe otra forma: poner las reglas **directamente en el controller** con anotaciones.

### `@EnableMethodSecurity` (comentada en el curso)

```java
@Configuration
//@EnableMethodSecurity    ← Descomentando esto se activan @PreAuthorize, @PostAuthorize, etc.
public class SecurityConfig { ... }
```

### `@PreAuthorize` en el controller (comentada en el curso)

```java
// AccountsController.java
//@PreAuthorize("hasAnyAuthority('VIEW_ACCOUNT', 'VIEW_CARDS')")
@GetMapping
public Map<String, String> accounts() {
    return Collections.singletonMap("msj", "accounts");
}
```

### ¿Como funciona?

```java
@PreAuthorize("hasAnyAuthority('VIEW_ACCOUNT', 'VIEW_CARDS')")
```

Antes de ejecutar el metodo, Spring evalua la expresion SpEL:
- Si retorna `true` → ejecuta el metodo
- Si retorna `false` → lanza `AccessDeniedException` (403)

### URL-based vs Method-based: ¿Cuando usar cual?

| Aspecto | URL-based (`SecurityConfig`) | Method-based (`@PreAuthorize`) |
|---|---|---|
| **Donde se define** | Centralizado en una clase | Distribuido en cada controller/service |
| **Granularidad** | Por URL pattern | Por metodo individual |
| **Visibilidad** | Ves TODAS las reglas en un lugar | Las reglas estan dispersas en el codigo |
| **Expresiones SpEL** | Limitadas (`hasRole`, `authenticated`) | Completas (acceso a parametros, principal, etc.) |
| **Caso de uso** | APIs REST con reglas por path | Logica compleja que depende del argumento o retorno |

**Ejemplo avanzado de `@PreAuthorize`:**
```java
// Solo permite si el usuario es el dueño del recurso
@PreAuthorize("#userId == authentication.principal.username")
public Account getAccount(@PathVariable String userId) { ... }
```

Esto no es posible con URL-based security porque no tiene acceso a los parametros del metodo.

---

## 8. Flujo Completo — Login como ADMIN y acceso a `/accounts`

```
POST /login (username=account@debuggeandoideas.com, password=to_be_encoded)
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  MyAuthenticationProvider.authenticate()                            │
│                                                                     │
│  1. customerRepository.findByEmail("account@debuggeandoideas.com")  │
│     → CustomerEntity { roles: [RoleEntity{name: "ROLE_ADMIN"}] }   │
│                                                                     │
│  2. passwordEncoder.matches("to_be_encoded", "to_be_encoded")       │
│     → true                                                          │
│                                                                     │
│  3. Mapea roles → authorities:                                      │
│     [RoleEntity{name: "ROLE_ADMIN"}]                                │
│     → [SimpleGrantedAuthority("ROLE_ADMIN")]                        │
│                                                                     │
│  4. return UPAT("account@...", pwd, [ROLE_ADMIN])                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
                  SecurityContext guarda: Authentication { authorities: [ROLE_ADMIN] }


GET /accounts (ya autenticado)
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  AuthorizationFilter                                                │
│                                                                     │
│  Regla: .requestMatchers("/accounts").hasRole("ADMIN")              │
│  → Spring busca: ¿tiene authority "ROLE_ADMIN"?                     │
│  → Authorities del usuario: [ROLE_ADMIN]                            │
│  → ¿ROLE_ADMIN esta en la lista? → SI                               │
│  → ACCESO PERMITIDO ✅                                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
              AccountsController.accounts() → {"msj": "accounts"}


GET /loans (mismo usuario ADMIN)
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  AuthorizationFilter                                                │
│                                                                     │
│  Regla: .requestMatchers("/loans").hasRole("USER")                  │
│  → Spring busca: ¿tiene authority "ROLE_USER"?                      │
│  → Authorities del usuario: [ROLE_ADMIN]                            │
│  → ¿ROLE_USER esta en la lista? → NO                                │
│  → 403 FORBIDDEN ❌                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 9. Archivo eliminado: `MyPasswordEncoder.java`

El `PasswordEncoder` custom educativo de la seccion 3 se elimino definitivamente. Ya cumplio su proposito didactico y limpiarlo evita confusion.

---

## 10. Resumen Visual

```
┌─────────────────────────────────────────────────────────────────────┐
│                   AUTORIZACION POR ROLES                            │
│                                                                     │
│  PostgreSQL:                                                        │
│  ┌──────────────┐    1:N    ┌──────────────────────────────┐        │
│  │  customers   │──────────►│  roles                       │        │
│  │  id, email,  │           │  id, role_name, id_customer  │        │
│  │  pwd         │           │                              │        │
│  └──────────────┘           │  ROLE_ADMIN (customers 1,2)  │        │
│                              │  ROLE_USER  (customers 3,4)  │        │
│                              └──────────────────────────────┘        │
│         │                                                           │
│         │ findByEmail()                                             │
│         ▼                                                           │
│  ┌──────────────────────────────────────┐                           │
│  │  MyAuthenticationProvider            │                           │
│  │  customer.getRoles()                 │                           │
│  │  → roles.stream().map(→ authority)   │                           │
│  │  → token con [ROLE_ADMIN]            │                           │
│  └──────────────────────────────────────┘                           │
│         │                                                           │
│         │ paso 7 → token con authorities                            │
│         ▼                                                           │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  SecurityFilterChain — AuthorizationFilter                   │   │
│  │                                                              │   │
│  │  /loans, /balance  →  hasRole("USER")   → necesita ROLE_USER│   │
│  │  /accounts, /cards →  hasRole("ADMIN")  → necesita ROLE_ADMIN│  │
│  │  anyRequest()      →  permitAll()       → acceso libre       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Alternativas (comentadas en el codigo):                            │
│  ├── hasAuthority("VIEW_LOANS") — permisos granulares por URL       │
│  ├── @PreAuthorize("hasRole('ADMIN')") — seguridad por metodo      │
│  └── @EnableMethodSecurity — activa las anotaciones de metodo       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. ¿Que cambio respecto a la seccion 5?

| Archivo | Cambio |
|---|---|
| `db/sql/create_schema.sql` | **Reescrito**: elimina `rol` de `customers`, crea tabla `roles` con FK |
| `db/sql/data.sql` | **Reescrito**: 4 usuarios, roles con prefijo `ROLE_` |
| `entites/RoleEntity.java` | **Nuevo** — entidad JPA para la tabla `roles` |
| `entites/CustomerEntity.java` | `String role` → `List<RoleEntity> roles` con `@OneToMany` |
| `security/MyAuthenticationProvider.java` | Mapea lista de `RoleEntity` → lista de `SimpleGrantedAuthority` |
| `security/SecurityConfig.java` | `authenticated()` → `hasRole("USER")` / `hasRole("ADMIN")` |
| `controllers/AccountsController.java` | Agrega `@PreAuthorize` comentado (ejemplo educativo) |
| `security/MyPasswordEncoder.java` | **Eliminado** (limpieza) |

---

## 12. ¿Que viene en la siguiente seccion?

En la **Seccion 7** se agregan **filtros custom** a la cadena de seguridad:

- Implementacion de un `ApiKeyFilter` para validar una API Key en el header
- Como insertar filtros en posiciones especificas de la cadena (`addFilterBefore`, `addFilterAfter`)
- Profundizacion en el orden de ejecucion de los filtros de seguridad

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `db/sql/create_schema.sql` | Esquema con tabla `customers` (sin rol) + tabla `roles` (con FK) |
| `db/sql/data.sql` | 4 usuarios + 4 roles con prefijo `ROLE_` |
| `entites/RoleEntity.java` | **Nuevo** — entidad JPA mapeada a tabla `roles` |
| `entites/CustomerEntity.java` | `@OneToMany` con `RoleEntity` (antes era `String role`) |
| `security/MyAuthenticationProvider.java` | Mapea multiples roles a authorities en el token |
| `security/SecurityConfig.java` | `hasRole("USER")` / `hasRole("ADMIN")` por endpoint |
| `controllers/AccountsController.java` | `@PreAuthorize` comentado como ejemplo educativo |
