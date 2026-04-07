# Seccion 2: Usuarios Personalizados — InMemory, JDBC y Base de Datos

> Notas del curso de Spring Security 6 — Tres formas de gestionar usuarios: en memoria, JDBC directo, y UserDetailsService custom con JPA

---

## Objetivo de la seccion

Pasar del usuario unico hardcodeado en `application.properties` (seccion 1) a **usuarios reales almacenados en base de datos**, explorando tres enfoques incrementales:

1. **InMemoryUserDetailsManager** — usuarios definidos en codigo Java (sin BD)
2. **JdbcUserDetailsManager** — usuarios en BD con esquema predefinido por Spring
3. **UserDetailsService custom** — usuarios en BD con TU propio esquema y logica (el que queda activo)

La meta final: que Spring Security valide credenciales contra una tabla `customers` en PostgreSQL.

---

## Ubicacion en la Arquitectura

```
                                                              ┌──────────────────┐
   Auth Providers ──── 6  Carga usuario ────────────────────► │ UserDetails      │
                                                              │ Manager/Service  │ ◄── ESTAS AQUI
                                                              └──────────────────┘
```

Esta seccion cubre el **paso 6** del diagrama maestro (ver Seccion 1): cuando el `AuthenticationProvider` necesita cargar los datos del usuario, delega a un `UserDetailsService`. Aqui exploramos 3 implementaciones de ese servicio: InMemory, JDBC, y custom con JPA.

---

## 1. ¿Por que necesitamos esto?

### El problema de la seccion anterior

En la seccion 1, el usuario vivia en `application.properties`:
```properties
spring.security.user.name=debugger
spring.security.user.password=ideas
```

Esto tiene 3 problemas fatales para cualquier app real:

| Problema | Impacto |
|---|---|
| **Un solo usuario** | No puedes tener multiples usuarios con diferentes permisos |
| **Password en texto plano** | Cualquiera que lea el archivo ve la contraseña |
| **Sin persistencia** | Si quieres agregar un usuario, tienes que modificar codigo y reiniciar |

### La solucion: `UserDetailsService`

Spring Security no sabe (ni le importa) donde guardas tus usuarios. Solo necesita que alguien implemente la interfaz `UserDetailsService` y le devuelva un objeto `UserDetails` cuando le pida un usuario por su username.

```
Spring Security pregunta: "¿Quien es 'super_user@debuggeandoideas.com'?"
        │
        ▼
UserDetailsService responde: UserDetails {
    username: "super_user@debuggeandoideas.com",
    password: "to_be_encoded",
    authorities: ["admin"]
}
        │
        ▼
Spring Security valida el password y decide si da acceso
```

Spring provee 3 implementaciones listas para usar, o puedes hacer la tuya:

| Implementacion | Donde guarda los usuarios | Cuando usarla |
|---|---|---|
| **InMemoryUserDetailsManager** | HashMap en memoria (Java) | Demos, tests, prototipos |
| **JdbcUserDetailsManager** | BD relacional con esquema de Spring | Cuando aceptas el esquema de tablas de Spring |
| **Custom `UserDetailsService`** | Donde tu quieras (JPA, MongoDB, API externa...) | Cuando tienes tu propio modelo de datos |

---

## 2. Infraestructura: PostgreSQL con Docker

### Concepto

Antes de hablar de usuarios en BD, necesitamos una BD. Se usa Docker Compose para levantar PostgreSQL con el esquema y datos iniciales ya cargados.

### Implementacion: `docker-compose.yml`

```yaml
version: '3.8'

services:
  db:
    image: postgres:15.2
    container_name: security_bank
    restart: always
    volumes:
      # Monta los scripts SQL en el directorio de inicializacion de Postgres
      # Postgres ejecuta AUTOMATICAMENTE todo lo que este en /docker-entrypoint-initdb.d/
      - ./db/sql/create_schema.sql:/docker-entrypoint-initdb.d/create_schema.sql
      - ./db/sql/data.sql:/docker-entrypoint-initdb.d/data.sql
    environment:
      - POSTGRES_DB=security_bank        # Nombre de la BD
      - POSTGRES_USER=alejandro          # Usuario de la BD
      - POSTGRES_PASSWORD=debuggeandoideas
    ports:
      - "5432:5432"                      # Puerto por defecto de PostgreSQL
```

**¿Para que los volumes?** Cuando el contenedor arranca por primera vez, PostgreSQL busca scripts en `/docker-entrypoint-initdb.d/` y los ejecuta en orden alfabetico. Asi, al hacer `docker-compose up`, la BD ya tiene la tabla y los datos listos.

### Script de esquema: `db/sql/create_schema.sql`

```sql
create table customers(
    id bigserial primary key,          -- ID autoincremental
    email varchar(50) not null,        -- Username (se usa el email como login)
    pwd varchar(500) not null,         -- Password (varchar largo para cuando se encripte)
    rol varchar(20) not null           -- Rol del usuario (admin, user, etc.)
);
```

**Decisiones de diseño:**
- **`email` como username**: En vez del tipico `username`, se usa el email. Es una decision de negocio — Spring Security no impone que campo usas como identificador.
- **`pwd` en vez de `password`**: Nombre acortado para la columna. El `@Column(name = "pwd")` en la entidad JPA hace el mapeo.
- **`varchar(500)` para password**: Parece excesivo para un password en texto plano, pero es prevision: cuando se encripte con BCrypt, el hash ocupa ~60 caracteres. Con otros algoritmos puede ser mas.

### Script de datos: `db/sql/data.sql`

```sql
insert into customers (email, pwd, rol) VALUES
    ('super_user@debuggeandoieas.com', 'to_be_encoded', 'admin'),
    ('basic_user@debuggeandoieas.com', 'to_be_encoded', 'user');
```

Dos usuarios de prueba. El password `'to_be_encoded'` es texto plano (se encriptara en la seccion 3). Por ahora se usa `NoOpPasswordEncoder` que acepta passwords sin encriptar.

---

## 3. Dependencias Nuevas: `pom.xml`

```xml
<!-- JPA: Para mapear entidades Java a tablas de BD -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

<!-- JDBC: Necesario para JdbcUserDetailsManager y conexion a BD -->
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-jdbc</artifactId>
</dependency>

<!-- Driver PostgreSQL: Para que Java pueda hablar con Postgres -->
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <version>42.6.0</version>
</dependency>

<!-- Lombok: Genera getters, setters, constructors automaticamente -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <version>1.18.28</version>
    <scope>provided</scope>
</dependency>
```

### Configuracion de conexion: `application.properties`

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/security_bank
spring.datasource.username=alejandro
spring.datasource.password=debuggeandoideas
spring.datasource.hikari.connection-timeout=20000    # Timeout de conexion: 20 segundos
spring.datasource.hikari.maximum-pool-size=5         # Maximo 5 conexiones simultaneas
```

**Nota:** Ya no estan las propiedades `spring.security.user.*` de la seccion 1. Se eliminaron porque ahora los usuarios vienen de la BD.

---

## 4. Enfoque 1: InMemoryUserDetailsManager (comentado)

### Concepto

`InMemoryUserDetailsManager` guarda usuarios en un `HashMap` dentro de la memoria de Java. No necesita base de datos. Es util para:
- Tests unitarios
- Prototipos rapidos
- Demos donde no quieres configurar una BD

### Implementacion (comentada en `SecurityConfig.java`)

```java
/*
@Bean
InMemoryUserDetailsManager inMemoryUserDetailsManager() {
    // Crea usuario admin
    var admin = User.withUsername("admin")
            .password("to_be_encoded")       // Password (sin encriptar por ahora)
            .authorities("ADMIN")            // Autoridad/rol
            .build();

    // Crea usuario normal
    var user = User.withUsername("user")
            .password("to_be_encoded")
            .authorities("USER")
            .build();

    // Retorna el manager con ambos usuarios pre-cargados
    return new InMemoryUserDetailsManager(admin, user);
}
*/
```

### ¿Como funciona por dentro?

```
InMemoryUserDetailsManager
    └── HashMap<String, UserDetails>
            ├── "admin" → UserDetails { password: "to_be_encoded", authorities: [ADMIN] }
            └── "user"  → UserDetails { password: "to_be_encoded", authorities: [USER] }
```

`User.withUsername("admin")` usa el patron **Builder** de Spring Security para construir un objeto `UserDetails` paso a paso. `UserDetails` es la interfaz que Spring Security entiende — no importa como lo construyas, mientras sea un `UserDetails`.

### ¿Por que esta comentado?

Porque es un paso intermedio de aprendizaje. Para la app bancaria queremos usuarios en BD, no en memoria. Pero es valioso conocerlo porque:
- Lo vas a usar en **tests** (crear usuarios de prueba sin levantar una BD)
- Te enseña la API de `User.builder()` que se usa en todos los enfoques

---

## 5. Enfoque 2: JdbcUserDetailsManager (comentado)

### Concepto

`JdbcUserDetailsManager` es el paso intermedio: usa una base de datos real, pero con un **esquema de tablas predefinido por Spring Security**. Spring espera encontrar tablas llamadas `users` y `authorities` con columnas especificas.

### Implementacion (comentada en `SecurityConfig.java`)

```java
/*
@Bean
UserDetailsService userDetailsService(DataSource dataSource) {
    return new JdbcUserDetailsManager(dataSource);
}
*/
```

**Solo 3 lineas.** Spring inyecta el `DataSource` (configurado en `application.properties`), y `JdbcUserDetailsManager` sabe hacer las queries SQL por ti.

### ¿Que queries ejecuta internamente?

```sql
-- Para buscar un usuario:
SELECT username, password, enabled FROM users WHERE username = ?

-- Para buscar sus autoridades:
SELECT username, authority FROM authorities WHERE username = ?
```

### ¿Por que esta comentado?

Porque requiere un esquema de tablas ESPECIFICO que Spring define:

```sql
-- Esquema que Spring espera (NO es el que tenemos):
CREATE TABLE users (
    username VARCHAR(50) NOT NULL PRIMARY KEY,
    password VARCHAR(500) NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username)
);
```

Nuestro esquema es diferente: tenemos `customers` con columnas `email`, `pwd`, `rol`. **No coincide con lo que Spring espera.** Por eso se descarta este enfoque y se implementa un `UserDetailsService` custom.

### ¿Cuando SI usarlo?

- Si estas empezando un proyecto **desde cero** y no tienes esquema de usuarios
- Si no te importa adoptar las convenciones de Spring
- Si quieres la solucion mas rapida sin escribir codigo custom

---

## 6. Enfoque 3: UserDetailsService Custom con JPA (el activo)

### Concepto

Cuando tu esquema de BD no coincide con el que Spring espera, implementas tu propio `UserDetailsService`. Esto te da control total:

- Defines TU entidad JPA con TUS columnas
- Defines TU repositorio con TUS queries
- Implementas `loadUserByUsername()` para traducir de TU modelo al `UserDetails` que Spring necesita

Es el enfoque mas comun en aplicaciones reales porque casi nadie tiene el esquema exacto que Spring espera.

### 6.1 Entidad JPA: `CustomerEntity.java`

```java
package com.javaoscar.app_security.entites;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.io.Serializable;
import java.math.BigInteger;

@Entity                        // "Esta clase representa una tabla en la BD"
@Table(name = "customers")     // "La tabla se llama 'customers'"
@Data                          // Lombok: genera getters, setters, toString, equals, hashCode
public class CustomerEntity implements Serializable {

    @Id                        // Clave primaria
    private BigInteger id;

    private String email;      // Mapea a columna 'email' (mismo nombre → no necesita @Column)

    @Column(name = "pwd")      // La columna en BD se llama 'pwd', pero el campo Java es 'password'
    private String password;

    @Column(name = "rol")      // La columna en BD se llama 'rol', pero el campo Java es 'role'
    private String role;
}
```

**¿Por que `@Column(name = "pwd")`?** Porque la columna en la tabla se llama `pwd` (abreviado), pero en Java queremos usar `password` (mas descriptivo). `@Column` hace el puente entre ambos nombres. Sin esta anotacion, JPA buscaria una columna llamada `password` y fallaria.

**¿Por que `implements Serializable`?** Es una buena practica para entidades JPA. Permite que el objeto se serialice (convierta a bytes) para cache, sesiones HTTP, o transferencia entre JVMs.

### 6.2 Repositorio: `CustomerRepository.java`

```java
package com.javaoscar.app_security.repositories;

import com.javaoscar.app_security.entites.CustomerEntity;
import org.springframework.data.repository.CrudRepository;

import java.math.BigInteger;
import java.util.Optional;

public interface CustomerRepository extends CrudRepository<CustomerEntity, BigInteger> {

    // Spring Data JPA genera automaticamente la query:
    // SELECT * FROM customers WHERE email = ?
    Optional<CustomerEntity> findByEmail(String email);
}
```

**¿Por que `Optional`?** Porque el usuario podria no existir. `Optional` fuerza a quien lo use a manejar ambos casos (existe / no existe) de forma explicita, evitando `NullPointerException`.

**¿Por que `findByEmail` y no `findByUsername`?** Porque en nuestro modelo, el campo que actua como "username" es el email. Spring Data JPA genera la query automaticamente basandose en el nombre del metodo: `findBy` + `Email` → `WHERE email = ?`.

### 6.3 El Corazon: `CustomerUserDetails.java`

```java
package com.javaoscar.app_security.security;

import com.javaoscar.app_security.repositories.CustomerRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service                // Registra esta clase como bean de Spring (y como "servicio" semanticamente)
@Transactional          // Cada metodo corre dentro de una transaccion de BD
@AllArgsConstructor     // Lombok: genera constructor con todos los campos (para inyeccion por constructor)
public class CustomerUserDetails implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. Busca el usuario en la BD por email
        return this.customerRepository.findByEmail(username)
                .map(customer -> {
                    // 2. Convierte el rol (String) a una autoridad de Spring Security
                    var authorities = List.of(new SimpleGrantedAuthority(customer.getRole()));

                    // 3. Construye el UserDetails que Spring Security entiende
                    return new User(
                        customer.getEmail(),      // username
                        customer.getPassword(),   // password
                        authorities               // lista de autoridades/roles
                    );
                })
                // 4. Si no existe el email en BD → excepcion
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
```

### Desglose del flujo interno

```
Spring Security llama: loadUserByUsername("super_user@debuggeandoideas.com")
        │
        ▼
customerRepository.findByEmail("super_user@debuggeandoideas.com")
        │
        ▼  (query a PostgreSQL)
┌───────────────────────────────────────────────────────────┐
│  SELECT * FROM customers WHERE email = ?                  │
│                                                           │
│  Resultado: CustomerEntity {                              │
│      id: 1,                                               │
│      email: "super_user@debuggeandoideas.com",            │
│      password: "to_be_encoded",                           │
│      role: "admin"                                        │
│  }                                                        │
└───────────────────────────────────────────────────────────┘
        │
        ▼  .map(customer -> ...)
┌───────────────────────────────────────────────────────────┐
│  TRADUCCION: CustomerEntity → UserDetails                 │
│                                                           │
│  authorities = [SimpleGrantedAuthority("admin")]          │
│                                                           │
│  return new User(                                         │
│      "super_user@debuggeandoideas.com",  // username      │
│      "to_be_encoded",                     // password     │
│      [SimpleGrantedAuthority("admin")]    // authorities  │
│  )                                                        │
└───────────────────────────────────────────────────────────┘
        │
        ▼
Spring Security recibe el UserDetails
  → Compara el password del UserDetails con el que envio el usuario
  → Si coincide → autenticacion exitosa
  → Si no coincide → 401 Unauthorized
```

### ¿Por que `@Service` y no `@Component`?

Ambos registran la clase como bean, pero `@Service` comunica intencion: "esta clase contiene logica de servicio". En Spring Security, lo importante es que la clase este en el contexto de Spring, porque `DaoAuthenticationProvider` busca automaticamente cualquier bean que implemente `UserDetailsService`.

### ¿Por que `@Transactional`?

Porque `loadUserByUsername` ejecuta una query a la BD. `@Transactional` asegura que:
- Se abre una conexion al inicio del metodo
- Se cierra correctamente al final (incluso si hay una excepcion)
- Se evitan problemas de lazy loading de JPA

### ¿Que es `SimpleGrantedAuthority`?

Es la implementacion mas simple de `GrantedAuthority`, que es como Spring Security representa un permiso/rol. Recibe un String: `"admin"`, `"user"`, `"ROLE_ADMIN"`, etc.

```
GrantedAuthority (interfaz)
    └── SimpleGrantedAuthority (implementacion)
            └── authority: "admin"  ← un String, nada mas
```

---

## 7. SecurityConfig Actualizado

### Implementacion: `SecurityConfig.java`

```java
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->
                auth.requestMatchers("/loans", "/balance", "/accounts", "/cards")
                        .authenticated()
                        .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    // (InMemoryUserDetailsManager comentado — ver seccion 4)
    // (JdbcUserDetailsManager comentado — ver seccion 5)

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
```

### ¿Que es `NoOpPasswordEncoder`?

Un `PasswordEncoder` que **no hace nada**: compara el password en texto plano directamente.

```java
// Internamente, NoOpPasswordEncoder hace esto:
public boolean matches(CharSequence rawPassword, String encodedPassword) {
    return rawPassword.toString().equals(encodedPassword);
    // "to_be_encoded".equals("to_be_encoded") → true
}
```

**Esta `@Deprecated`** y no debe usarse en produccion. Existe solo para escenarios de desarrollo y aprendizaje. En la seccion 3 se reemplazara por `BCryptPasswordEncoder`.

### ¿Por que es obligatorio declarar un `PasswordEncoder`?

Desde Spring Security 5+, si no declaras un `PasswordEncoder` como bean, Spring lanza una excepcion al arrancar:

```
java.lang.IllegalArgumentException:
There is no PasswordEncoder mapped for the id "null"
```

Spring Security **siempre** necesita saber como comparar passwords. Incluso si es texto plano, tienes que decirlo explicitamente con `NoOpPasswordEncoder`.

### ¿Donde esta el `UserDetailsService`?

No esta en `SecurityConfig`. Esta en `CustomerUserDetails.java` (la clase con `@Service`). Spring Security lo encuentra automaticamente gracias a la **auto-deteccion de beans**:

1. Spring escanea el classpath y encuentra `CustomerUserDetails` (por `@Service`)
2. Ve que implementa `UserDetailsService`
3. Lo registra como el bean de `UserDetailsService`
4. `DaoAuthenticationProvider` (que Spring crea automaticamente) lo detecta y lo usa

No necesitas escribir `@Autowired` ni registrarlo manualmente en ningun lado.

---

## 8. El Pegamento Invisible: `DaoAuthenticationProvider`

### Concepto

Tu no escribes la logica de "comparar password del formulario con el password de la BD". Eso lo hace **`DaoAuthenticationProvider`**, un componente que Spring Security crea automaticamente cuando detecta:

1. Un bean `UserDetailsService` (tu `CustomerUserDetails`)
2. Un bean `PasswordEncoder` (tu `NoOpPasswordEncoder`)

### Flujo completo de autenticacion

```
Usuario envia: POST /login
    username: super_user@debuggeandoideas.com
    password: to_be_encoded
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│  UsernamePasswordAuthenticationFilter                               │
│  1. Extrae username y password del request                          │
│  2. Crea: UsernamePasswordAuthenticationToken("super_user@...",     │
│                                                "to_be_encoded")     │
│  3. Pasa el token al AuthenticationManager                          │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  AuthenticationManager (ProviderManager)                            │
│  Tiene una lista de AuthenticationProviders.                        │
│  Itera hasta encontrar uno que soporte el tipo de token.            │
│  → DaoAuthenticationProvider soporta                                │
│    UsernamePasswordAuthenticationToken                              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DaoAuthenticationProvider                                          │
│                                                                     │
│  PASO 1: Buscar al usuario                                          │
│  → Llama a userDetailsService.loadUserByUsername("super_user@...")   │
│  → Tu CustomerUserDetails consulta PostgreSQL                       │
│  → Retorna: UserDetails { password: "to_be_encoded",                │
│                            authorities: ["admin"] }                 │
│                                                                     │
│  PASO 2: Comparar passwords                                         │
│  → Llama a passwordEncoder.matches("to_be_encoded", "to_be_encoded")│
│  → NoOpPasswordEncoder: "to_be_encoded".equals("to_be_encoded")     │
│  → true                                                             │
│                                                                     │
│  PASO 3: Crear Authentication exitoso                                │
│  → Retorna: UsernamePasswordAuthenticationToken con                  │
│     principal = UserDetails, authorities = ["admin"]                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  SecurityContextHolder                                              │
│  Guarda el Authentication en el contexto de seguridad.              │
│  A partir de aqui, cualquier parte de la app puede consultar:       │
│  "¿Quien es el usuario actual?" → SecurityContextHolder.getContext() │
└─────────────────────────────────────────────────────────────────────┘
```

### ¿Por que es importante entender esto?

Porque en la **seccion 4** vas a reemplazar `DaoAuthenticationProvider` con tu propio `AuthenticationProvider` custom. Si no entiendes el flujo actual, no sabras que estas reemplazando ni por que.

---

## 9. Comparativa: Los 3 Enfoques

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ¿DONDE VIVEN LOS USUARIOS?                           │
│                                                                         │
│  ENFOQUE 1: InMemoryUserDetailsManager                                  │
│  ┌──────────────────────────────────────────────┐                       │
│  │  HashMap en memoria (Java)                   │                       │
│  │  ├── "admin" → { pwd, authorities }          │                       │
│  │  └── "user"  → { pwd, authorities }          │  ← Muere al reiniciar│
│  └──────────────────────────────────────────────┘                       │
│                                                                         │
│  ENFOQUE 2: JdbcUserDetailsManager                                      │
│  ┌──────────────────────────────────────────────┐                       │
│  │  BD con esquema DE SPRING:                   │                       │
│  │  TABLE users (username, password, enabled)   │                       │
│  │  TABLE authorities (username, authority)      │  ← Esquema rigido    │
│  └──────────────────────────────────────────────┘                       │
│                                                                         │
│  ENFOQUE 3: Custom UserDetailsService (EL ACTIVO)                       │
│  ┌──────────────────────────────────────────────┐                       │
│  │  BD con TU esquema:                          │                       │
│  │  TABLE customers (id, email, pwd, rol)       │                       │
│  │  + CustomerEntity (JPA)                      │                       │
│  │  + CustomerRepository (Spring Data)          │  ← Flexible          │
│  │  + CustomerUserDetails (tu logica)           │                       │
│  └──────────────────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────────────┘
```

| Aspecto | InMemory | JDBC | Custom (JPA) |
|---|---|---|---|
| **Persistencia** | No (se pierde al reiniciar) | Si | Si |
| **Esquema de BD** | No aplica | Predefinido por Spring | El tuyo |
| **Codigo necesario** | ~10 lineas | ~3 lineas | ~3 clases |
| **Flexibilidad** | Nula | Baja | Total |
| **Caso de uso** | Tests, demos | Proyectos nuevos simples | Apps reales |
| **Tiene query custom** | No | No (usa queries internas) | Si (`findByEmail`) |

---

## 10. ¿Que cambio respecto a la seccion 1?

| Archivo | Seccion 1 | Seccion 2 |
|---|---|---|
| `application.properties` | `spring.security.user.*` (usuario hardcodeado) | `spring.datasource.*` (conexion a PostgreSQL) |
| `pom.xml` | Solo `web` + `security` | + `data-jpa` + `spring-jdbc` + `postgresql` + `lombok` |
| `SecurityConfig.java` | Solo `SecurityFilterChain` | + `PasswordEncoder` bean + enfoques comentados |
| **Archivos nuevos** | — | `CustomerEntity`, `CustomerRepository`, `CustomerUserDetails`, `docker-compose.yml`, SQL scripts |
| **Fuente de usuarios** | properties file | PostgreSQL (tabla `customers`) |

---

## 11. Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────────────────────┐
│                        APLICACION BANCARIA                          │
│                                                                     │
│  SecurityConfig.java                                                │
│  ├── SecurityFilterChain (misma que seccion 1)                      │
│  └── PasswordEncoder → NoOpPasswordEncoder (texto plano)            │
│                                                                     │
│  CustomerUserDetails.java (@Service)                                │
│  └── implements UserDetailsService                                  │
│      └── loadUserByUsername(email)                                   │
│              │                                                      │
│              ▼                                                      │
│  CustomerRepository.java                                            │
│  └── findByEmail(email) ── query ──┐                                │
│                                     │                               │
│  ┌──────────────────────────────────▼──────────────────────────┐    │
│  │  PostgreSQL (Docker) — security_bank                        │    │
│  │                                                             │    │
│  │  TABLE customers:                                           │    │
│  │  ┌────┬────────────────────────────────┬───────────────┬──┐ │    │
│  │  │ id │ email                          │ pwd           │rol│ │    │
│  │  ├────┼────────────────────────────────┼───────────────┼──┤ │    │
│  │  │  1 │ super_user@debuggeandoideas.com│ to_be_encoded │admin│    │
│  │  │  2 │ basic_user@debuggeandoideas.com│ to_be_encoded │user │    │
│  │  └────┴────────────────────────────────┴───────────────┴──┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  DaoAuthenticationProvider (AUTOMATICO — no lo escribimos)          │
│  ├── Usa: CustomerUserDetails (UserDetailsService)                  │
│  └── Usa: NoOpPasswordEncoder (PasswordEncoder)                     │
│                                                                     │
│  Flujo: Request → Filter → DaoAuthProvider → CustomerUserDetails    │
│         → PostgreSQL → UserDetails → compara password → OK/FAIL     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 12. Conceptos Clave de esta Seccion

### La interfaz `UserDetailsService`

```java
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

Un solo metodo. Recibe un `String` (el username/email que el usuario escribio en el formulario) y devuelve un `UserDetails` (el objeto que Spring Security sabe comparar). Si el usuario no existe, lanza `UsernameNotFoundException`.

**Dato importante de la documentacion oficial:** `UserDetailsService` es un **DAO** (Data Access Object) de solo lectura. Su unica responsabilidad es **cargar** datos del usuario. **NO** es responsable de la autenticacion en si — eso lo hace `DaoAuthenticationProvider`.

### La interfaz `UserDetails`

Es lo que `loadUserByUsername` debe devolver. Representa un usuario para Spring Security:

```java
public interface UserDetails {
    String getUsername();                           // Quien es
    String getPassword();                           // Su password (para comparar)
    Collection<? extends GrantedAuthority> getAuthorities();  // Que puede hacer
    boolean isAccountNonExpired();                  // ¿Cuenta vigente?
    boolean isAccountNonLocked();                   // ¿Cuenta no bloqueada?
    boolean isCredentialsNonExpired();              // ¿Password vigente?
    boolean isEnabled();                            // ¿Cuenta activa?
}
```

`User` (de `org.springframework.security.core.userdetails.User`) es la implementacion lista de Spring. Por defecto, los 4 booleanos son `true`. En el curso se usa este `User` directamente; en apps complejas podrias implementar `UserDetails` tu mismo.

---

## 13. ¿Que viene en la siguiente seccion?

En la **Seccion 3** se reemplaza `NoOpPasswordEncoder` por un **Password Encoder real**, implementando:

- `BCryptPasswordEncoder` (el estandar de la industria)
- Un `PasswordEncoder` custom para entender como funciona por dentro
- Por que NUNCA debes guardar passwords en texto plano

Es el paso natural: ya tenemos usuarios en BD, ahora falta que sus passwords esten encriptados de forma segura.

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `pom.xml` | Nuevas deps: `data-jpa`, `spring-jdbc`, `postgresql`, `lombok` |
| `docker-compose.yml` | Levanta PostgreSQL con esquema y datos iniciales |
| `db/sql/create_schema.sql` | Crea tabla `customers` (id, email, pwd, rol) |
| `db/sql/data.sql` | Inserta 2 usuarios de prueba |
| `application.properties` | Conexion a PostgreSQL (ya no tiene `spring.security.user.*`) |
| `entites/CustomerEntity.java` | Entidad JPA mapeada a la tabla `customers` |
| `repositories/CustomerRepository.java` | Repositorio con `findByEmail()` — query automatica |
| `security/CustomerUserDetails.java` | `UserDetailsService` custom — traduce de CustomerEntity a UserDetails |
| `security/SecurityConfig.java` | `PasswordEncoder` (NoOp) + enfoques InMemory y JDBC comentados |
