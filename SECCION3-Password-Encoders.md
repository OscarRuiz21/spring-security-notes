# Seccion 3: Password Encoders

> Notas del curso de Spring Security 6 — Por que nunca guardar passwords en texto plano y como encriptarlos correctamente

---

## Objetivo de la seccion

Reemplazar `NoOpPasswordEncoder` (texto plano) por **`BCryptPasswordEncoder`** (hash seguro), entendiendo:

- La **historia** de por que almacenar passwords evoluciono
- La interfaz `PasswordEncoder` y sus dos metodos clave
- Como funciona **BCrypt** por dentro (sal, factor de trabajo, hash adaptativo)
- Como implementar un `PasswordEncoder` custom (para entender el contrato)
- Por que BCrypt es el estandar de la industria

---

## Ubicacion en la Arquitectura

```
                        ┌────────────────┐
                        │   Password     │
                        │   Encoder      │ ◄── ESTAS AQUI
                        └───────▲────────┘
                                │
                                5  Valida password
                                │
                        ┌───────┴──────────┐
                        │  Auth Providers  │
                        └──────────────────┘
```

Esta seccion cubre el **paso 5** del diagrama maestro (ver Seccion 1): cuando el `AuthenticationProvider` ya tiene el password que envio el usuario y el password almacenado en BD, usa el `PasswordEncoder` para compararlos de forma segura. Aqui se entiende por que esa comparacion no puede ser un simple `equals()`.

---

## 1. ¿Por que importa como guardas los passwords?

### La historia del almacenamiento de passwords

Segun la documentacion oficial de Spring Security, el almacenamiento de passwords evoluciono en 4 etapas:

```
ETAPA 1: Texto plano
   password = "ideas"
   → Almacenado tal cual: "ideas"
   → Problema: si alguien accede a la BD, tiene TODOS los passwords

ETAPA 2: Hash simple (SHA-256, MD5)
   password = "ideas"
   → hash("ideas") = "a7f3b2e1c4d..."
   → Almacenado: "a7f3b2e1c4d..."
   → Problema: Rainbow Tables — tablas pre-calculadas con millones
     de hashes. Si "ideas" → "a7f3b2e1c4d...", el atacante ya lo
     tiene en su tabla y lo revierte instantaneamente.

ETAPA 3: Hash + Salt (sal aleatoria)
   password = "ideas", salt = "x9k2m"
   → hash("x9k2m" + "ideas") = "f8e2a1b..."
   → Almacenado: "x9k2m:f8e2a1b..."
   → Mejora: cada usuario tiene un salt diferente, asi que las
     Rainbow Tables ya no sirven (tendrias que calcular una por salt)
   → Problema: con hardware moderno, se pueden calcular MILES DE
     MILLONES de hashes SHA-256 por segundo. Un atacante con una GPU
     puede probar todas las combinaciones por fuerza bruta.

ETAPA 4: Funciones adaptativas (BCrypt, SCrypt, Argon2) ← HOY
   password = "ideas", salt = auto-generado, work factor = 10
   → bcrypt("ideas", salt, 10) = "$2a$10$dXJ3SW6G7P50..."
   → Almacenado: "$2a$10$dXJ3SW6G7P50..."
   → Solucion: el hash es INTENCIONALMENTE LENTO. Tarda ~1 segundo
     en calcularse. Un atacante necesitaria AÑOS para probar todas
     las combinaciones en vez de segundos.
```

### ¿Que es una "funcion adaptativa"?

Es una funcion de hash que puedes configurar para que sea **mas lenta** a medida que el hardware mejora. El parametro se llama **work factor** (factor de trabajo) o **strength**:

| Work factor | Iteraciones | Tiempo aprox. |
|---|---|---|
| 10 (default) | 2^10 = 1,024 | ~100ms |
| 12 | 2^12 = 4,096 | ~300ms |
| 14 | 2^14 = 16,384 | ~1 segundo |
| 16 | 2^16 = 65,536 | ~4 segundos |

**La recomendacion oficial de Spring:** Ajustar el work factor para que la verificacion tome **aproximadamente 1 segundo** en tu hardware. Esto es imperceptible para un usuario que hace login una vez, pero devastador para un atacante que necesita probar millones de combinaciones.

---

## 2. La Interfaz `PasswordEncoder`

### Concepto

`PasswordEncoder` es el contrato que Spring Security usa para todo lo relacionado con passwords. Tiene solo 2 metodos relevantes:

```java
public interface PasswordEncoder {

    // Toma el password en texto plano y devuelve el hash
    String encode(CharSequence rawPassword);

    // Compara un password en texto plano con un hash almacenado
    // rawPassword = lo que el usuario escribio en el formulario
    // encodedPassword = lo que esta guardado en la BD
    boolean matches(CharSequence rawPassword, String encodedPassword);

    // (Opcional) ¿Hay que re-encodear este password con un algoritmo mas nuevo?
    default boolean upgradeEncoding(String encodedPassword) {
        return false;
    }
}
```

### ¿Cuando se llama cada metodo?

```
REGISTRO (crear usuario):
   Usuario escribe: "mi_password_seguro"
        │
        ▼
   passwordEncoder.encode("mi_password_seguro")
        │
        ▼
   Retorna: "$2a$10$dXJ3SW6G7P50lGmM..."
        │
        ▼
   Se guarda en BD: pwd = "$2a$10$dXJ3SW6G7P50lGmM..."


LOGIN (autenticarse):
   Usuario escribe: "mi_password_seguro"
   BD tiene almacenado: "$2a$10$dXJ3SW6G7P50lGmM..."
        │
        ▼
   passwordEncoder.matches("mi_password_seguro", "$2a$10$dXJ3SW6G7P50lGmM...")
        │
        ▼
   Internamente:
     1. Extrae el salt del hash almacenado
     2. Aplica bcrypt("mi_password_seguro", salt_extraido)
     3. Compara el resultado con el hash almacenado
     4. ¿Son iguales? → true (login exitoso) / false (401)
```

**Punto clave:** `encode()` y `matches()` son **asimetricos**. No puedes "desencriptar" el hash para obtener el password original. Solo puedes verificar si un password dado produce el mismo hash.

---

## 3. Password Encoder Custom (educativo)

### Concepto

El curso crea un `PasswordEncoder` custom para mostrar como se ve la interfaz por dentro. **NO es seguro** — usa `String.hashCode()` que es trivial de revertir. Existe solo como ejercicio didactico.

### Implementacion: `MyPasswordEncoder.java`

```java
package com.javaoscar.app_security.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//@Component   ← Comentado: NO esta activo como bean
public class MyPasswordEncoder /*implements PasswordEncoder*/ {

    // Toma el password y devuelve su hashCode de Java como String
    public String encode(CharSequence rawPassword) {
        return String.valueOf(rawPassword.toString().hashCode());
    }

    // Calcula el hashCode del password ingresado y lo compara con el almacenado
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        var passwordAsString = String.valueOf(rawPassword.toString().hashCode());
        return encodedPassword.equals(passwordAsString);
    }
}
```

### ¿Por que esta comentado y desactivado?

Tres razones por las que `String.hashCode()` es TERRIBLE para passwords:

| Problema | Explicacion |
|---|---|
| **Reversible** | `hashCode()` produce un `int` de 32 bits — solo ~4 mil millones de posibilidades. Una Rainbow Table lo cubre completo |
| **Sin salt** | El mismo password siempre produce el mismo hash. Si dos usuarios tienen "password123", ambos tendran el mismo hash |
| **Rapido** | Se calcula en nanosegundos. Un atacante puede probar miles de millones por segundo |

### ¿Entonces para que sirve verlo?

Para entender el **contrato**:

1. `encode()` transforma el password en algo que NO es el password original
2. `matches()` verifica sin necesitar el password original — solo el hash almacenado

Cualquier `PasswordEncoder` real (BCrypt, SCrypt, Argon2) cumple el mismo contrato, pero de forma segura.

---

## 4. BCryptPasswordEncoder (el que queda activo)

### Concepto

BCrypt es una **funcion adaptativa de hash** disenada especificamente para passwords. Es el estandar de la industria y el default recomendado por Spring Security.

### ¿Que hace BCrypt diferente?

```
Entrada: "ideas"
                │
                ▼
┌─────────────────────────────────────────────────────────────┐
│  BCrypt                                                     │
│                                                             │
│  1. Genera un SALT aleatorio de 16 bytes                    │
│     salt = "x9k2mP7qR3..."                                 │
│                                                             │
│  2. Ejecuta el algoritmo Blowfish 2^strength veces          │
│     (con strength=10, son 1,024 iteraciones)                │
│     Cada iteracion mezcla el password + salt + resultado    │
│     anterior. Esto es lo que lo hace LENTO a proposito.     │
│                                                             │
│  3. Produce un hash de 60 caracteres que INCLUYE:           │
│     - La version del algoritmo ($2a$)                       │
│     - El strength ($10$)                                    │
│     - El salt (22 caracteres)                               │
│     - El hash (31 caracteres)                               │
│                                                             │
│  Resultado:                                                 │
│  $2a$10$N9qo8uLOickgx2ZMRZoMye.IjqQBrkUNS9jPQ2EcSbNF36g.d│
│  ─┬── ─┬─ ──────────┬────────── ──────────┬────────────────│
│   │    │             │                     │                │
│   │    │             salt                  hash             │
│   │    strength                                             │
│   version                                                   │
└─────────────────────────────────────────────────────────────┘
```

### Propiedades clave de BCrypt

| Propiedad | Que significa | Impacto |
|---|---|---|
| **Salt integrado** | Cada `encode()` genera un salt aleatorio diferente | El mismo password produce hashes DIFERENTES cada vez |
| **Adaptativo** | El `strength` controla cuantas iteraciones se hacen | Puedes hacerlo mas lento cuando el hardware mejore |
| **Lento a proposito** | Con strength=10, tarda ~100ms; con 14, ~1 segundo | Inviable para ataques de fuerza bruta |
| **Irreversible** | No existe forma matematica de "des-hashear" | Ni siquiera con la clave, solo puedes verificar |

### Ejemplo practico

```java
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

// Cada llamada a encode() produce un hash DIFERENTE (por el salt aleatorio)
encoder.encode("ideas");  // "$2a$10$N9qo8uLOickgx2ZMRZoMye..."
encoder.encode("ideas");  // "$2a$10$Ek7aHYKmUr5tSVLqGBPmXu..."  ← DIFERENTE
encoder.encode("ideas");  // "$2a$10$R4DsPQ7YRbGkEl9pXk2bje..."  ← DIFERENTE

// Pero matches() sabe verificar CUALQUIERA de ellos
encoder.matches("ideas", "$2a$10$N9qo8uLOickgx2ZMRZoMye...");  // true
encoder.matches("ideas", "$2a$10$Ek7aHYKmUr5tSVLqGBPmXu...");  // true
encoder.matches("wrong",  "$2a$10$N9qo8uLOickgx2ZMRZoMye..."); // false
```

**¿Como funciona `matches()` si el hash es diferente cada vez?** Porque el salt esta EMBEBIDO en el hash (los 22 caracteres despues del strength). `matches()` extrae el salt del hash almacenado, re-calcula bcrypt(password_ingresado, salt_extraido), y compara el resultado.

---

## 5. El Cambio en SecurityConfig

### Antes (Seccion 2)

```java
@Bean
PasswordEncoder passwordEncoder() {
    return NoOpPasswordEncoder.getInstance();  // Texto plano — INSEGURO
}
```

### Despues (Seccion 3)

```java
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();  // Hash BCrypt — SEGURO
}
```

**Una sola linea cambiada.** Esto es posible gracias al patron de **abstraccion por interfaz**: `DaoAuthenticationProvider` no sabe ni le importa que implementacion de `PasswordEncoder` usas. Solo llama a `matches()` y espera un `boolean`.

### Impacto en la BD

Con este cambio, los passwords en la tabla `customers` ahora deben estar **hasheados con BCrypt**. El password `'to_be_encoded'` en texto plano ya no funcionaria — habria que actualizarlo a su equivalente BCrypt:

```sql
-- ANTES (texto plano — ya no funciona):
INSERT INTO customers (email, pwd, rol) VALUES
    ('super_user@debuggeandoideas.com', 'to_be_encoded', 'admin');

-- DESPUES (hash BCrypt):
INSERT INTO customers (email, pwd, rol) VALUES
    ('super_user@debuggeandoideas.com',
     '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjqQBrkUNS9jPQ2EcSbNF36g.dCq',
     'admin');
```

---

## 6. Flujo Completo con BCrypt

```
Usuario envia: POST /login
    username: super_user@debuggeandoideas.com
    password: ideas
        │
        ▼
┌─────────────────────────────────────────────────────────────────┐
│  DaoAuthenticationProvider                                      │
│                                                                 │
│  PASO 1: Buscar usuario                                         │
│  → CustomerUserDetails.loadUserByUsername("super_user@...")      │
│  → PostgreSQL retorna:                                          │
│    UserDetails {                                                │
│      password: "$2a$10$N9qo8uLOickgx2ZMRZoMye..."              │
│    }                                                            │
│                                                                 │
│  PASO 2: Comparar password                                      │
│  → BCryptPasswordEncoder.matches(                               │
│        "ideas",                            // lo que escribio   │
│        "$2a$10$N9qo8uLOickgx2ZMRZoMye..." // lo de la BD       │
│    )                                                            │
│                                                                 │
│  INTERNAMENTE:                                                  │
│  1. Extrae salt de "$2a$10$N9qo8uLOickgx2ZMRZoMye..."          │
│     → salt = "N9qo8uLOickgx2ZMRZoMye"                          │
│  2. Calcula bcrypt("ideas", "N9qo8uLOickgx2ZMRZoMye", 10)      │
│     → resultado = "$2a$10$N9qo8uLOickgx2ZMRZoMye.IjqQBrk..."   │
│  3. ¿resultado == hash almacenado? → SI → matches retorna true  │
│                                                                 │
│  PASO 3: Autenticacion exitosa                                   │
│  → Crea Authentication con el principal y authorities            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Otros Password Encoders de Spring Security

Spring Security ofrece varias implementaciones. BCrypt es el default, pero existen alternativas para casos especificos:

| Encoder | Algoritmo | Fortaleza | Uso tipico |
|---|---|---|---|
| **BCryptPasswordEncoder** | Blowfish (bcrypt) | Intensivo en CPU | **Default recomendado.** Soportado en todas partes |
| **SCryptPasswordEncoder** | scrypt | Intensivo en CPU + **memoria** | Cuando quieres resistencia contra hardware custom (ASICs) |
| **Argon2PasswordEncoder** | Argon2id | Intensivo en CPU + memoria + paralelismo | El **mas moderno**. Ganador de Password Hashing Competition (2015) |
| **Pbkdf2PasswordEncoder** | PBKDF2 | Intensivo en CPU | Cuando necesitas cumplir con FIPS-140 (regulaciones gubernamentales USA) |
| **NoOpPasswordEncoder** | Ninguno (texto plano) | Nula | Solo para desarrollo/tests. **Deprecated** |

### ¿Cual elegir?

- **Si no tienes requisitos especiales:** `BCryptPasswordEncoder` (es lo que usa el curso)
- **Si quieres lo mas moderno y seguro:** `Argon2PasswordEncoder`
- **Si tienes regulaciones de gobierno:** `Pbkdf2PasswordEncoder`
- **Si te preocupan ataques con hardware especializado:** `SCryptPasswordEncoder`

### DelegatingPasswordEncoder (bonus: migracion de algoritmos)

Spring ofrece un encoder "inteligente" que soporta multiples algoritmos a la vez, util para **migrar passwords gradualmente**:

```java
// Crea un encoder que soporta todos los algoritmos, con BCrypt como default
PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
```

Este encoder lee el **prefijo** del hash almacenado para saber que algoritmo usar:

```
{bcrypt}$2a$10$dXJ3SW6G7P50lGmMkk...   → usa BCryptPasswordEncoder
{noop}password                           → usa NoOpPasswordEncoder (texto plano)
{scrypt}$e0801$8bWJaSu2IKSn9Z9kM+T...   → usa SCryptPasswordEncoder
{sha256}97cde38028ad898ebc02e6908...     → usa SHA-256 encoder
```

**Caso de uso real:** Imagina que tu app tiene 10,000 usuarios con passwords en SHA-256 (legacy). No puedes re-hashear todos porque no tienes los passwords originales. Con `DelegatingPasswordEncoder`:

1. Los usuarios viejos siguen funcionando con su hash `{sha256}...`
2. Los usuarios nuevos se crean con `{bcrypt}...`
3. Cuando un usuario viejo hace login, puedes re-hashear con BCrypt y actualizar la BD
4. Eventualmente, todos migran a BCrypt sin downtime

---

## 8. Comparativa: NoOpPasswordEncoder vs BCryptPasswordEncoder

| Aspecto | `NoOpPasswordEncoder` (antes) | `BCryptPasswordEncoder` (ahora) |
|---|---|---|
| **Password en BD** | `"to_be_encoded"` (texto plano) | `"$2a$10$N9qo8..."` (hash) |
| **Si roban la BD** | Tienen TODOS los passwords | Tienen hashes inutiles sin fuerza bruta |
| **Tiempo para crackear 1 password** | 0 segundos (ya esta en texto plano) | ~100 años (con hardware consumer) |
| **Mismo password, misma salida** | Si (`"ideas"` siempre es `"ideas"`) | No (salt aleatorio cambia el hash cada vez) |
| **Uso en produccion** | NUNCA | Si (estandar de la industria) |

---

## 9. ¿Que cambio respecto a la seccion 2?

Solo 3 archivos:

| Archivo | Cambio |
|---|---|
| `SecurityConfig.java` | `NoOpPasswordEncoder.getInstance()` → `new BCryptPasswordEncoder()` |
| `MyPasswordEncoder.java` | **Nuevo** (pero desactivado/comentado). Ejercicio educativo |
| `AppSecurityApplication.java` | Solo cambios de formato (sin impacto funcional) |

Es la seccion mas pequena en terminos de codigo, pero una de las mas importantes conceptualmente. Una sola linea cambiada transforma radicalmente la seguridad de toda la aplicacion.

---

## 10. Resumen Visual

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ALMACENAMIENTO DE PASSWORDS                      │
│                                                                     │
│  SECCION 2 (ANTES):                                                 │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  BD: pwd = "to_be_encoded"        (TEXTO PLANO)            │    │
│  │  SecurityConfig: NoOpPasswordEncoder                        │    │
│  │  matches("to_be_encoded", "to_be_encoded") → equals → true │    │
│  │  ⚠️ INSEGURO: si roban la BD, tienen todos los passwords    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                      │
│                              ▼                                      │
│  SECCION 3 (AHORA):                                                 │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  BD: pwd = "$2a$10$N9qo8uLOickgx2ZMRZoMye..."  (HASH)     │    │
│  │  SecurityConfig: BCryptPasswordEncoder                      │    │
│  │  matches("ideas", "$2a$10$...") → bcrypt+salt → true/false │    │
│  │  ✅ SEGURO: hash irreversible + salt + lento a proposito    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  PasswordEncoder (interfaz):                                        │
│  ┌────────────────────────────┐                                     │
│  │  encode(raw) → hash        │  Se usa al REGISTRAR usuario       │
│  │  matches(raw, hash) → bool │  Se usa al hacer LOGIN             │
│  └────────────────────────────┘                                     │
│                                                                     │
│  Implementaciones disponibles:                                      │
│  ├── BCryptPasswordEncoder    ← ACTIVO (default recomendado)        │
│  ├── Argon2PasswordEncoder    ← El mas moderno                      │
│  ├── SCryptPasswordEncoder    ← Resistente a hardware custom        │
│  ├── Pbkdf2PasswordEncoder    ← Cumple regulaciones FIPS-140        │
│  └── NoOpPasswordEncoder      ← DEPRECATED (solo desarrollo)        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 11. ¿Que viene en la siguiente seccion?

En la **Seccion 4** se reemplaza la cadena automatica de `DaoAuthenticationProvider` por un **`AuthenticationProvider` custom**, para tener control total sobre como se validan las credenciales:

- Se elimina `CustomerUserDetails` (el `UserDetailsService` custom)
- Se crea `MyAuthenticationProvider` que implementa `AuthenticationProvider` directamente
- Se entiende la diferencia entre delegar la autenticacion (via `UserDetailsService`) y hacerla tu mismo (via `AuthenticationProvider`)

---

## Archivos clave de esta seccion

| Archivo | Que hace |
|---|---|
| `security/SecurityConfig.java` | Cambia `NoOpPasswordEncoder` por `BCryptPasswordEncoder` |
| `security/MyPasswordEncoder.java` | Encoder custom educativo (desactivado). Muestra el contrato de `PasswordEncoder` |
| `AppSecurityApplication.java` | Sin cambios funcionales (solo formato) |
