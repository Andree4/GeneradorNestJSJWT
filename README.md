# Generador de Módulos NestJS y Gestor de Base de Datos

## 📋 Autor

Arancibia Aguilar Daniel Andre

Ingeniería en Ciencias de la Computación

## 📋 Descripción General

Este proyecto es una aplicación web basada en Flask diseñada para optimizar la gestión de bases de datos relacionales (PostgreSQL y MySQL) y automatizar la generación de aplicaciones backend NestJS seguras y modulares. Permite a los desarrolladores conectarse a bases de datos manualmente o a través de Docker, ejecutar consultas SQL a través de una interfaz web amigable, y generar proyectos NestJS con módulos basados en las tablas de la base de datos.

Los proyectos generados incluyen un sistema de autenticación robusto usando JSON Web Tokens (JWT) y una tabla de usuarios con contraseñas cifradas con bcrypt, lo que los hace ideales para el desarrollo rápido de APIs en entornos de laboratorio o empresariales.

## ✨ Características

- 🔌 Conexión a bases de datos PostgreSQL o MySQL (locales o Docker)
- 🔍 Ejecución de consultas SQL y visualización de resultados en formato JSON
- 👤 Creación automática de tabla de usuarios con usuario administrador por defecto (`admin` / `admin123`)
- 🏗️ Generación de proyectos NestJS con módulos para cada tabla de la base de datos
- 🛡️ Sistema de autenticación seguro con JWT y cifrado bcrypt
- 📦 Generación completa de entidades, DTOs, servicios y controladores

## 🛠️ Tecnologías Utilizadas

### Backend (Flask)

- **Flask**: Interfaz web y lógica del servidor
- **Python**: Conexiones a base de datos y análisis de esquemas
  - `psycopg2`, `mysql-connector-python`, `pymysql`
  - `SQLAlchemy`
- **Bcrypt**: Seguridad de contraseñas

### Aplicación Generada (NestJS)

- **NestJS**: Framework para aplicaciones escalables y modulares
- **TypeORM**: Mapeo objeto-relacional para TypeScript
- **JWT**: Autenticación de endpoints de API
- **Node.js/NestJS CLI**: Creación y gestión de proyectos

## 📋 Requisitos Previos

- **Python 3.8+** y **Node.js v16+** instalados
- Base de datos **PostgreSQL** o **MySQL** (local o Docker)
- **Docker** (opcional) para configuraciones de base de datos en contenedores
- **NestJS CLI**:
  ```bash
  npm install -g @nestjs/cli
  ```

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone <repository-url>
cd <repository-directory>
```

### 2. Configurar entorno Python

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### 3. Configurar base de datos

Asegúrate de tener una base de datos PostgreSQL o MySQL ejecutándose:

**Con Docker:**

- PostgreSQL: Puerto 5450, credenciales `root/root`
- MySQL: Puerto 3311, credenciales `root/root`

**Local:**

- PostgreSQL: Puerto por defecto 5432
- MySQL: Puerto por defecto 3306

## 💻 Uso

### 1. Iniciar la aplicación Flask

```bash
python app.py
```

### 2. Acceder a la interfaz web

Abre [http://localhost:5000](http://localhost:5000) en tu navegador.

### 3. Configurar conexión a base de datos

- Selecciona **PostgreSQL** o **MySQL**
- Elige **manual** (introduce host, puerto, usuario, contraseña) o **Docker** (configuración preconfigurada)

### 4. Seleccionar base de datos

Elige una base de datos para crear la tabla de usuarios con el usuario administrador por defecto.

### 5. Usar la interfaz para:

- Ejecutar consultas SQL y ver resultados en JSON
- Generar un proyecto NestJS especificando nombre y ruta base

### 6. Configurar proyecto NestJS generado

```bash
cd ruta/al/proyecto-nest-generado
npm install
npm run start:dev
```

### 7. Acceder a la API

La API NestJS estará disponible en [http://localhost:3000](http://localhost:3000).

## 📁 Estructura del Proyecto Generado

El proyecto NestJS generado incluye:

### Configuración Principal

- **`app.module.ts`**: Configuración de la aplicación y conexión a base de datos

### Módulos de Tablas

Para cada tabla de la base de datos (ej: `products`):

- **Entity**: Mapea columnas y relaciones usando TypeORM
- **DTO**: Define estructuras de datos para operaciones CRUD
- **Service**: Maneja la lógica de negocio para CRUD
- **Controller**: Proporciona endpoints RESTful (GET, POST, PUT, DELETE) protegidos por JWT

### Módulo de Autenticación

- **`user.entity.ts`**: Mapea la tabla de usuarios
- **`auth.dto.ts`**: Define estructuras para registro e inicio de sesión
- **`auth.service.ts`** y **`auth.controller.ts`**: Gestionan endpoints `/auth/register` y `/auth/login`
- **`jwt.strategy.ts`** y **`jwt-auth.guard.ts`**: Implementan autenticación JWT

## 🧪 Pruebas

### 1. Conexión a Base de Datos

- En [http://localhost:5000](http://localhost:5000), conecta a una base de datos y verifica la lista de bases de datos disponibles

### 2. Tabla de Usuarios

- Selecciona una base de datos
- Ejecuta `SELECT * FROM users;` para confirmar que existe el usuario admin con contraseña cifrada

### 3. Consultas SQL

- Ejecuta consultas como `SELECT * FROM <tabla>;` o declaraciones INSERT
- Verifica resultados JSON o confirmación de ejecución

### 4. Generación de Proyecto

- Genera un proyecto NestJS y verifica su estructura

### 5. Pruebas de API (usando Postman)

#### Autenticación

```bash
POST http://localhost:3000/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

#### Acceso a Endpoints Protegidos

```bash
GET http://localhost:3000/<tabla>
Authorization: Bearer <token-jwt>
```

#### Registro de Nuevo Usuario

```bash
POST http://localhost:3000/auth/register
Content-Type: application/json

{
  "username": "nuevo_usuario",
  "password": "mi_contraseña"
}
```

### 6. Pruebas de Seguridad

- Intenta acceder a endpoints sin token o con credenciales inválidas
- Debe devolver error 401 (No autorizado)

## 🔧 Solución de Problemas

### Errores de Conexión

- Asegúrate de que la base de datos esté ejecutándose
- Verifica que las credenciales y puertos coincidan:
  - PostgreSQL Docker: Puerto 5450
  - MySQL Docker: Puerto 3311

### Conflictos de Tablas

- Si ocurren errores de TypeORM, verifica `synchronize: false` en `app.module.ts`
- Recrea la tabla de usuarios a través de Flask si es necesario

### Problemas con JWT

- Asegúrate de que el secreto JWT en `auth.module.ts` y `jwt.strategy.ts` sea consistente
- Reemplaza `your-secret-key` con un valor seguro

### Dependencias Faltantes

- Ejecuta `npm install` en el proyecto NestJS generado si faltan módulos

Este proyecto está licenciado bajo la **Licencia MIT**.

---
