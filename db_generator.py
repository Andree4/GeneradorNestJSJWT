import os
import subprocess
import psycopg2
import mysql.connector
from sqlalchemy import create_engine, inspect, MetaData, text
from sqlalchemy.exc import OperationalError


def test_connection(db_type, host, port, username, password, database):
    """Prueba la conexión a una base de datos específica."""
    try:
        if db_type == 'postgres':
            conn = psycopg2.connect(
                host=host, port=port, database=database, user=username, password=password
            )
            conn.close()
            return True, None
        elif db_type == 'mysql':
            conn = mysql.connector.connect(
                host=host, port=port, database=database, user=username, password=password
            )
            conn.close()
            return True, None
        else:
            return False, "Tipo de base de datos no soportado."
    except (psycopg2.Error, mysql.connector.Error) as e:
        return False, f"Error al conectar: {str(e)}"
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def list_databases(db_type, host, port, username, password):
    """Lista las bases de datos disponibles, como en consola."""
    try:
        if db_type == 'postgres':
            conn = psycopg2.connect(
                host=host, port=port, database='postgres', user=username, password=password
            )
            cursor = conn.cursor()
            cursor.execute(
                "SELECT datname FROM pg_database WHERE datistemplate = false;")
            databases = [row[0] for row in cursor.fetchall()]
            cursor.close()
            conn.close()
            return databases, None
        elif db_type == 'mysql':
            conn = mysql.connector.connect(
                host=host, port=port, user=username, password=password
            )
            cursor = conn.cursor()
            cursor.execute("SHOW DATABASES;")
            databases = [row[0] for row in cursor.fetchall()]
            cursor.close()
            conn.close()
            return databases, None
        else:
            return [], "Tipo de base de datos no soportado."
    except (psycopg2.Error, mysql.connector.Error) as e:
        return [], f"Error al conectar: {str(e)}"
    except Exception as e:
        return [], f"Error inesperado al listar DBs: {str(e)}"


def list_docker_databases(db_type):
    """Lista bases de datos en contenedores Docker."""
    try:
        if db_type == 'postgres':
            return list_databases(db_type, 'localhost', '5450', 'root', 'root')
        elif db_type == 'mysql':
            return list_databases(db_type, 'localhost', '3311', 'root', 'root')
        else:
            return [], "Tipo de base de datos no soportado."
    except Exception as e:
        return [], f"Error al listar DBs en Docker: {str(e)}"


def init_nest_project(base_path, project_name):
    """Inicializa un proyecto NestJS con el nombre especificado y dependencias."""
    try:
        project_path = os.path.join(base_path, project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path, exist_ok=True)
            subprocess.run(
                ["nest", "new", project_name, "-p", "npm", "--skip-git"],
                cwd=base_path,
                shell=True,
                check=True,
                capture_output=True,
                text=True
            )
            status = f"Proyecto NestJS '{project_name}' creado en {project_path}"
        else:
            status = f"Proyecto NestJS '{project_name}' ya existe en {project_path}"

        # Instalar dependencias necesarias, incluyendo JWT
        subprocess.run(
            ["npm", "install", "@nestjs/typeorm", "typeorm", "pg", "mysql2",
                "@nestjs/jwt", "@nestjs/passport", "passport", "passport-jwt", "bcrypt"],
            cwd=project_path,
            shell=True,
            check=True,
            capture_output=True,
            text=True
        )
        return True, f"{status}\nDependencias instaladas exitosamente."
    except subprocess.CalledProcessError as e:
        return False, f"Error al crear/instalar proyecto NestJS: {e.stderr}"
    except Exception as e:
        return False, f"Error inesperado al crear proyecto NestJS: {str(e)}"


def to_pascal(name):
    """Convertir snake_case a PascalCase."""
    return ''.join(word.capitalize() for word in name.split('_'))


def db_to_ts_type(db_type, col_type, nullable=False):
    """Mapear tipos de DB a tipos de TypeScript/TypeORM."""
    base_type = str(col_type).split('(')[0].upper()
    pg_mapping = {
        "INTEGER": ("number", "int"),
        "BIGINT": ("number", "bigint"),
        "SMALLINT": ("number", "smallint"),
        "SERIAL": ("number", "int"),
        "BIGSERIAL": ("number", "bigint"),
        "VARCHAR": ("string", "varchar"),
        "TEXT": ("string", "text"),
        "CHAR": ("string", "char"),
        "BOOLEAN": ("boolean", "boolean"),
        "TIMESTAMP": ("Date", "timestamp"),
        "TIMESTAMP WITHOUT TIME ZONE": ("Date", "timestamp"),
        "DATE": ("Date", "date"),
        "UUID": ("string", "uuid"),
        "JSON": ("any", "json"),
        "JSONB": ("any", "jsonb"),
        "FLOAT": ("number", "float"),
        "DOUBLE PRECISION": ("number", "double precision"),
        "NUMERIC": ("number", "numeric"),
        "DECIMAL": ("number", "decimal"),
    }
    mysql_mapping = {
        "INT": ("number", "int"),
        "BIGINT": ("number", "bigint"),
        "SMALLINT": ("number", "smallint"),
        "TINYINT": ("number", "tinyint"),
        "VARCHAR": ("string", "varchar"),
        "TEXT": ("string", "text"),
        "CHAR": ("string", "char"),
        "BOOLEAN": ("boolean", "boolean"),
        "TIMESTAMP": ("Date", "timestamp"),
        "DATETIME": ("Date", "datetime"),
        "DATE": ("Date", "date"),
        "JSON": ("any", "json"),
        "FLOAT": ("number", "float"),
        "DOUBLE": ("number", "double"),
        "DECIMAL": ("number", "decimal"),
    }
    mapping = pg_mapping if db_type == 'postgres' else mysql_mapping
    ts_type, typeorm_type = mapping.get(base_type, ("any", "varchar"))
    return (ts_type if not nullable else f"{ts_type} | null", typeorm_type)


def get_primary_keys(inspector, table):
    """Obtener los nombres de las columnas de la clave primaria."""
    try:
        pk_constraint = inspector.get_pk_constraint(table)
        return pk_constraint['constrained_columns'] if pk_constraint['constrained_columns'] else ['id']
    except Exception:
        return ['id']


def get_relations(inspector, table):
    """Obtener relaciones de clave foránea y relaciones inversas."""
    fks = inspector.get_foreign_keys(table)
    relations = {fk['constrained_columns'][0]                 : fk['referred_table'] for fk in fks}
    inverse_relations = {}
    for other_table in inspector.get_table_names():
        if other_table == table:
            continue
        other_fks = inspector.get_foreign_keys(other_table)
        for fk in other_fks:
            if fk['referred_table'] == table:
                inverse_relations[other_table] = fk['constrained_columns'][0]
    return relations, inverse_relations


def generate_module(engine, db_type, table, nest_src):
    """Generar archivos del módulo NestJS para una tabla dada."""
    try:
        inspector = inspect(engine)
        class_name = to_pascal(table)
        folder_path = os.path.join(nest_src, table)
        os.makedirs(folder_path, exist_ok=True)

        columns = inspector.get_columns(table)
        relations, inverse_relations = get_relations(inspector, table)
        pk_columns = get_primary_keys(inspector, table)

        # entity.ts
        entity = f"""import {{ Entity, Column, PrimaryGeneratedColumn, ManyToOne, OneToMany }} from 'typeorm';\n"""
        imported_entities = set(relations.values()) | set(
            inverse_relations.keys())
        for ref in imported_entities:
            entity += f"import {{ {to_pascal(ref)} }} from '../{ref}/{ref}.entity';\n"

        entity += f"\n@Entity()\nexport class {class_name} {{\n"
        for col in columns:
            name = col['name']
            ts_type, typeorm_type = db_to_ts_type(
                db_type, col['type'], col.get('nullable', False))
            is_pk = name in pk_columns
            if is_pk:
                entity += f"  @PrimaryGeneratedColumn()\n"
            elif name in relations:
                entity += f"  @ManyToOne(() => {to_pascal(relations[name])}, {{ nullable: {str(col.get('nullable', False)).lower()} }})\n"
            else:
                type_option = f"{{ type: '{typeorm_type}', nullable: {str(col.get('nullable', False)).lower()} }}"
                entity += f"  @Column({type_option})\n"
            entity += f"  {name}: {ts_type};\n"

        for inv_table, fk_column in inverse_relations.items():
            inv_class_name = to_pascal(inv_table)
            inv_property = inv_table if inv_table.endswith(
                's') else f"{inv_table}s"
            entity += f"  @OneToMany(() => {inv_class_name}, ({inv_table}) => {inv_table}.{fk_column})\n"
            entity += f"  {inv_property}: {inv_class_name}[];\n"

        entity += "}\n"
        with open(f"{folder_path}/{table}.entity.ts", "w", encoding="utf-8") as f:
            f.write(entity)

        # dto.ts
        dto = f"export class Create{class_name}Dto {{\n"
        for col in columns:
            if col['name'] not in pk_columns:
                ts_type, _ = db_to_ts_type(
                    db_type, col['type'], col.get('nullable', False))
                dto += f"  readonly {col['name']}: {ts_type};\n"
        dto += "}\n"
        with open(f"{folder_path}/{table}.dto.ts", "w", encoding="utf-8") as f:
            f.write(dto)

        # service.ts
        service = f"""import {{ Injectable, NotFoundException }} from '@nestjs/common';
import {{ InjectRepository }} from '@nestjs/typeorm';
import {{ Repository }} from 'typeorm';
import {{ {class_name} }} from './{table}.entity';
import {{ Create{class_name}Dto }} from './{table}.dto';

@Injectable()
export class {class_name}Service {{
  constructor(
    @InjectRepository({class_name})
    private repo: Repository<{class_name}>,
  ) {{}}

  async create(dto: Create{class_name}Dto) {{
    const entity = this.repo.create(dto);
    return this.repo.save(entity);
  }}

  findAll() {{
    return this.repo.find({{ relations: [{', '.join(f"'{rel}'" for rel in relations.values())}] }});
  }}

  async findOne(id: {db_to_ts_type(db_type, columns[0]['type'])[0]}) {{
    const entity = await this.repo.findOneBy({{ {pk_columns[0]}: id }});
    if (!entity) throw new NotFoundException('{class_name} no encontrado');
    return entity;
  }}

  async update(id: {db_to_ts_type(db_type, columns[0]['type'])[0]}, dto: Create{class_name}Dto) {{
    const entity = await this.findOne(id);
    Object.assign(entity, dto);
    return this.repo.save(entity);
  }}

  async remove(id: {db_to_ts_type(db_type, columns[0]['type'])[0]}) {{
    const entity = await this.findOne(id);
    return this.repo.remove(entity);
  }}
}}
"""
        with open(f"{folder_path}/{table}.service.ts", "w", encoding="utf-8") as f:
            f.write(service)

        # controller.ts (with JWT guard)
        controller = f"""import {{ Controller, Get, Post, Body, Param, Put, Delete, ParseIntPipe, ParseUUIDPipe, UseGuards }} from '@nestjs/common';
import {{ {class_name}Service }} from './{table}.service';
import {{ Create{class_name}Dto }} from './{table}.dto';
import {{ JwtAuthGuard }} from '../auth/jwt-auth.guard';

@Controller('{table}')
@UseGuards(JwtAuthGuard)
export class {class_name}Controller {{
  constructor(private readonly service: {class_name}Service) {{}}

  @Post()
  create(@Body() dto: Create{class_name}Dto) {{
    return this.service.create(dto);
  }}

  @Get()
  findAll() {{
    return this.service.findAll();
  }}

  @Get(':id')
  findOne(@Param('id', {'ParseIntPipe' if db_to_ts_type(db_type, columns[0]['type'])[0] == 'number' else 'ParseUUIDPipe'}) id: {db_to_ts_type(db_type, columns[0]['type'])[0]}) {{
    return this.service.findOne(id);
  }}

  @Put(':id')
  update(@Param('id', {'ParseIntPipe' if db_to_ts_type(db_type, columns[0]['type'])[0] == 'number' else 'ParseUUIDPipe'}) id: {db_to_ts_type(db_type, columns[0]['type'])[0]}, @Body() dto: Create{class_name}Dto) {{
    return this.service.update(id, dto);
  }}

  @Delete(':id')
  remove(@Param('id', {'ParseIntPipe' if db_to_ts_type(db_type, columns[0]['type'])[0] == 'number' else 'ParseUUIDPipe'}) id: {db_to_ts_type(db_type, columns[0]['type'])[0]}) {{
    return this.service.remove(id);
  }}
}}
"""
        with open(f"{folder_path}/{table}.controller.ts", "w", encoding="utf-8") as f:
            f.write(controller)

        # module.ts
        module = f"""import {{ Module }} from '@nestjs/common';
import {{ TypeOrmModule }} from '@nestjs/typeorm';
import {{ {class_name} }} from './{table}.entity';
import {{ {class_name}Service }} from './{table}.service';
import {{ {class_name}Controller }} from './{table}.controller';

@Module({{
  imports: [TypeOrmModule.forFeature([{class_name}])],
  controllers: [{class_name}Controller],
  providers: [{class_name}Service],
}})
export class {class_name}Module {{}}
"""
        with open(f"{folder_path}/{table}.module.ts", "w", encoding="utf-8") as f:
            f.write(module)

        return f"{class_name}Module", f"./{table}/{table}.module"

    except Exception as e:
        print(f"Error generando módulo para la tabla {table}: {str(e)}")
        return None, None


def generate_auth_module(engine, db_type, nest_src):
    """Generar módulo de autenticación con JWT."""
    try:
        folder_path = os.path.join(nest_src, 'auth')
        os.makedirs(folder_path, exist_ok=True)

        # user.entity.ts
        user_entity = """import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 255, unique: true })
  username: string;

  @Column({ type: 'varchar', length: 255 })
  password: string;
}
"""
        with open(f"{folder_path}/user.entity.ts", "w", encoding="utf-8") as f:
            f.write(user_entity)

        # auth.dto.ts
        auth_dto = """export class RegisterDto {
  readonly username: string;
  readonly password: string;
}

export class LoginDto {
  readonly username: string;
  readonly password: string;
}
"""
        with open(f"{folder_path}/auth.dto.ts", "w", encoding="utf-8") as f:
            f.write(auth_dto)

        # jwt.strategy.ts
        jwt_strategy = """import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'your-secret-key', // Cambia esto por una clave segura
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, username: payload.username };
  }
}
"""
        with open(f"{folder_path}/jwt.strategy.ts", "w", encoding="utf-8") as f:
            f.write(jwt_strategy)

        # auth.service.ts
        auth_service = """import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { User } from './user.entity';
import { RegisterDto, LoginDto } from './auth.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    const { username, password } = dto;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = this.usersRepository.create({ username, password: hashedPassword });
    await this.usersRepository.save(user);
    return { message: 'Usuario registrado exitosamente' };
  }

  async login(dto: LoginDto) {
    const { username, password } = dto;
    const user = await this.usersRepository.findOneBy({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Credenciales inválidas');
    }
    const payload = { username: user.username, sub: user.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
"""
        with open(f"{folder_path}/auth.service.ts", "w", encoding="utf-8") as f:
            f.write(auth_service)

        # auth.controller.ts
        auth_controller = """import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto } from './auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }
}
"""
        with open(f"{folder_path}/auth.controller.ts", "w", encoding="utf-8") as f:
            f.write(auth_controller)

        # auth.module.ts
        auth_module = """import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from './user.entity';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret: 'your-secret-key', // Cambia esto por una clave segura
      signOptions: { expiresIn: '60m' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [JwtStrategy, PassportModule],
})
export class AuthModule {}
"""
        with open(f"{folder_path}/auth.module.ts", "w", encoding="utf-8") as f:
            f.write(auth_module)

        # jwt-auth.guard.ts
        jwt_guard = """import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
"""
        with open(f"{folder_path}/jwt-auth.guard.ts", "w", encoding="utf-8") as f:
            f.write(jwt_guard)

        return "AuthModule", "./auth/auth.module"

    except Exception as e:
        print(f"Error generando módulo de autenticación: {str(e)}")
        return None, None


def generate_nest_modules(db_type, host, port, username, password, database, nest_src):
    """Genera módulos NestJS para todas las tablas de la BD, incluyendo autenticación."""
    try:
        # Usar pymysql para conexiones MySQL con SQLAlchemy
        dialect = 'postgresql' if db_type == 'postgres' else 'mysql+pymysql'
        db_url = f"{dialect}://{username}:{password}@{host}:{port}/{database}"
        engine = create_engine(db_url)
        db_type = 'postgres' if db_type == 'postgres' else 'mysql'
        inspector = inspect(engine)
        metadata = MetaData()
        metadata.reflect(bind=engine)
        modules = [generate_module(engine, db_type, table, nest_src)
                   for table in inspector.get_table_names()]
        modules = [m for m in modules if m[0] is not None]

        # Generar módulo de autenticación
        auth_module = generate_auth_module(engine, db_type, nest_src)
        if auth_module[0] is not None:
            modules.append(auth_module)

        imports_array = ',\n    '.join([m[0] for m in modules])
        paths_array = '\n'.join(
            [f"import {{ {m[0]} }} from '{m[1]}';" for m in modules])

        app_module_path = os.path.join(nest_src, 'app.module.ts')
        with open(app_module_path, 'w', encoding="utf-8") as f:
            f.write(f"""import {{ Module }} from '@nestjs/common';
import {{ TypeOrmModule }} from '@nestjs/typeorm';
{paths_array}

@Module({{
  imports: [
    TypeOrmModule.forRoot({{
      type: '{db_type}',
      host: '{host}',
      port: {port},
      username: '{username}',
      password: '{password}',
      database: '{database}',
      autoLoadEntities: true,
      synchronize: false, // Desactivado para evitar conflictos con el esquema existente
    }}),
    {imports_array}
  ],
}})
export class AppModule {{}}
""")
        return True, "Módulos generados exitosamente, incluyendo autenticación."
    except Exception as e:
        return False, f"Error durante la generación: {str(e)}"


def execute_query(db_type, host, port, username, password, database, query):
    """Ejecuta una consulta SQL en la base de datos seleccionada."""
    try:
        if db_type == 'postgres':
            conn = psycopg2.connect(
                host=host, port=port, database=database, user=username, password=password
            )
            cursor = conn.cursor()
            cursor.execute(query)
            if cursor.description:  # Verifica si la consulta devuelve resultados
                columns = [desc[0] for desc in cursor.description]
                rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
            else:
                columns, rows = [], []
                conn.commit()
            cursor.close()
            conn.close()
            return True, {"columns": columns, "rows": rows}, None
        elif db_type == 'mysql':
            conn = mysql.connector.connect(
                host=host, port=port, database=database, user=username, password=password
            )
            cursor = conn.cursor()
            cursor.execute(query)
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]
                rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
            else:
                columns, rows = [], []
                conn.commit()
            cursor.close()
            conn.close()
            return True, {"columns": columns, "rows": rows}, None
        else:
            return False, None, "Tipo de base de datos no soportado."
    except (psycopg2.Error, mysql.connector.Error) as e:
        return False, None, f"Error al ejecutar consulta: {str(e)}"
    except Exception as e:
        return False, None, f"Error inesperado: {str(e)}"
