from flask import Flask, render_template, request, session
from flask_session import Session
import os
import bcrypt
import psycopg2
import mysql.connector
from db_generator import test_connection, list_databases, list_docker_databases, init_nest_project, generate_nest_modules, execute_query

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'your-secret-key'
Session(app)

# Configuración predeterminada para Docker
DOCKER_POSTGRES_CONFIG = {"host": "localhost",
                          "port": "5450", "username": "root", "password": "root"}
DOCKER_MYSQL_CONFIG = {"host": "localhost",
                       "port": "3311", "username": "root", "password": "root"}
DEFAULT_NEST_SRC = "C:/Tareas Hechas/Taller de especialidad/NestArchivosGen"


def create_users_table(db_type, host, port, username, password, database):
    """Crea la tabla 'users' en la base de datos seleccionada, eliminándola primero si existe."""
    try:
        if db_type == 'postgres':
            conn = psycopg2.connect(
                host=host, port=port, database=database, user=username, password=password)
            cursor = conn.cursor()
            # Eliminar la tabla si existe
            cursor.execute("DROP TABLE IF EXISTS users CASCADE;")
            # Crear la tabla
            cursor.execute("""
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                );
            """)
            # Insertar un usuario por defecto
            default_username = "admin"
            default_password = bcrypt.hashpw("admin123".encode(
                'utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s);",
                           (default_username, default_password))
            conn.commit()
            cursor.close()
            conn.close()
            return True, None
        elif db_type == 'mysql':
            conn = mysql.connector.connect(
                host=host, port=port, database=database, user=username, password=password)
            cursor = conn.cursor()
            # Eliminar la tabla si existe
            cursor.execute("DROP TABLE IF EXISTS users;")
            # Crear la tabla
            cursor.execute("""
                CREATE TABLE users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                );
            """)
            # Insertar un usuario por defecto
            default_username = "admin"
            default_password = bcrypt.hashpw("admin123".encode(
                'utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s);",
                           (default_username, default_password))
            conn.commit()
            cursor.close()
            conn.close()
            return True, None
        else:
            return False, "Tipo de base de datos no soportado."
    except (psycopg2.Error, mysql.connector.Error) as e:
        return False, f"Error al crear tabla users: {str(e)}"
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


@app.route('/', methods=['GET', 'POST'])
def home():
    status = "Esperando acción..."
    result = None
    error = None
    db_type = request.form.get('db_type', session.get('db_type', 'postgres'))
    connection_type = request.form.get(
        'connection_type', session.get('connection_type', 'manual'))
    host = request.form.get('host', session.get('host', ''))
    port = request.form.get('port', session.get('port', ''))
    username = request.form.get('username', session.get('username', ''))
    password = request.form.get('password', session.get('password', ''))
    selected_db = request.form.get(
        'selected_db', session.get('selected_db', ''))
    nest_src = request.form.get(
        'nest_src', session.get('nest_src', DEFAULT_NEST_SRC))
    project_name = request.form.get(
        'project_name', session.get('project_name', 'my-nest-project'))
    sql_query = request.form.get('sql_query', '')
    action = request.form.get('action')
    databases = session.get('databases', [])
    is_connected = session.get('is_connected', False)

    # Guardar configuración en la sesión
    session['db_type'] = db_type
    session['connection_type'] = connection_type
    session['host'] = host
    session['port'] = port
    session['username'] = username
    session['password'] = password
    session['selected_db'] = selected_db
    session['nest_src'] = nest_src
    session['project_name'] = project_name

    # Manejo de conexión inicial
    if action == 'connect':
        if connection_type == 'manual' and host and port and username:
            config = {"host": host, "port": port,
                      "username": username, "password": password}
        elif connection_type == 'docker':
            config = DOCKER_POSTGRES_CONFIG if db_type == 'postgres' else DOCKER_MYSQL_CONFIG
        else:
            config = None
            status = "Faltan datos de conexión."
            error = "Por favor, completa todos los campos para la conexión manual o selecciona Docker."

        if config:
            # Probar conexión inicial a la base administrativa
            databases, error = list_databases(
                db_type, config['host'], config['port'], config['username'], config['password'])
            if error:
                status = f"Error al conectar: {error}"
                is_connected = False
            else:
                is_connected = True
                status = f"Conexión exitosa a {db_type} en {config['host']}:{config['port']}"
                session['config'] = config
                session['databases'] = databases
                session['is_connected'] = True

    # Manejo de selección de base de datos
    if selected_db and is_connected and session.get('config'):
        success, error = test_connection(db_type, session['config']['host'], session['config']
                                         ['port'], session['config']['username'], session['config']['password'], selected_db)
        if success:
            # Crear tabla users al conectar a la base de datos
            success, error = create_users_table(
                db_type, session['config']['host'], session['config']['port'], session['config']['username'], session['config']['password'], selected_db)
            if success:
                status = f"BD {selected_db} Conectada. Tabla 'users' creada o verificada."
                session['selected_db'] = selected_db
            else:
                status = f"Error al crear tabla users en {selected_db}: {error}"
                is_connected = False
                session['is_connected'] = False
                session['selected_db'] = ''
        else:
            status = f"Error al conectar a BD {selected_db}: {error}"
            is_connected = False
            session['is_connected'] = False
            session['selected_db'] = ''

    # Ejecutar consulta SQL
    if action == 'query' and is_connected and selected_db and session.get('config'):
        success, query_result, query_error = execute_query(
            db_type, session['config']['host'], session['config']['port'], session['config']['username'], session['config']['password'], selected_db, sql_query)
        if success:
            result = query_result
            status = f"Consulta ejecutada exitosamente en {selected_db}"
        else:
            error = query_error
            status = query_error

    # Generar proyecto NestJS y módulos
    if action == 'generate' and is_connected and selected_db and session.get('config'):
        if not project_name:
            error = "El nombre del proyecto NestJS es requerido."
            status = error
        else:
            try:
                # Crear proyecto NestJS y instalar dependencias
                success, msg = init_nest_project(nest_src, project_name)
                if not success:
                    error = msg
                    status = msg
                else:
                    status = msg
                    # Generar módulos en la carpeta src del proyecto creado
                    project_src = os.path.join(nest_src, project_name, 'src')
                    success, msg = generate_nest_modules(
                        db_type,
                        session['config']['host'],
                        session['config']['port'],
                        session['config']['username'],
                        session['config']['password'],
                        selected_db,
                        project_src
                    )
                    if success:
                        status = f"{status}\n{msg}"
                    else:
                        error = msg
                        status = msg
            except Exception as e:
                error = f"Error al generar: {str(e)}"
                status = error

    session['is_connected'] = is_connected
    session['databases'] = databases

    return render_template('index.html',
                           status=status,
                           result=result,
                           error=error,
                           db_type=db_type,
                           connection_type=connection_type,
                           host=host,
                           port=port,
                           username=username,
                           password=password,
                           databases=databases,
                           selected_db=selected_db,
                           nest_src=nest_src,
                           project_name=project_name,
                           sql_query=sql_query,
                           is_connected=is_connected)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=7000)
