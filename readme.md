# Sistema de Gestión de Visitantes - Banco Agrícola de Venezuela

Este es un sistema web robusto desarrollado en **Django** para el control y registro de visitantes en las sedes del Banco Agrícola. Permite gestionar de manera eficiente quién entra y sale, manteniendo un historial detallado y seguro.

## Características Principales
* **Gestión de Visitantes**: Registro con foto, cédula, nombre y teléfono.
* **Directorio Interactivo**: Búsqueda rápida de personas registradas.
* **Control de Presencia**: Visualización en tiempo real de quién se encuentra en la sede.
* **Historial y Reportes**: Registro automático de fechas y horas de entrada/salida.
* **Seguridad**: Panel administrativo protegido con gestión de usuarios y cambio de contraseñas.
* **Interfaz Moderna**: Diseño limpio basado en Bootstrap 5 con avatares dinámicos.

## Tecnologías Utilizadas
* **Backend**: Python / Django 6.0
* **Base de Datos**: PostgreSQL
* **Frontend**: HTML5, CSS3 (Custom Dashboard), JavaScript (Previsualización de imágenes, Modales)
* **Estilos**: Bootstrap 5 & Bootstrap Icons
* **Seguridad**: Python-Decouple (Variables de entorno)

## Instalación (Para Desarrollo Local)

1. **Clonar el repositorio**:
   ```bash
   git clone [https://github.com/TU_USUARIO/TU_REPOSITORIO.git](https://github.com/TU_USUARIO/TU_REPOSITORIO.git)

2. **Crear entorno virtual**:

    ```bash
    python -m venv venv
    source venv/Scripts/activate  # En Windows

3. **Instalar dependencias**:
    ```bash
    pip install -r requirements.txt

4. **Configurar variables de entorno**:
    Crea un archivo `.env` basado en el archivo de ejemplo y configura tu base de datos PostgreSQL.

5. **Migrar base de datos y correr**:
    ```bash
    python manage.py migrate
    python manage.py runserver

