# ==========================================
# IMPORTACIONES (Librerías y Vistas)
# ==========================================

# 1. Librerías estándar de Python (Las que ya vienen con el lenguaje)
import datetime
import json
from io import BytesIO

# 2. Herramientas del núcleo de Django (HTTP, Base de datos, Atajos)
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse
from django.utils import timezone
from django.db.models import Q, OuterRef, Subquery
from django.core.paginator import Paginator

# 3. Seguridad, Usuarios y Mensajes
from django.contrib import messages, auth
from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.admin.views.decorators import staff_member_required

# 4. Librerías de terceros (ReportLab para los PDFs)
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# 5. Importaciones Locales (Lo que tú creaste en tu app)
from .models import RegistroIntento ,Bitacora, Visitante, Visita, IpPermitida, IpActiva
from django.urls import reverse
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash

# ==========================================
# VISTAS DE AUTENTICACIÓN
# ==========================================

# Esta función verifica si es administrador
def es_administrador(user):
    return user.is_authenticated and user.is_superuser

def login_view(request):
    # --- REGLA BANCARIA (PARTE 1) ---
    # Si el navegador ya tiene una sesión iniciada, no dejamos que otro intente loguearse encima
    if request.user.is_authenticated:
        messages.warning(request, "Ya tienes una sesión activa en este dispositivo.")
        return redirect('dashboard')
        
    if request.method == 'POST':
        client_ip = get_client_ip(request)
        ip_actual = get_client_ip(request)
        username = request.POST.get('username')
        password = request.POST.get('password')

        # 1. VERIFICAR IP PERMITIDA (Tu lógica original)
        ip_obj = IpPermitida.objects.filter(direccion_ip=client_ip).first()
        if client_ip in BLOCKED_IPS or (ip_obj and not ip_obj.esta_permitida):
            Bitacora.objects.create(
                usuario=None, accion="Acceso denegado",
                detalles=f"IP bloqueada: {client_ip}", ip_origen=client_ip
            )
            messages.error(request, f'Acceso denegado desde la IP: {client_ip}')
            return render(request, "login.html", {'ip_blocked': True})

        # 2. VERIFICAR SI EL USUARIO ESTÁ BLOQUEADO POR INTENTOS
        user_obj = User.objects.filter(username=username).first()
        if user_obj:
            if not user_obj.is_active:
                messages.error(request, 'Tu cuenta ha sido bloqueada tras 3 intentos fallidos.')
                return render(request, "login.html")
            registro, _ = RegistroIntento.objects.get_or_create(usuario=user_obj)
        else:
            registro = None

        # 3. INTENTAR AUTENTICAR
        user = auth.authenticate(request, username=username, password=password)

        if user is not None:
            # --- LOGIN EXITOSO ---

            # --- REGLA BANCARIA (PARTE 2): SESIÓN ÚNICA POR DISPOSITIVO ---
            # Verificamos si la IP ya tiene una sesión activa con un navegador distinto al actual
            sesion_previa = IpActiva.objects.filter(
                ip_address=client_ip, 
                is_active=True
            ).exclude(user_agent=request.META.get('HTTP_USER_AGENT')).exists()
            
            if sesion_previa:
                # Si ya hay alguien en este PC, lo mandamos al aviso de seguridad
                return render(request, "warn.html", {'ip': ip_actual})

            # Resetear intentos si entró bien
            if registro:
                registro.intentos = 0
                registro.save()

            # Iniciamos la sesión de Django
            auth.login(request, user)

            # Marcamos en la base de datos que este dispositivo está OCUPADO
            IpActiva.objects.update_or_create(
                ip_address=client_ip,
                defaults={'is_active': True, 'user_agent': request.META.get('HTTP_USER_AGENT')}
            )

            # REQUISITO: Cambio de contraseña obligatorio primer ingreso
            if registro and registro.debe_cambiar_password:
                request.session['mostrar_modal_password'] = True
                messages.info(request, 'Bienvenido. Por seguridad, debes actualizar tu contraseña.')

            Bitacora.objects.create(
                usuario=user, accion="Inicio de sesión",
                detalles=f"El usuario {user.username} entró al sistema",
                ip_origen=client_ip
            )
            
            Bitacora.objects.create(
                    usuario=user, 
                    accion="Sesión Duplicada Rechazada",
                    detalles=f"El usuario {user.username} intentó abrir una segunda sesión desde un navegador diferente en la misma IP.",
                    ip_origen=client_ip
                )

            return redirect('dashboard')

        else:
            # --- FALLO DE LOGIN ---
            if user_obj:
                registro.intentos += 1
                registro.save()
                
                if registro.intentos >= 3:
                    user_obj.is_active = False # Bloqueo automático
                    user_obj.save()
                    detalles_fallo = f"USUARIO BLOQUEADO tras 3 intentos: {username}"
                    messages.error(request, 'Seguridad: Has superado el límite de intentos. Tu cuenta ha sido bloqueada.')
                else:
                    detalles_fallo = f"Intento fallido {registro.intentos}/3 para: {username}"
                    messages.error(request, f'Usuario o contraseña incorrectos. Intentos restantes: {3 - registro.intentos}')
            else:
                detalles_fallo = f"Credenciales inválidas (usuario inexistente): {username}"
                messages.error(request, 'Usuario o contraseña incorrectos')

            # Registrar fallo en bitácora
            Bitacora.objects.create(
                usuario=None, accion="Fallo de login",
                detalles=detalles_fallo, ip_origen=client_ip
            )

    return render(request, "login.html")

#logout.html
def logout_view(request):
    client_ip = get_client_ip(request)
    # IMPORTANTE: Liberamos el dispositivo para que otro pueda entrar
    IpActiva.objects.filter(ip_address=client_ip).update(is_active=False)
    auth.logout(request)
    
    if request.user.is_authenticated:
        # Registrar cierre de sesión
        Bitacora.objects.create(
            usuario=request.user,
            accion="Cierre de sesión",
            detalles=f"El usuario {request.user.username} cerró sesión",
            ip_origen=get_client_ip(request)
        )
        auth.logout(request)
    return render(request, "logout.html")

#warn.html
def warn_view(request):
    # Usamos TU función existente para obtener la IP
    ip_actual = get_client_ip(request)
    
    if request.user.is_authenticated:
        # Registrar en bitácora usando la IP obtenida
        Bitacora.objects.create(
            usuario=request.user,
            accion="Cierre de sesión / Advertencia",
            detalles=f"El usuario {request.user.username} salió del sistema. IP: {ip_actual}",
            ip_origen=ip_actual
        )
        auth.logout(request)
    
    # IMPORTANTE: Aquí mandamos la variable 'ip' al HTML
    return render(request, "warn.html", {'ip': ip_actual})

# ==========================================
# SECCIÓN: DASHBOARD ()
# ==========================================

#dashboard.html
@login_required(login_url='warn')
def dashboard_view(request):
    # Registrar acceso al dashboard
    Bitacora.objects.create(
        usuario=request.user,
        accion="Acceso al Dashboard",
        detalles=f"El usuario {request.user.username} accedió al dashboard principal",
        ip_origen=get_client_ip(request)
    )
    # Obtener las últimas 5 actividades
    actividades_recientes = Bitacora.objects.order_by('-fecha_hora')[:5]

    # Estadísticas para las tarjetas
    now = timezone.localtime(timezone.now())
    today = now.date()
    visitantes_hoy = Visita.objects.filter(entrada__date=today).count()
    visitantes_activos = Visita.objects.filter(salida__isnull=True).count()

    # Crecimiento mensual: comparar visitas del mes actual vs mes anterior
    now = timezone.localtime(timezone.now())
    first_day_current = now.replace(day=1)
    last_month_end = first_day_current - datetime.timedelta(days=1)
    first_day_last = last_month_end.replace(day=1)

    visitas_mes_actual = Visita.objects.filter(entrada__gte=first_day_current).count()
    visitas_mes_anterior = Visita.objects.filter(entrada__gte=first_day_last, entrada__lt=first_day_current).count()
    if visitas_mes_anterior > 2:
        crecimiento_pct = round((visitas_mes_actual - visitas_mes_anterior) / visitas_mes_anterior * 100, 1)
    else:
        crecimiento_pct = 100.0 if visitas_mes_actual > 0 else 0.0

    # Datos para gráfico: últimos 7 días
    labels = []
    data = []
    for i in range(6, -1, -1):
        day = today - datetime.timedelta(days=i)
        count = Visita.objects.filter(entrada__date=day).count()
        labels.append(day.strftime('%a'))
        data.append(count)


    # Calcular porcentajes para barras
    visitantes_pct = min(visitantes_hoy, 100)
    visitantes_activos_pct = min(visitantes_activos, 100)
    crecimiento_pct = min(crecimiento_pct, 100)  # limitar a 100% para la barra

    context = {
        'actividades_recientes': actividades_recientes,
        'visitantes_hoy': visitantes_hoy,
        'visitantes_activos': visitantes_activos,
        'crecimiento_pct': crecimiento_pct,
        'visitantes_pct': visitantes_pct,
        'visitantes_activos_pct': visitantes_activos_pct,
        'chart_labels_json': json.dumps(labels),
        'chart_data_json': json.dumps(data),
    }

    return render(request, "dashboard.html", context)

# ==========================================
# SECCIÓN: VISITANTES ()
# ==========================================

#visitor_create.html
@login_required(login_url='warn')
def visitor_create_view(request):
    # Registrar acceso al formulario (Solo cuando entran a ver la página)
    if request.method == 'GET':
        Bitacora.objects.create(
            usuario=request.user,
            accion="Acceso al formulario de visitantes",
            detalles=f"El usuario {request.user.username} accedió al formulario de visitantes",
            ip_origen=get_client_ip(request)
        )

    # Lógica para guardar cuando le dan al botón "Registrar"
    if request.method == 'POST':
        # 1. Capturar los datos
        cedula = request.POST.get('cedula')

        # --- AQUÍ PONES EL AVISO DE ERROR (Validación) ---
        hoy = timezone.now().date()
        if Visita.objects.filter(visitante__cedula=cedula, entrada__date=hoy).exists():
            from django.contrib import messages
            messages.error(request, f"Información duplicada: La cédula {cedula} ya registró un ingreso hoy.")
            # Devolvemos a la página sin guardar nada y pasando los datos actuales
            return render(request, 'visitor_create.html', {'datos': request.POST})
        # -------------------------------------------------

        nombre = request.POST.get('nombre_completo')
        estatus = request.POST.get('estatus')
        correo = request.POST.get('correo')
        telefono = request.POST.get('telefono')
        foto = request.FILES.get('foto')
        motivo = request.POST.get('motivo')
        a_quien = request.POST.get('a_quien_visita')
        observaciones = request.POST.get('observaciones')

        # 2. Crear o obtener el Visitante (datos personales)
        visitante, created = Visitante.objects.get_or_create(
            cedula=cedula,
            defaults={
                'nombre_completo': nombre,
                'estatus': estatus,
                'correo': correo,
                'telefono': telefono,
                'foto': foto,
            }
        )

        # Si no se creó (ya existía), actualizar datos si es necesario
        if not created:
            visitante.nombre_completo = nombre
            visitante.estatus = estatus
            visitante.correo = correo
            visitante.telefono = telefono
            if foto:
                visitante.foto = foto
            visitante.save()

        # 3. Crear la Visita (registro de la entrada)
        Visita.objects.create(
            visitante=visitante,
            motivo=motivo,
            a_quien_visita=a_quien,
            observaciones=observaciones,
            entrada=timezone.now()
        )


        Bitacora.objects.create(
            usuario=request.user,
            accion="Registro de Visitante",
            detalles=f"Se registró ingreso de {nombre} (C.I. {cedula})",
            ip_origen=get_client_ip(request)
        )

        return redirect('visitor_records')
    # Si no es POST, simplemente renderiza el formulario
    return render(request, 'visitor_create.html')

#visitor_records.html
@login_required(login_url='warn')
def visitor_records_view(request):
    """
    Vista para ver únicamente a las personas que están dentro de la institución
    (Visitas que no tienen registrada una fecha/hora de salida)
    """
    # 1. Registrar el acceso en la Bitácora
    Bitacora.objects.create(
        usuario=request.user,
        accion="Consulta de Personal en Sede",
        detalles=f"El usuario {request.user.username} consultó la lista de visitas activas",
        ip_origen=get_client_ip(request)
    )

    # 2. Obtener las visitas activas (donde salida es NULL)
    # Usamos select_related para traer los datos del visitante en una sola consulta (más rápido)
    visitas_activas = Visita.objects.filter(
        salida__isnull=True
    ).select_related('visitante').order_by('-entrada')

    # 3. Renderizar el template que ya creamos
    context = {
        'visitas': visitas_activas,
    }
    
    return render(request, 'visitor_records.html', context)

def registrar_salida_desde_records(request, visita_id):
    """
    Función rápida para marcar la salida desde la tabla de Visitas Activas
    """
    visita = get_object_or_404(Visita, pk=visita_id)
    nombre = visita.visitante.nombre_completo
    
    # Marcar la salida con la hora actual
    visita.salida = timezone.now()
    visita.save()
    
    # Registrar en bitácora
    Bitacora.objects.create(
        usuario=request.user,
        accion="Egreso de Visitante",
        detalles=f"Se registró la salida de {nombre} desde el panel de control",
        ip_origen=get_client_ip(request)
    )
    
    messages.success(request, f"Salida confirmada para {nombre}.")
    
    # Redirigir de vuelta a la misma lista de activos
    return redirect('visitor_records')

#visitor_edit.html
@login_required(login_url='warn')
def visitor_edit_view(request, pk):
    # 1. Buscamos al visitante por su ID
    visitante = get_object_or_404(Visitante, pk=pk)

    if request.method == 'GET':
        # Registrar acceso al formulario de edición
        Bitacora.objects.create(
            usuario=request.user,
            accion="Acceso al Formulario de Edición de Visitante",
            detalles=f"El usuario {request.user.username} accedió al formulario de edición del visitante {visitante.nombre_completo} ({visitante.cedula})",
            ip_origen=get_client_ip(request)
        )

    if request.method == 'POST':
        # --- PARTE A: Actualizar datos personales ---
        visitante.nombre_completo = request.POST.get('nombre_completo')
        visitante.cedula = request.POST.get('cedula')
        visitante.telefono = request.POST.get('telefono')

        # Si subió una foto nueva, la guardamos
        if 'foto' in request.FILES:
            visitante.foto = request.FILES['foto']

        visitante.save() # Guardamos los cambios en la base de datos

        # --- PARTE B: Registrar la nueva visita ---
        Visita.objects.create(
            visitante=visitante,
            motivo=request.POST.get('motivo'),
            a_quien_visita=request.POST.get('a_quien_visita'),
            observaciones=request.POST.get('observaciones'),
            entrada=timezone.now() # Fecha y hora actual
        )

        # Registrar la edición y nueva visita
        Bitacora.objects.create(
            usuario=request.user,
            accion="Edición de Visitante y Nueva Visita",
            detalles=f"Se editó al visitante {visitante.nombre_completo} ({visitante.cedula}) y se registró nueva visita",
            ip_origen=get_client_ip(request)
        )

        return redirect('visitor_records') # Volvemos a la biblioteca al terminar

    # 2. Obtenemos las últimas 5 visitas para el historial lateral
    historial = Visita.objects.filter(visitante=visitante).order_by('-entrada')[:5]

    return render(request, 'visitor_edit.html', {
        'visitante': visitante,
        'historial': historial
    })

# Nueva función para registrar la salida rápido
def registrar_salida(request, pk):  # Cambiado a 'pk' para que coincida con la URL
    # Buscamos la visita usando el pk que viene de la URL
    visita = get_object_or_404(Visita, pk=pk) 
    
    visita.salida = timezone.now()
    visita.save()
    
    # Redirigir al detalle del visitante (ajusta el nombre del parámetro si es necesario)
    return redirect('visitor_edit', pk=visita.visitante.id)

#visitor_delete.html
@login_required(login_url='warn')
def visitor_delete_view(request, pk):
    visitante = get_object_or_404(Visitante, pk=pk)
    nombre = visitante.nombre_completo
    
    # 1. Registrar la eliminación en la bitácora antes de borrarlo
    Bitacora.objects.create(
        usuario=request.user,
        accion="Eliminación de registro",
        detalles=f"Se eliminó permanentemente a {nombre} del directorio.",
        ip_origen=get_client_ip(request)
    )
    
    # 2. Eliminar de la base de datos
    visitante.delete()
    
    # 3. Enviar aviso de éxito y volver al directorio
    from django.contrib import messages
    messages.success(request, f"El registro de {nombre} ha sido eliminado correctamente.")
    return redirect('visitor_log') # Asegúrate que 'directory' sea el nombre de tu url

#visitor_log.html
@login_required(login_url='warn')
def visitor_log_view(request):
    # 1. Definimos la subconsulta para obtener la fecha y hora de la última entrada de la tabla Visita
    ultima_entrada_qs = Visita.objects.filter(
        visitante=OuterRef('pk')
    ).order_by('-entrada').values('entrada')[:1]

    # 2. Definimos la subconsulta para obtener la fecha y hora de la última salida de la tabla Visita
    ultima_salida_qs = Visita.objects.filter(
        visitante=OuterRef('pk'),
        salida__isnull=False
    ).order_by('-salida').values('salida')[:1]

    # 3. Obtenemos los visitantes y les "anotamos" la fecha de su última entrada y salida
    # para poder ordenar por ella sin que de error.
    visitantes = Visitante.objects.annotate(
        ultima_entrada_fecha=Subquery(ultima_entrada_qs),
        ultima_salida_fecha=Subquery(ultima_salida_qs)
    ).order_by('-ultima_entrada_fecha')

    # 4. Registrar acceso al directorio (Tu lógica de bitácora se mantiene igual)
    Bitacora.objects.create(
        usuario=request.user,
        accion="Acceso al Directorio de Visitantes",
        detalles=f"El usuario {request.user.username} accedió al directorio de visitantes",
        ip_origen=get_client_ip(request)
    )

    context = {
        'visitantes': visitantes
    }
    return render(request, 'visitor_log.html', context)

#visitor_reports.html
@login_required(login_url='warn')
def visitor_reports_view(request):
    # Registrar acceso a reportes
    Bitacora.objects.create(
        usuario=request.user,
        accion="Acceso a Reportes de Visitas",
        detalles=f"El usuario {request.user.username} accedió a los reportes de visitas",
        ip_origen=get_client_ip(request)
    )

    # Traemos todas las visitas
    queryset = Visita.objects.all().select_related('visitante').order_by('-entrada')

    # Filtros de fecha
    fecha_inicio = request.GET.get('fecha_inicio')
    fecha_fin = request.GET.get('fecha_fin')

    if fecha_inicio:
        queryset = queryset.filter(entrada__date__gte=fecha_inicio)
    if fecha_fin:
        queryset = queryset.filter(entrada__date__lte=fecha_fin)

    # Filtro de búsqueda por nombre o cédula
    search = request.GET.get('search')
    if search:
        queryset = queryset.filter(
            Q(visitante__nombre_completo__icontains=search) | Q(visitante__cedula__icontains=search)
        )

    # Paginación: 10 registros por página
    paginator = Paginator(queryset, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'visitor_reports.html', {
        'visitas': page_obj
    })

# ==========================================
# SECCIÓN: configuracion ()
# ==========================================

# settings.py
ALLOWED_HOSTS = ['192.168.1.2', 'localhost', '127.0.0.1'] 
# O para pruebas rápidas:
ALLOWED_HOSTS = ['*']
# IPs bloqueadas para demostración
BLOCKED_IPS = ['192.168.1.8', '10.0.0.1']

# Agrega esto a tus views.py



def get_client_ip(request):
    """
    Obtener la IP real del cliente considerando proxies
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


#settings_log.html
@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def settings_log_view (request):
    # Lógica para la vista de configuración administrativa
    Bitacora.objects.create(
        usuario=request.user,
        accion="Acceso a Configuración Administrativa",
        detalles=f"El usuario {request.user.username} accedió a la configuración administrativa",
        ip_origen=get_client_ip(request)
    )
    # Obtener todos los registros de la bitácora ordenados por fecha descendente
    bitacora_completa = Bitacora.objects.all().order_by('-fecha_hora')

    # Paginación: 100 registros por página
    paginator = Paginator(bitacora_completa, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Obtener las IPs para el control de acceso
    ips = IpPermitida.objects.all().order_by('-id')

    # Obtener las IPs activas
    ips_activas = IpActiva.objects.filter(is_active=True).order_by('-last_seen')

    context = {
        'bitacora_completa': page_obj,
        'ips': ips,
        'ips_activas': ips_activas,
    }
    return render(request, 'settings_log.html', context)


@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def manage_ips_view(request):
    if request.method == 'POST':
        ip = request.POST.get('ip')
        motivo = request.POST.get('motivo') # Podemos guardar esto en equipo_nombre o notas

        # Guardamos en la base de datos
        IpPermitida.objects.update_or_create(
            direccion_ip=ip,
            defaults={
                'esta_permitida': False, # Si la bloqueas manualmente, nace como False
                'equipo_nombre': motivo if motivo else "Bloqueo Manual",
                'sistema_operativo': "N/A",
                'navegador': "N/A"
            }
        )

        # Registrar en bitácora
        Bitacora.objects.create(
            usuario=request.user,
            accion="Bloqueo Manual de IP",
            detalles=f"Se bloqueó manualmente la IP: {ip} - Motivo: {motivo}",
            ip_origen=get_client_ip(request)
        )

        messages.warning(request, f"Se ha actualizado el estado de la IP: {ip}")
        return redirect('settings_log') # Ajusta al nombre de tu URL de configuración

    # Obtenemos las IPs para la tabla
    ips = IpPermitida.objects.all().order_by('-id')
    return ips

@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def toggle_ip_status(request, ip_id):
    ip_obj = get_object_or_404(IpPermitida, id=ip_id)
    ip_obj.esta_permitida = not ip_obj.esta_permitida
    ip_obj.save()

    estado = "Permitida" if ip_obj.esta_permitida else "Bloqueada"

    # Registrar en bitácora
    Bitacora.objects.create(
        usuario=request.user,
        accion=f"Cambio de Estado de IP - {estado}",
        detalles=f"Se cambió el estado de la IP {ip_obj.direccion_ip} a {estado}",
        ip_origen=get_client_ip(request)
    )

    messages.info(request, f"La IP {ip_obj.direccion_ip} ahora está {estado}.")
    return redirect(request.META.get('HTTP_REFERER', 'settings_log'))

#edip_ip.html
@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def edit_ip_view(request, ip_id):
    ip_obj = get_object_or_404(IpPermitida, id=ip_id)

    if request.method == 'POST':
        ip_obj.equipo_nombre = request.POST.get('equipo_nombre', '')
        ip_obj.sistema_operativo = request.POST.get('sistema_operativo', '')
        ip_obj.navegador = request.POST.get('navegador', '')
        estado = request.POST.get('estado')
        if estado == 'permitida':
            ip_obj.esta_permitida = True
        elif estado == 'bloqueada':
            ip_obj.esta_permitida = False
        ip_obj.save()

        Bitacora.objects.create(
            usuario=request.user,
            accion="Edición de IP",
            detalles=f"Se editó la información de la IP: {ip_obj.direccion_ip}",
            ip_origen=get_client_ip(request)
        )

        messages.success(request, f"Información de la IP {ip_obj.direccion_ip} actualizada correctamente.")
        return redirect('settings_log')

    context = {
        'ip': ip_obj,
    }
    return render(request, 'edit_ip.html', context)

@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def delete_ip_view(request, ip_id):
    ip_obj = get_object_or_404(IpPermitida, id=ip_id)
    ip_address = ip_obj.direccion_ip

    ip_obj.delete()

    Bitacora.objects.create(
        usuario=request.user,
        accion="Eliminación de IP",
        detalles=f"Se eliminó la IP: {ip_address} del control de acceso",
        ip_origen=get_client_ip(request)
    )

    messages.success(request, f"La IP {ip_address} ha sido eliminada del control de acceso.")
    return redirect('settings_log')

@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def export_log_pdf_view(request):
    # Obtener todos los registros de la bitácora
    bitacora_completa = Bitacora.objects.all().order_by('-fecha_hora')

    # Crear buffer para el PDF
    buffer = BytesIO()
    # Usar A4 landscape para más espacio horizontal
    from reportlab.lib.pagesizes import A4
    doc = SimpleDocTemplate(buffer, pagesize=(A4[1], A4[0]))  # Landscape
    elements = []

    # Estilos
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    title_style.alignment = 1  # Centrado

    # Título
    title = Paragraph("Bitácora Completa - Sistema BAV", title_style)
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Datos para la tabla
    data = [['Fecha/Hora', 'Usuario', 'Acción', 'Detalles', 'IP Origen']]
    for log in bitacora_completa:
        usuario = log.usuario.username if log.usuario else 'Sistema'
        # Truncar textos largos para que quepan mejor
        accion = log.accion[:50] + '...' if len(log.accion) > 50 else log.accion
        detalles = log.detalles[:100] + '...' if len(log.detalles) > 100 else log.detalles
        data.append([
            log.fecha_hora.strftime('%d/%m/%Y %H:%M:%S'),
            usuario,
            accion,
            detalles,
            log.ip_origen
        ])

    # Crear tabla con anchos de columna específicos
    col_widths = [80, 60, 80, 200, 80]  # Anchos en puntos
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.green),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # Cambiar a LEFT para mejor legibilidad
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),  # Reducir tamaño de fuente
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),  # Tamaño de fuente más pequeño para datos
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Alineación vertical al medio
        ('LEFTPADDING', (0, 0), (-1, -1), 3),  # Padding izquierdo
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),  # Padding derecho
        ('TOPPADDING', (0, 0), (-1, -1), 2),  # Padding superior
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),  # Padding inferior
    ]))

    elements.append(table)

    # Construir PDF
    doc.build(elements)

    # Preparar respuesta
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="bitacora_completa.pdf"'

    # Registrar en bitácora
    Bitacora.objects.create(
        usuario=request.user,
        accion="Exportación de Bitácora PDF",
        detalles=f"El usuario {request.user.username} exportó la bitácora completa en PDF",
        ip_origen=get_client_ip(request)
    )

    return response

@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def export_log_txt_view(request):
    # Obtener todos los registros de la bitácora
    bitacora_completa = Bitacora.objects.all().order_by('-fecha_hora')

    # Crear contenido del archivo TXT
    txt_content = "BITÁCORA COMPLETA - SISTEMA BAV\n"
    txt_content += "=" * 50 + "\n\n"

    for log in bitacora_completa:
        usuario = log.usuario.username if log.usuario else 'Sistema'
        txt_content += f"Fecha/Hora: {log.fecha_hora.strftime('%d/%m/%Y %H:%M:%S')}\n"
        txt_content += f"Usuario: {usuario}\n"
        txt_content += f"Acción: {log.accion}\n"
        txt_content += f"Detalles: {log.detalles}\n"
        txt_content += f"IP Origen: {log.ip_origen}\n"
        txt_content += "-" * 50 + "\n"

    # Preparar respuesta
    response = HttpResponse(txt_content, content_type='text/plain; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="bitacora_completa.txt"'

    # Registrar en bitácora
    Bitacora.objects.create(
        usuario=request.user,
        accion="Exportación de Bitácora TXT",
        detalles=f"El usuario {request.user.username} exportó la bitácora completa en TXT",
        ip_origen=get_client_ip(request)
    )

    return response

@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def database_backup_view(request):
    """Vista para crear respaldo completo de TODA la base de datos"""
    import os
    import json
    from django.core import serializers
    from django.conf import settings
    from django.apps import apps
    from datetime import datetime

    # Crear directorio de respaldos si no existe
    backup_dir = os.path.join(settings.BASE_DIR, 'backups')
    os.makedirs(backup_dir, exist_ok=True)

    # Nombre del archivo con timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'backup_completo_{timestamp}.json'
    filepath = os.path.join(backup_dir, filename)

    try:
        # Obtener TODOS los modelos de TODAS las aplicaciones instaladas
        data = []
        total_models = 0
        total_records = 0

        # Iterar sobre todas las aplicaciones instaladas
        for app_config in apps.get_app_configs():
            app_label = app_config.label

            # Iterar sobre todos los modelos de cada aplicación
            for model in app_config.get_models():
                model_name = f"{app_label}.{model.__name__}"
                try:
                    queryset = model.objects.all()
                    record_count = queryset.count()
                    total_models += 1
                    total_records += record_count

                    if record_count > 0:
                        # Serializar todos los registros del modelo
                        serialized_data = serializers.serialize('json', queryset)
                        if serialized_data:
                            # Si es una lista de objetos, extenderla
                            if isinstance(serialized_data, list):
                                data.extend(serialized_data)
                            else:
                                # Si es un string JSON, parsearlo y extenderlo
                                try:
                                    parsed_data = json.loads(serialized_data)
                                    if isinstance(parsed_data, list):
                                        data.extend(parsed_data)
                                    else:
                                        data.append(parsed_data)
                                except:
                                    # Si no se puede parsear, intentar agregarlo como string
                                    data.append(serialized_data)

                except Exception as e:
                    # Log del error pero continuar con otros modelos
                    print(f"Error backing up model {model_name}: {str(e)}")
                    continue

        # Guardar el respaldo completo en archivo JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Preparar respuesta para descarga
        with open(filepath, 'r', encoding='utf-8') as f:
            response = HttpResponse(f.read(), content_type='application/json')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'

        # Registrar en bitácora con detalles completos
        Bitacora.objects.create(
            usuario=request.user,
            accion="Respaldo Completo de Base de Datos",
            detalles=f"Se creó respaldo completo de TODA la base de datos: {filename}. Modelos: {total_models}, Registros: {total_records}",
            ip_origen=get_client_ip(request)
        )

        # Limpiar archivo temporal después de la descarga
        import threading
        def cleanup_file():
            import time
            time.sleep(5)  # Esperar 5 segundos para que se complete la descarga
            try:
                os.remove(filepath)
            except:
                pass

        threading.Thread(target=cleanup_file, daemon=True).start()

        return response

    except Exception as e:
        messages.error(request, f"Error al crear el respaldo completo: {str(e)}")
        return redirect('settings_log')

@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def database_restore_view(request):
    """Vista para restaurar la base de datos desde archivo"""
    if request.method == 'POST' and request.FILES.get('backup_file'):
        import json
        from django.core import serializers

        backup_file = request.FILES['backup_file']

        try:
            # Leer el contenido del archivo
            file_content = backup_file.read().decode('utf-8')
            data = json.loads(file_content)

            # Deserializar y guardar los datos
            for obj_data in data:
                try:
                    # Crear el objeto desde los datos serializados
                    obj = serializers.deserialize('json', json.dumps([obj_data])).next()
                    obj.save()
                except Exception as e:
                    # Si hay conflicto (objeto ya existe), intentar actualizar
                    try:
                        # Para objetos que ya existen, intentar actualizar campos
                        existing_obj = obj.object.__class__.objects.filter(pk=obj.object.pk).first()
                        if existing_obj:
                            # Actualizar campos del objeto existente
                            for field in obj.object._meta.fields:
                                if not field.primary_key:
                                    setattr(existing_obj, field.name, getattr(obj.object, field.name))
                            existing_obj.save()
                    except:
                        # Si no se puede actualizar, continuar
                        continue

            # Registrar en bitácora
            Bitacora.objects.create(
                usuario=request.user,
                accion="Restauración de Base de Datos",
                detalles=f"Se restauró la base de datos desde archivo: {backup_file.name}",
                ip_origen=get_client_ip(request)
            )

            messages.success(request, "Base de datos restaurada exitosamente.")
            return redirect('settings_log')

        except Exception as e:
            messages.error(request, f"Error al restaurar la base de datos: {str(e)}")
            return redirect('settings_log')

    # Si no es POST o no hay archivo, redirigir
    return redirect('settings_log')

# ==========================================
# SECCIÓN: GESTIÓN DE USUARIOS (settings_users.html)
# ==========================================

#settings_users.html
@login_required(login_url='warn')
@user_passes_test(es_administrador, login_url='warn')
def settings_users_view(request):
    # 1. Obtener datos (excluimos al admin actual para seguridad)
    usuarios = User.objects.exclude(id=request.user.id).order_by('-date_joined')
    groups = Group.objects.all()

    if request.method == 'POST':
        user_id = request.POST.get('user_id') # Viene del campo hidden al editar
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        is_staff = 'is_staff' in request.POST
        is_superuser = 'is_superuser' in request.POST
        groups_ids = request.POST.getlist('groups')

        if user_id:  # --- MODO EDICIÓN ---
            target_user = get_object_or_404(User, id=user_id)
            target_user.username = username
            target_user.email = email
            
            if password: # Solo cambia clave si se escribió algo
                target_user.set_password(password)
            
            target_user.is_staff = is_staff
            target_user.is_superuser = is_superuser
            target_user.groups.set(groups_ids)
            target_user.save()
            
            messages.success(request, f"Usuario {username} actualizado.")

        else:  # --- MODO CREACIÓN ---
            if User.objects.filter(username=username).exists():
                messages.error(request, "El nombre de usuario ya existe.")
            else:
                nuevo_user = User.objects.create_user(
                    username=username, email=email, password=password
                )
                nuevo_user.is_staff = is_staff
                nuevo_user.is_superuser = is_superuser
                nuevo_user.groups.set(groups_ids)
                nuevo_user.save()
                
                # Si usas el modelo 'aaa' para preguntas de seguridad:
                # aaa.objects.create(user=nuevo_user, ...)
                
                messages.success(request, f"Usuario {username} creado con éxito.")

        return redirect('settings_users')

    return render(request, 'settings_users.html', {
        'usuarios': usuarios, 
        'groups': groups
    })

@login_required
@user_passes_test(es_administrador, login_url='warn')
def toggle_user_status(request, pk): # Cambiamos user_id por pk para que coincida con la URL
    target_user = get_object_or_404(User, pk=pk)
    target_user.is_active = not target_user.is_active
    target_user.save()
    
    status = "activado" if target_user.is_active else "bloqueado"
    messages.warning(request, f"Usuario {target_user.username} {status}.")
    return redirect('settings_users')

@login_required
@user_passes_test(es_administrador, login_url='warn')
def delete_user(request, pk):  # Cambié 'user_id' por 'pk'
    target_user = get_object_or_404(User, pk=pk)  # Cambié 'id=user_id' por 'pk=pk'
    nombre = target_user.username
    target_user.delete()
    messages.success(request, f"Usuario {nombre} eliminado exitosamente.")  # Cambié 'error' por 'success' para un mensaje más positivo
    return redirect('settings_users')
    
@login_required
@user_passes_test(es_administrador, login_url='warn')
def settings_users(request):
    usuarios = User.objects.all()
    selected_user = request.user  # Por defecto, el usuario logueado
    if 'user' in request.GET:
        selected_user = get_object_or_404(User, pk=request.GET['user'])
    return render(request, 'settings_users.html', {'usuarios': usuarios, 'selected_user': selected_user})

@login_required
@user_passes_test(es_administrador, login_url='warn')
def edit_user_view(request, pk):
    target_user = get_object_or_404(User, pk=pk)
    target_user.is_active = 'is_active' in request.POST  # True si está marcado
    target_user.is_staff = 'is_staff' in request.POST
    target_user.is_superuser = 'is_superuser' in request.POST
    
    if request.method == 'POST':
        target_user.first_name = request.POST.get('first_name')
        target_user.last_name = request.POST.get('last_name')
        target_user.email = request.POST.get('email')
        target_user.save()  # Agrega esto para guardar los cambios
        messages.success(request, f"Usuario {target_user.username} actualizado exitosamente.")  # Opcional, para mostrar mensaje

        
    # Para GET: Renderizar el template con el usuario
    return render(request, 'settings_edit.html', {  # Cambié a 'settings_users.html' si es el template correcto
        'target_user': target_user,
        'usuarios': User.objects.all()  # Agregué para que funcione el template
    })

    
@login_required
@user_passes_test(es_administrador, login_url='warn')
def change_password_view(request, pk):
    if request.method == 'POST':
        target_user = get_object_or_404(User, pk=pk)
        pass1 = request.POST.get('new_password1')
        pass2 = request.POST.get('new_password2')

        if pass1 and pass1 == pass2:
            target_user.set_password(pass1)
            target_user.save()
            messages.success(request, f"¡Contraseña de {target_user.username} actualizada con éxito!")
        else:
            messages.error(request, "Las contraseñas no coinciden o están vacías.")
            
    # Siempre redirigimos a la página de edición, eliminando la necesidad del template inexistente
    return redirect('edit_user', pk=pk)


def change_password(request, pk):
    if request.method == 'POST':
        user = get_object_or_404(User, pk=pk)
        pass1 = request.POST.get('new_password1')
        pass2 = request.POST.get('new_password2')

        if pass1 and pass1 == pass2:
            # 1. Cambiamos la clave físicamente
            user.set_password(pass1)
            user.save()

            # 2. Mantenemos la sesión activa (si no, Django te saca al login)
            update_session_auth_hash(request, user)

            # 3. ACTUALIZAMOS EL MODELO (Para que el modal no salga más)
            registro, _ = RegistroIntento.objects.get_or_create(usuario=user)
            registro.debe_cambiar_password = False
            registro.save()

            # 4. Borramos la señal de la sesión
            if 'mostrar_modal_password' in request.session:
                del request.session['mostrar_modal_password']

            messages.success(request, "Contraseña actualizada con éxito.")
            return redirect('dashboard')
        else:
            messages.error(request, "Las contraseñas no coinciden o están vacías.")
            return redirect('dashboard')
            
    return redirect('dashboard')

@login_required
@user_passes_test(es_administrador, login_url='warn')
def create_user_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        is_active = 'is_active' in request.POST
        is_staff = 'is_staff' in request.POST
        is_superuser = 'is_superuser' in request.POST

        if password1 != password2:
            messages.error(request, "Las contraseñas no coinciden.")
            return redirect('create_user')

        if User.objects.filter(username=username).exists():
            messages.error(request, "El nombre de usuario ya existe.")
            return redirect('create_user')

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1,
            first_name=first_name,
            last_name=last_name,
            is_active=is_active,
            is_staff=is_staff,
            is_superuser=is_superuser
        )
        messages.success(request, f"Usuario {username} creado exitosamente.")
        return redirect('settings_users')

    return render(request, 'settings_new.html', {'usuarios': User.objects.all()})

@login_required
@user_passes_test(es_administrador, login_url='warn')
def create_group_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        permission_ids = request.POST.getlist('permissions')

        if Group.objects.filter(name=name).exists():
            messages.error(request, "El nombre del grupo ya existe.")
            return redirect('create_group')

        group = Group.objects.create(name=name)
        permissions = Permission.objects.filter(id__in=permission_ids)
        group.permissions.set(permissions)
        messages.success(request, f"Grupo '{name}' creado exitosamente.")
        return redirect('settings_users')

    permissions = Permission.objects.all().select_related('content_type')
    grupos = Group.objects.all()
    return render(request, 'settings_groups.html', {'permissions': permissions, 'grupos': grupos})

@login_required
@user_passes_test(es_administrador, login_url='warn')
def settings_users_view(request):
    usuarios = User.objects.all()
    grupos = Group.objects.all()  # Agrega esto si no está
    fecha_actual = timezone.now()
    return render(request, 'settings_users.html', {
        'usuarios': usuarios,
        'grupos': grupos,
        'fecha_actual': fecha_actual,
    })

@login_required
@user_passes_test(es_administrador, login_url='warn')
def edit_group_view(request, pk):
    group = get_object_or_404(Group, pk=pk)
    if request.method == 'POST':
        name = request.POST.get('name')
        permission_ids = request.POST.getlist('permissions')
        group.name = name
        group.save()
        group.permissions.set(Permission.objects.filter(id__in=permission_ids))
        messages.success(request, f"Grupo '{name}' actualizado.")
        return redirect('settings_users')
    permissions = Permission.objects.all().select_related('content_type')
    return render(request, 'edit_group.html', {'group': group, 'permissions': permissions})

@login_required
@user_passes_test(es_administrador, login_url='warn')
def delete_group_view(request, pk):
    group = get_object_or_404(Group, pk=pk)
    if request.method == 'POST':
        group.delete()
        messages.success(request, f"Grupo '{group.name}' eliminado.")
        return redirect('settings_users')
    return redirect('settings_users')

@login_required
@user_passes_test(es_administrador, login_url='warn')
def edit_group_view(request, pk):
    group = get_object_or_404(Group, pk=pk)
    if request.method == 'POST':
        name = request.POST.get('name')
        permission_ids = request.POST.getlist('permissions')
        user_ids = request.POST.getlist('users')
        
        group.name = name
        group.save()
        group.permissions.set(Permission.objects.filter(id__in=permission_ids))
        group.user_set.set(User.objects.filter(id__in=user_ids))
        messages.success(request, f"Grupo '{name}' actualizado.")
        return redirect('settings_users')
    
    permissions = Permission.objects.all().select_related('content_type')
    users = User.objects.all()
    return render(request, 'edit_group.html', {'group': group, 'permissions': permissions, 'users': users})