# ==========================================
# IMPORTACIONES
# ==========================================
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

# ==========================================
# MODELOS DE USUARIO Y SEGURIDAD
# ==========================================

class IpPermitida(models.Model):
    direccion_ip = models.GenericIPAddressField(unique=True)
    esta_permitida = models.BooleanField(default=True)
    equipo_nombre = models.CharField(max_length=100)
    sistema_operativo = models.CharField(max_length=100)
    navegador = models.CharField(max_length=100)
    
class IpActiva(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    user_agent = models.TextField(blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.ip_address} - {self.last_seen}"

class Bitacora(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    accion = models.CharField(max_length=100)
    detalles = models.TextField()
    ip_origen = models.GenericIPAddressField()
    fecha_hora = models.DateTimeField(auto_now_add=True)

# ==========================================
# MODELOS DE NEGOCIO (BIBLIOTECA)
# ==========================================

class Visitante(models.Model):
    ESTATUS_CHOICES = [
        ('natural', 'Persona Natural'),
        ('empleado', 'Empleado'),
        ('externo', 'Empresa Externa'),
        ('denegado', 'Acceso Denegado'),
    ]
    cedula = models.CharField(max_length=20, unique=True)
    nombre_completo = models.CharField(max_length=200)
    foto = models.ImageField(upload_to='visitantes/', null=True, blank=True)
    correo = models.EmailField(blank=True)
    telefono = models.CharField(max_length=20, blank=True)
    estatus = models.CharField(max_length=20, choices=ESTATUS_CHOICES, default='natural')

    def __str__(self):
        return f"{self.nombre_completo} ({self.cedula})"
    
class Visita(models.Model):
    visitante = models.ForeignKey(Visitante, on_delete=models.CASCADE, related_name='historial')
    motivo = models.CharField(max_length=255)
    a_quien_visita = models.CharField(max_length=200)
    entrada = models.DateTimeField(auto_now_add=True)
    salida = models.DateTimeField(null=True, blank=True)
    observaciones = models.TextField(blank=True)

    def __str__(self):
        return f"Visita de {self.visitante.nombre_completo} - {self.entrada.strftime('%d/%m/%Y')}"

# ==========================================
# SEÑALES (LOGGING AUTOMÁTICO)
# ==========================================
@receiver(post_save, sender=Visitante)
def registrar_visitante_save(sender, instance, created, **kwargs):
    try:
        if created:
            accion = "Creación de Visitante"
            detalles = f"Se creó visitante: {instance.nombre_completo} ({instance.cedula})"
        else:
            accion = "Actualización de Visitante"
            detalles = f"Se actualizó visitante: {instance.nombre_completo} ({instance.cedula})"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen='0.0.0.0'
        )
    except Exception:
        # Evitar que errores en logging rompan la operación principal
        pass


@receiver(post_delete, sender=Visitante)
def registrar_visitante_delete(sender, instance, **kwargs):
    try:
        accion = "Eliminación de Visitante"
        detalles = f"Se eliminó visitante: {instance.nombre_completo} ({instance.cedula})"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen='0.0.0.0'
        )
    except Exception:
        pass


@receiver(post_save, sender=Visita)
def registrar_visita_save(sender, instance, created, **kwargs):
    try:
        if created:
            accion = "Creación de Visita"
            detalles = f"Se registró entrada de {instance.visitante.nombre_completo} ({instance.visitante.cedula}) - Motivo: {instance.motivo}"
        else:
            accion = "Actualización de Visita"
            detalles = f"Se actualizó visita de {instance.visitante.nombre_completo} ({instance.visitante.cedula})"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen='0.0.0.0'
        )
    except Exception:
        pass


@receiver(post_save, sender=Visita)
def registrar_visita_salida(sender, instance, **kwargs):
    try:
        if instance.salida and not kwargs.get('created', False):
            accion = "Registro de Salida"
            detalles = f"Se registró salida de {instance.visitante.nombre_completo} ({instance.visitante.cedula})"
            Bitacora.objects.create(
                usuario=None,
                accion=accion,
                detalles=detalles,
                ip_origen='0.0.0.0'
            )
    except Exception:
        pass


@receiver(post_delete, sender=Visita)
def registrar_visita_delete(sender, instance, **kwargs):
    try:
        accion = "Eliminación de Visita"
        detalles = f"Se eliminó visita de {instance.visitante.nombre_completo} ({instance.visitante.cedula})"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen='0.0.0.0'
        )
    except Exception:
        pass


@receiver(post_save, sender=IpPermitida)
def registrar_ip_permitida_save(sender, instance, created, **kwargs):
    try:
        if created:
            accion = "Creación de IP Permitida"
            detalles = f"Se agregó IP permitida: {instance.direccion_ip} - {instance.equipo_nombre}"
        else:
            accion = "Actualización de IP Permitida"
            detalles = f"Se actualizó IP permitida: {instance.direccion_ip} - {instance.equipo_nombre}"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen='0.0.0.0'
        )
    except Exception:
        pass


@receiver(post_delete, sender=IpPermitida)
def registrar_ip_permitida_delete(sender, instance, **kwargs):
    try:
        accion = "Eliminación de IP Permitida"
        detalles = f"Se eliminó IP permitida: {instance.direccion_ip} - {instance.equipo_nombre}"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen='0.0.0.0'
        )
    except Exception:
        pass


@receiver(post_save, sender=IpActiva)
def registrar_ip_activa_save(sender, instance, created, **kwargs):
    try:
        if created:
            accion = "Nueva IP Activa Detectada"
            detalles = f"Se detectó nueva IP activa: {instance.ip_address} - User-Agent: {instance.user_agent[:100]}..."
        else:
            accion = "Actualización de IP Activa"
            detalles = f"Se actualizó IP activa: {instance.ip_address}"
        Bitacora.objects.create(
            usuario=None,
            accion=accion,
            detalles=detalles,
            ip_origen=instance.ip_address
        )
    except Exception:
        pass
