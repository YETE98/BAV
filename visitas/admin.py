from django.contrib import admin
from .models import Visitante, Visita, IpPermitida, Bitacora

@admin.register(Visitante)
class VisitanteAdmin(admin.ModelAdmin):
    # ELIMINAMOS 'entrada' de aquí porque ya no pertenece a este modelo
    list_display = ('cedula', 'nombre_completo', 'estatus') 
    search_fields = ('cedula', 'nombre_completo')

# REGISTRAMOS la nueva tabla de Visitas para ver el historial en el admin
@admin.register(Visita)
class VisitaAdmin(admin.ModelAdmin):
    list_display = ('visitante', 'entrada', 'salida', 'motivo')
    list_filter = ('entrada', 'salida')
    search_fields = ('visitante__nombre_completo', 'visitante__cedula')

@admin.register(IpPermitida)
class IpPermitidaAdmin(admin.ModelAdmin):
    list_display = ('direccion_ip', 'esta_permitida', 'equipo_nombre')

@admin.register(Bitacora)
class BitacoraAdmin(admin.ModelAdmin):
    list_display = ('accion', 'usuario', 'ip_origen', 'fecha_hora')
    list_filter = ('accion',)