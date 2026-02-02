from .models import IpActiva
from .views import get_client_ip
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

class ActiveIPMiddleware(MiddlewareMixin):
    """
    Middleware para rastrear IPs activas en el sistema
    """
    def process_request(self, request):
        # Obtener la IP del cliente
        client_ip = get_client_ip(request)

        # Obtener el User-Agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Actualizar o crear registro de IP activa
        IpActiva.objects.update_or_create(
            ip_address=client_ip,
            defaults={
                'user_agent': user_agent[:500],  # Limitar longitud
                'last_seen': timezone.now(),
                'is_active': True
            }
        )

        # Limpiar IPs inactivas (que no se han visto en las últimas 24 horas)
        cutoff_time = timezone.now() - timezone.timedelta(hours=24)
        IpActiva.objects.filter(last_seen__lt=cutoff_time).update(is_active=False)

        return None
