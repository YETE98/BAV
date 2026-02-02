from django.contrib.auth.signals import user_login_failed, user_logged_in
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import RegistroIntento

# REGLA: Si falla el login, sumamos 1
@receiver(user_login_failed)
def registrar_intento_fallido(sender, credentials, **kwargs):
    username = credentials.get('username')
    try:
        user = User.objects.get(username=username)
        registro, created = RegistroIntento.objects.get_or_create(usuario=user)
        registro.intentos += 1
        
        # Si llega a 3, bloqueamos al usuario de Django
        if registro.intentos >= 3:
            user.is_active = False 
            user.save()
        
        registro.save()
    except User.DoesNotExist:
        # Si el usuario ni siquiera existe, no hacemos nada
        pass

# REGLA: Si entra bien, reseteamos a 0 (Tu punto #3)
@receiver(user_logged_in)
def resetear_intentos(sender, request, user, **kwargs):
    registro, created = RegistroIntento.objects.get_or_create(usuario=user)
    registro.intentos = 0
    registro.save()