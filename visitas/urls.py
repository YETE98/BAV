# ==========================================
# IMPORTACIONES (Librerías y Vistas)
# ==========================================
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

# ==========================================
# CONFIGURACIÓN DE RUTAS (URL PATTERNS)
# ==========================================
urlpatterns = [
    # --- Autenticación y Dashboard ---
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('warn/', views.warn_view, name='warn'),

    # --- Gestión de Visitantes (Biblioteca) ---
    # Incluye: Foto, Cédula, Nombre, Última Visita y CRUD
    path('visitors/create/', views.visitor_create_view, name='visitor_create'),
    path('visitors/edit/<int:pk>', views.visitor_edit_view, name='visitor_edit'),
    path('visitors/delete/<int:pk>', views.visitor_delete_view, name='visitor_delete'),
    path('checked-in/', views.visitor_records_view, name='visitor_records'),
    path('cambiar-password/<int:pk>/', views.change_password, name='change_password'),

    # --- Control de Flujo y Logs ---
    path('visitors/', views.visitor_log_view, name='visitor_log'),
    path('visitors/exit/<int:pk>', views.registrar_salida, name='registrar_salida'),
    path('visits/', views.visitor_reports_view, name='visitor_reports'),

    # --- Configuración y Usuarios ---
    path('settings/users/', views.settings_users_view, name='settings_users'),
    path('settings/users/toggle/<int:pk>/', views.toggle_user_status, name='toggle_user_status'),
    path('settings/users/edit/<int:pk>/', views.edit_user_view, name='edit_user'),
    path('settings/users/delete/<int:pk>/', views.delete_user, name='delete_user'),
    #path('settings/users/password/<int:pk>/', views.change_password_view, name='change_password'),
    path('create_user/', views.create_user_view, name='create_user'),
    path('create_group/', views.create_group_view, name='create_group'),
    path('edit_group/<int:pk>/', views.edit_group_view, name='edit_group'),
    path('delete_group/<int:pk>/', views.delete_group_view, name='delete_group'),
    path('settings/log/', views.settings_log_view, name='settings_log'),

    # --- Herramientas de Sistema (IPs, Backup, Exportación) ---
    path('system/ips/', views.manage_ips_view, name='manage_ips'),
    path('system/ips/edit/<int:ip_id>/', views.edit_ip_view, name='edit_ip'),
    path('system/ips/toggle/<int:ip_id>/', views.toggle_ip_status, name='toggle_ip_status'),
    path('system/ips/delete/<int:ip_id>/', views.delete_ip_view, name='delete_ip'),
    
    path('system/backup/', views.database_backup_view, name='database_backup'),
    path('system/restore/', views.database_restore_view, name='database_restore'),

    path('export/pdf/', views.export_log_pdf_view, name='export_log_pdf'),
    path('export/txt/', views.export_log_txt_view, name='export_log_txt'),

]

# Servir archivos estáticos/media en desarrollo
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
