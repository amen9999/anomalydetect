"""
URL configuration for anomaly_detection project.
Configuration principale des URLs pour le projet de détection d'anomalies.
"""

from django.contrib import admin
from django.urls import path, include
from graphene_django.views import GraphQLView  
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.views import obtain_auth_token
import json

def home_view(request):
    """Vue d'accueil avec informations sur l'API"""
    return JsonResponse({
        'message': 'Bienvenue sur l\'API de Détection d\'Anomalies',
        'version': '1.0.0',
        'endpoints': {
            'api': '/api/',
            'admin': '/admin/',
            'auth': '/api-token-auth/',
            'health': '/health/',
            'stats': '/stats/',
        },
        'status': 'active'
    })

def health_check(request):
    """Endpoint de vérification de santé"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'anomaly-detection',
        'timestamp': '2025-06-02',
    })

def stats_view(request):
    """Vue des statistiques de base"""
    try:
        from logs.models import LogEntry, AnomalyReport
        
        total_logs = LogEntry.objects.count()
        total_anomalies = AnomalyReport.objects.count()
        
        return JsonResponse({
            'statistics': {
                'total_logs': total_logs,
                'total_anomalies': total_anomalies,
                'detection_rate': f"{(total_anomalies/total_logs*100):.2f}%" if total_logs > 0 else "0.00%"
            }
        })
    except Exception as e:
        return JsonResponse({
            'error': 'Unable to fetch statistics',
            'details': str(e)
        }, status=500)

urlpatterns = [
    # Page d'accueil
    path('', home_view, name='home'),
    
    # Administration Django
    path('admin/', admin.site.urls),
    
    # API principale (ton app logs)
    path('api/', include('logs.urls')),

    path('graphql/', csrf_exempt(GraphQLView.as_view(graphiql=True))),
    
    # Authentification Token
    path('api-token-auth/', obtain_auth_token, name='api_token_auth'),
    
    # Endpoints utilitaires
    path('health/', health_check, name='health'),
    path('stats/', stats_view, name='stats'),
]

# Configuration pour servir les fichiers statiques et media en développement
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Configuration du site admin
admin.site.site_header = "Administration - Détection d'Anomalies"
admin.site.site_title = "Anomaly Detection Admin"
admin.site.index_title = "Gestion des Logs et Anomalies"