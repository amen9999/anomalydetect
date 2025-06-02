"""
URL configuration for logs app.
URLs pour l'API de détection d'anomalies dans les logs.
"""

from django.urls import path, include
from django.http import JsonResponse
from rest_framework.routers import DefaultRouter
from . import views

# Vue de test simple
def api_test_view(request):
    return JsonResponse({
        'message': 'API Logs fonctionne !',
        'status': 'success',
        'endpoints': {
            'api_root': '/api/',
            'test': '/api/test/',
        }
    })

# Configuration du router DRF
router = DefaultRouter()

# Enregistrement des ViewSets (seulement s'ils existent)
viewsets_to_register = [
    ('logs', 'LogEntryViewSet'),
    ('anomalies', 'AnomalyReportViewSet'), 
    ('batches', 'LogBatchViewSet'),
]

for url_name, viewset_name in viewsets_to_register:
    try:
        viewset = getattr(views, viewset_name)
        router.register(url_name, viewset, basename=url_name)
    except AttributeError:
        # ViewSet n'existe pas, on continue
        continue

# URLs patterns
urlpatterns = [
    # API REST avec DRF Router
    path('', include(router.urls)),
    
    # Vue de test
    path('test/', api_test_view, name='api-test'),
]