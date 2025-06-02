from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import hashlib
import hmac
from .models import LogEntry, AnomalyReport, LogBatch
from .serializers import LogEntrySerializer, AnomalyReportSerializer, LogBatchSerializer

# Permissions personnalisées
class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.created_by == request.user

# ViewSets principaux
class LogEntryViewSet(viewsets.ModelViewSet):
    queryset = LogEntry.objects.all()
    serializer_class = LogEntrySerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        queryset = LogEntry.objects.all()
        level = self.request.query_params.get('level')
        source = self.request.query_params.get('source')
        
        if level:
            queryset = queryset.filter(level=level)
        if source:
            queryset = queryset.filter(source=source)
            
        return queryset.order_by('-timestamp')
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    @action(detail=False, methods=['post'])
    def bulk_create(self, request):
        """Création en lot de logs"""
        serializer = LogEntrySerializer(data=request.data, many=True)
        if serializer.is_valid():
            serializer.save(created_by=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AnomalyReportViewSet(viewsets.ModelViewSet):
    queryset = AnomalyReport.objects.all()
    serializer_class = AnomalyReportSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
    
    @action(detail=False, methods=['post'])
    def analyze_logs(self, request):
        """Analyser les logs pour détecter des anomalies"""
        # Logique d'analyse simplifiée
        recent_logs = LogEntry.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=1)
        )
        
        anomalies_count = recent_logs.filter(level='ERROR').count()
        
        if anomalies_count > 10:  # Seuil configurable
            anomaly = AnomalyReport.objects.create(
                title=f"Pic d'erreurs détecté: {anomalies_count} erreurs",
                description=f"Détection automatique de {anomalies_count} erreurs dans la dernière heure",
                severity='HIGH',
                created_by=request.user
            )
            serializer = AnomalyReportSerializer(anomaly)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response({
            'message': 'Aucune anomalie détectée',
            'errors_count': anomalies_count
        })

class LogBatchViewSet(viewsets.ModelViewSet):
    queryset = LogBatch.objects.all()
    serializer_class = LogBatchSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    
    def perform_create(self, serializer):
        serializer.save(created_by=request.user)
    
    @action(detail=True, methods=['post'])
    def process_batch(self, request, pk=None):
        """Traiter un batch de logs"""
        batch = self.get_object()
        
        if batch.status == 'COMPLETED':
            return Response({
                'error': 'Batch déjà traité'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Simulation du traitement
        batch.status = 'PROCESSING'
        batch.save()
        
        # Ici tu peux ajouter la logique de traitement réel
        # Pour l'instant on simule
        batch.status = 'COMPLETED'
        batch.processed_count = batch.total_count
        batch.save()
        
        serializer = LogBatchSerializer(batch)
        return Response(serializer.data)

# Vues utilitaires
class HealthCheckView(APIView):
    """Vérification de l'état de l'API"""
    permission_classes = []
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'timestamp': timezone.now(),
            'version': '1.0.0',
            'database': 'connected',
        })

class APIStatsView(APIView):
    """Statistiques de l'API"""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        stats = {
            'total_logs': LogEntry.objects.count(),
            'total_anomalies': AnomalyReport.objects.count(),
            'total_batches': LogBatch.objects.count(),
            'logs_by_level': dict(
                LogEntry.objects.values('level').annotate(count=Count('level')).values_list('level', 'count')
            ),
            'recent_anomalies': AnomalyReport.objects.filter(
                created_at__gte=timezone.now() - timedelta(days=7)
            ).count(),
        }
        return Response(stats)