from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
import re

class LogEntry(models.Model):
    SEVERITY_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'), 
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    timestamp = models.DateTimeField()
    level = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    message = models.TextField()
    source = models.CharField(max_length=100)
    anomaly_score = models.FloatField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='log_entries', default=1)  # DEFAULT ADDED
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['level']),
            models.Index(fields=['anomaly_score']),
        ]
    
    def clean(self):
        """Validation avancée obligatoire pour l'examen"""
        errors = {}
        
        # 1. Validation timestamp ordering
        if self.timestamp and self.timestamp > timezone.now():
            errors['timestamp'] = 'Timestamp cannot be in the future'
        
        # 2. Validation log severity
        valid_severities = [choice[0] for choice in self.SEVERITY_CHOICES]
        if self.level and self.level not in valid_severities:
            errors['level'] = f'Invalid severity level. Must be one of: {valid_severities}'
        
        # 3. Validation message format
        if self.message and len(self.message.strip()) < 5:
            errors['message'] = 'Log message must be at least 5 characters'
        
        # 4. Validation source format
        if self.source and not re.match(r'^[a-zA-Z0-9._-]+$', self.source):
            errors['source'] = 'Source must contain only alphanumeric characters, dots, underscores, and hyphens'
        
        # 5. Validation anomaly score range
        if self.anomaly_score is not None and (self.anomaly_score < 0 or self.anomaly_score > 1):
            errors['anomaly_score'] = 'Anomaly score must be between 0 and 1'
        
        if errors:
            raise ValidationError(errors)
    
    def save(self, *args, **kwargs):
        self.full_clean()  # Déclenche la validation avant sauvegarde
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.timestamp} - {self.level} - {self.source}"

class AnomalyReport(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Investigating'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    
    log_entry = models.ForeignKey(LogEntry, on_delete=models.CASCADE, related_name='anomaly_reports')
    title = models.CharField(max_length=200, default="Anomaly Detection Alert")  # DEFAULT ADDED
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    confidence_score = models.FloatField()
    ai_summary = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_anomalies')
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['confidence_score']),
        ]
    
    def clean(self):
        """Validation pour AnomalyReport"""
        errors = {}
        
        # Validation confidence score
        if self.confidence_score is not None and (self.confidence_score < 0 or self.confidence_score > 1):
            errors['confidence_score'] = 'Confidence score must be between 0 and 1'
        
        # Validation title
        if self.title and len(self.title.strip()) < 10:
            errors['title'] = 'Title must be at least 10 characters'
        
        # Validation description
        if self.description and len(self.description.strip()) < 20:
            errors['description'] = 'Description must be at least 20 characters'
        
        if errors:
            raise ValidationError(errors)
    
    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.title} - {self.severity} - {self.status}"

class LogBatch(models.Model):
    name = models.CharField(max_length=100)
    file_path = models.CharField(max_length=500, blank=True, null=True)
    total_logs = models.IntegerField(default=0)
    processed_logs = models.IntegerField(default=0)
    anomalies_detected = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='log_batches', default=1)  # DEFAULT ADDED
    
    def clean(self):
        """Validation pour LogBatch"""
        errors = {}
        
        if self.processed_logs > self.total_logs:
            errors['processed_logs'] = 'Processed logs cannot exceed total logs'
        
        if self.anomalies_detected > self.processed_logs:
            errors['anomalies_detected'] = 'Anomalies detected cannot exceed processed logs'
        
        if errors:
            raise ValidationError(errors)
    
    @property
    def progress_percentage(self):
        if self.total_logs == 0:
            return 0
        return (self.processed_logs / self.total_logs) * 100
    
    def __str__(self):
        return f"{self.name} - {self.status}"