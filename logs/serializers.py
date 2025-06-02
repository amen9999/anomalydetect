from rest_framework import serializers
from django.contrib.auth.models import User
from .models import LogEntry, AnomalyReport, LogBatch


class UserSerializer(serializers.ModelSerializer):
    """Simple user serializer for nested representations"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        read_only_fields = ['id']


class LogEntrySerializer(serializers.ModelSerializer):
    """
    Serializer for LogEntry model with custom validation
    This addresses the DRF serializers with custom validation requirement
    """
    
    class Meta:
        model = LogEntry
        fields = [
            'id', 'timestamp', 'level', 'message', 'source',
            'ip_address', 'user_agent', 'request_method', 'status_code',
            'response_time', 'raw_log', 'parsed_data', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def validate_response_time(self, value):
        """Custom validation for response time"""
        if value is not None and value < 0:
            raise serializers.ValidationError("Response time cannot be negative")
        return value
    
    def validate_status_code(self, value):
        """Custom validation for HTTP status codes"""
        if value is not None and not (100 <= value <= 599):
            raise serializers.ValidationError("Invalid HTTP status code. Must be between 100-599")
        return value
    
    def validate_level(self, value):
        """Ensure log level is uppercase"""
        if value:
            return value.upper()
        return value
    
    def validate(self, data):
        """Cross-field validation"""
        # If it's a web request log, ensure we have required fields
        if data.get('request_method') and not data.get('status_code'):
            raise serializers.ValidationError({
                'status_code': 'Status code is required for web request logs'
            })
        
        # Validate timestamp is not in the future
        from django.utils import timezone
        if data.get('timestamp') and data['timestamp'] > timezone.now():
            raise serializers.ValidationError({
                'timestamp': 'Log timestamp cannot be in the future'
            })
        
        return data
    
    def create(self, validated_data):
        """Custom create method with additional processing"""
        # Parse additional data from raw_log if needed
        raw_log = validated_data.get('raw_log', '')
        if raw_log and not validated_data.get('parsed_data'):
            # Simple parsing logic - you can enhance this
            try:
                import json
                import re
                
                # Extract JSON if present
                json_match = re.search(r'\{.*\}', raw_log)
                if json_match:
                    validated_data['parsed_data'] = json.loads(json_match.group())
            except (json.JSONDecodeError, AttributeError):
                # If parsing fails, store raw log info
                validated_data['parsed_data'] = {'raw_length': len(raw_log)}
        
        return super().create(validated_data)


class AnomalyReportSerializer(serializers.ModelSerializer):
    """
    Serializer for AnomalyReport model with nested log entry details
    """
    log_entry_details = LogEntrySerializer(source='log_entry', read_only=True)
    assigned_to_details = UserSerializer(source='assigned_to', read_only=True)
    
    class Meta:
        model = AnomalyReport
        fields = [
            'id', 'log_entry', 'log_entry_details', 'anomaly_type', 
            'confidence_score', 'severity', 'detection_method', 'model_version',
            'description', 'suggested_action', 'status', 'is_resolved',
            'assigned_to', 'assigned_to_details', 'detected_at', 'resolved_at',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_resolved']
    
    def validate_confidence_score(self, value):
        """Ensure confidence score is between 0.0 and 1.0"""
        if not (0.0 <= value <= 1.0):
            raise serializers.ValidationError("Confidence score must be between 0.0 and 1.0")
        return value
    
    def validate_detection_method(self, value):
        """Validate detection method format"""
        if value and len(value.strip()) < 3:
            raise serializers.ValidationError("Detection method must be at least 3 characters long")
        return value.strip() if value else value
    
    def validate(self, data):
        """Cross-field validation for anomaly reports"""
        # If status is RESOLVED, ensure resolved_at is set
        if data.get('status') == 'RESOLVED' and not data.get('resolved_at'):
            from django.utils import timezone
            data['resolved_at'] = timezone.now()
        
        # High confidence scores should have detailed descriptions
        confidence = data.get('confidence_score', 0)
        description = data.get('description', '')
        if confidence > 0.8 and len(description.strip()) < 20:
            raise serializers.ValidationError({
                'description': 'High confidence anomalies (>0.8) require detailed descriptions (min 20 chars)'
            })
        
        # Critical severity should have suggested actions
        if data.get('severity') == 'CRITICAL' and not data.get('suggested_action'):
            raise serializers.ValidationError({
                'suggested_action': 'Critical anomalies must include suggested actions'
            })
        
        return data


class LogBatchSerializer(serializers.ModelSerializer):
    """
    Serializer for LogBatch model for bulk processing
    """
    log_entries_details = LogEntrySerializer(source='log_entries', many=True, read_only=True)
    progress_percentage = serializers.ReadOnlyField()
    
    class Meta:
        model = LogBatch
        fields = [
            'id', 'name', 'description', 'status', 'log_entries', 'log_entries_details',
            'total_entries', 'processed_entries', 'anomalies_detected',
            'progress_percentage', 'created_at', 'started_at', 'completed_at'
        ]
        read_only_fields = [
            'id', 'total_entries', 'processed_entries', 'anomalies_detected',
            'progress_percentage', 'created_at', 'started_at', 'completed_at'
        ]
    
    def validate_name(self, value):
        """Ensure batch name is unique and properly formatted"""
        if value and len(value.strip()) < 3:
            raise serializers.ValidationError("Batch name must be at least 3 characters long")
        return value.strip() if value else value


class AnomalyReportCreateSerializer(serializers.ModelSerializer):
    """
    Simplified serializer for creating anomaly reports (used by AI system)
    """
    class Meta:
        model = AnomalyReport
        fields = [
            'log_entry', 'anomaly_type', 'confidence_score', 'severity',
            'detection_method', 'model_version', 'description', 'suggested_action'
        ]
    
    def validate_confidence_score(self, value):
        if not (0.0 <= value <= 1.0):
            raise serializers.ValidationError("Confidence score must be between 0.0 and 1.0")
        return value


class LogIngestionSerializer(serializers.Serializer):
    """
    Serializer for bulk log ingestion with HMAC validation
    This is for the secure ingestion endpoints requirement
    """
    logs = serializers.ListField(
        child=serializers.DictField(),
        min_length=1,
        max_length=1000,  # Limit batch size for performance
        help_text="List of log entries to ingest"
    )
    signature = serializers.CharField(
        max_length=128,
        help_text="HMAC signature for request verification"
    )
    timestamp = serializers.DateTimeField(
        help_text="Request timestamp for replay attack prevention"
    )
    
    def validate_timestamp(self, value):
        """Prevent replay attacks by checking timestamp"""
        from django.utils import timezone
        import datetime
        
        now = timezone.now()
        time_diff = abs((now - value).total_seconds())
        
        # Allow 5 minutes window
        if time_diff > 300:
            raise serializers.ValidationError("Request timestamp is too old or in the future")
        
        return value
    
    def validate_logs(self, value):
        """Validate each log entry in the batch"""
        required_fields = ['message', 'level', 'timestamp']
        
        for i, log_data in enumerate(value):
            for field in required_fields:
                if field not in log_data:
                    raise serializers.ValidationError(
                        f"Log entry {i}: Missing required field '{field}'"
                    )
        
        return value
    
    def validate(self, data):
        """Validate HMAC signature"""
        import hashlib
        import hmac
        from django.conf import settings
        
        # Get the secret key for HMAC (you should set this in settings)
        secret_key = getattr(settings, 'LOG_INGESTION_SECRET', 'default-secret-key')
        
        # Create message to sign (logs + timestamp)
        message = f"{data['logs']}{data['timestamp']}"
        expected_signature = hmac.new(
            secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(expected_signature, data['signature']):
            raise serializers.ValidationError("Invalid HMAC signature")
        
        return data