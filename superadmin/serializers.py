from rest_framework import serializers
from .models import Events,services,location  # Assuming Service is the related model
from managers.models import AllUsers

class EventSerializer(serializers.ModelSerializer):
    services = serializers.StringRelatedField(many=True)


    class Meta:
        model = Events
        fields = ['id','name', 'services','image','description','created_at']  # Add any other fields you need

    def get_image_url(self, obj):
        return obj.image.url if obj.image else None

class AdminSerializer(serializers.ModelSerializer):
    event_name = serializers.ReadOnlyField(source='manager_type.name', default=None)

    class Meta:
        model = AllUsers
        fields = ['id','username', 'email', 'first_name','event_name','is_superuser','is_active','date_joined','profile_pic']

class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = location
        fields = '__all__'  # Include fields you need

class ServiceSerializer(serializers.ModelSerializer):

    class Meta:
        model = services
        fields = ['id','service_name','created_at','is_deleted','image']  # Include fields you need

    def get_image_url(self, obj):
        return obj.image.url if obj.image else None
