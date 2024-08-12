from rest_framework import serializers
from .models import Managers
from superadmin.models import location,services

class   ManagerSerializer(serializers.ModelSerializer):
    event_name = serializers.ReadOnlyField(source='manager_type.name', default=None)

    class Meta:
        model = Managers
        fields = ['id','username', 'email', 'first_name','event_name','is_Manager','is_superuser','is_active','date_joined','profile_pic','password_changed','created_at']


class LocationSerializer(serializers.ModelSerializer):

    class Meta:
        model = location
        fields = ['name']


    
