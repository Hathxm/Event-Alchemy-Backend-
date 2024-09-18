from rest_framework import serializers
from .models import Managers
from superadmin.models import location,services

class ManagerSerializer(serializers.ModelSerializer):
    event_name = serializers.ReadOnlyField(source='manager_type.name', default=None)

    class Meta:
        model = Managers
        fields = "__all__"


class LocationSerializer(serializers.ModelSerializer):

    class Meta:
        model = location
        fields = ['name']


    
