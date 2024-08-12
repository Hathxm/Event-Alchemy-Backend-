from rest_framework import serializers
from .models import vendorservices,Vendors

class VendorserviceSerializer(serializers.ModelSerializer):
    service_name = serializers.ReadOnlyField(source='service_type.service_name', default=None)
    service_image = serializers.ImageField(source='service_type.image', read_only=True) 
    vendor_name = serializers.ReadOnlyField(source='vendor.username', default=None)
    vendor_id = serializers.ReadOnlyField(source='vendor.id', default=None)

  


    class Meta:
        model = vendorservices
        fields = ['id','vendor','service_type','price','description','service_name','is_active','service_image','vendor_name','vendor_id']

class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendors 
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active', 'profile_pic', 'is_superuser','date_joined','is_vendor']


