from django.db import models
from managers.models import AllUsers
from superadmin.models import location,services
from django.utils import timezone

# Create your models here.


class Vendors(AllUsers):
    is_vendor = models.BooleanField(default=False)
    class Meta:
        verbose_name = 'Vendor'
        verbose_name_plural = 'Vendors'

class vendorservices(models.Model):
    vendor = models.ForeignKey(Vendors,on_delete=models.CASCADE)
    service_type = models.ForeignKey(services,on_delete=models.CASCADE)
    price = models.IntegerField()
    description = models.TextField()
    is_active=models.BooleanField(default=False)
    location = models.ForeignKey(location,on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now())
    is_deleted = models.BooleanField(default=False)



