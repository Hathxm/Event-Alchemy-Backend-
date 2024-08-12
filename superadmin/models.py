from django.db import models
from django.utils import timezone

# Create your models here.
class services(models.Model):
    service_name=models.CharField(max_length=15)
    image=models.ImageField(upload_to='services',null=True)
    created_at = models.DateTimeField(default=timezone.now())
    is_deleted = models.BooleanField(default=False)



    def __str__(self) -> str:
        return self.service_name
    
class Events(models.Model):
    image = models.ImageField(upload_to='event_img',default=None,null=True)
    name=models.CharField(max_length=15)
    services=models.ManyToManyField(services,null=True,blank=True,default=None)
    description=models.TextField(null=True,default=None)
    created_at = models.DateTimeField(default=timezone.now())
    is_deleted = models.BooleanField(default=False)


    def __str__(self) -> str:
        return self.name
    
class location(models.Model):
    name=models.CharField(max_length=25)

    def __str__(self) -> str:
        return self.name