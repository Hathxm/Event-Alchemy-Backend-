from django.db import models
from superadmin.models import Events,location
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


# Create your models here.

class AllUsers(AbstractUser):
    profile_pic = models.ImageField(upload_to='userprofilepics',default=None,null=True,blank=True)
    bio = models.TextField()
    created_at = models.DateTimeField(default=timezone.now())
    wallet = models.BigIntegerField(default=0)


    class Meta:
        verbose_name = 'Users'
        verbose_name_plural = 'All Users'

class Managers(AllUsers):
    is_Manager = models.BooleanField(default=False)
    manager_type=models.ForeignKey(Events,on_delete=models.CASCADE,null=True,default=None,blank=True)
    password_changed = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Manager'
        verbose_name_plural = 'Managers'


class venues(models.Model):
    image1=models.ImageField(upload_to="venue pictures")
    image2=models.ImageField(upload_to="venue pictures",null=True,blank=True,default=None)
    image3=models.ImageField(upload_to="venue pictures",null=True,blank=True,default=None)
    image4=models.ImageField(upload_to="venue pictures",null=True,blank=True,default=None)
    venue_name=models.CharField(max_length=40)
    price_per_hour=models.BigIntegerField()
    accomodation=models.IntegerField()
    event_type=models.ForeignKey(Events,on_delete=models.CASCADE)
    location=models.ForeignKey(location,on_delete=models.CASCADE)
    description=models.TextField()
    created_at = models.DateTimeField(default=timezone.now)
    is_deleted = models.BooleanField(default=False)

    def __str__(self) -> str:
        return self.venue_name
    




