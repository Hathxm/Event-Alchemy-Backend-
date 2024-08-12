from django.db import models
from django.contrib.auth.models import AbstractUser
from managers.models import AllUsers,venues,Managers
from vendors.models import vendorservices 
from superadmin.models import Events
from django.utils import timezone


# Create your models here.

class Customusers(AllUsers):
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


class Shift(models.Model):
    name = models.CharField(max_length=100)
    start_time = models.TimeField()
    end_time = models.TimeField()

class Booking_status(models.Model):
    name = models.CharField(max_length=25)
    
class Booking(models.Model):
    customer = models.ForeignKey(Customusers, on_delete=models.CASCADE)
    venue = models.ForeignKey(venues, on_delete=models.CASCADE)
    date = models.DateField()
    shift = models.ForeignKey(Shift,on_delete=models.CASCADE)
    Total = models.BigIntegerField()
    amount_paid = models.BigIntegerField()
    services = models.ManyToManyField(vendorservices,blank=True)
    manager = models.ForeignKey(Managers, on_delete=models.CASCADE)
    event_type = models.ForeignKey(Events, on_delete=models.CASCADE)
    created_at = models.DateField(default=timezone.now())
    status = models.ForeignKey(Booking_status,on_delete=models.CASCADE)
    rating = models.IntegerField(default=0)
    is_rated = models.BooleanField(default=False)
    review = models.TextField(blank=True, null=True)


    def __str__(self):
        return f'{self.venue} booking on {self.date},{self.shift.name}'


class Service_Rating(models.Model):
    service = models.ForeignKey(vendorservices, on_delete=models.CASCADE)
    booking = models.ForeignKey(Booking,on_delete=models.CASCADE)
    rating = models.PositiveIntegerField()
    created_at = models.DateTimeField(default=timezone.now())
    

    def __str__(self):
        return f'{self.booking.customer.first_name} rated {self.service} - {self.rating}'
        
    

    



