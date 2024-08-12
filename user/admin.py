from django.contrib import admin
from .models import Customusers,Booking,Shift,Booking_status,Service_Rating
# Register your models here.
admin.site.register(Customusers)
admin.site.register(Booking)
admin.site.register(Shift)
admin.site.register(Booking_status)
admin.site.register(Service_Rating)


