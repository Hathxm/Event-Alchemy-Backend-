# yourapp/tasks.py

from celery import shared_task
from backend.celery import app
from django.core.mail import send_mail
from django.conf import settings
from user.models import Booking
from datetime import datetime
from vendors.models import Vendors

@shared_task(bind=True)
def notify_vendors(self):
    today = datetime.now().date()
    bookings = Booking.objects.filter(created_at=today)
    print(bookings)
   
    for booking in bookings:
        print(f"Booking: {booking}")
        services = booking.services.all()
        print(f"Services: {services}")

        for service in services:
            vendor = service.vendor
            print(f"vendor: {vendor}")

            if vendor.email :
                print(vendor.email)
                subject = "Daily Booking Notification"
                message = (f"Dear {vendor.first_name},\n\n"
                           f"You have new bookings for today:\n\n"
                           f"Booking Details:\n"
                           f"Event: {booking.event_type.name}\n"
                           f"Event: {service.service_type.service_name}\n"
                           f"Date: {booking.date}\n\n"
                           f"Please ensure you are prepared for the services you have been booked for.\n\n"
                           f"Best regards,\n"
                           f"Event Management Team")
                send_mail(subject, message, settings.EMAIL_HOST_USER, [vendor.email])
               
    return "Notifications sent to vendors."


# @shared_task(bind=True)
# def notify_vendors(self):
#     subject="hey"
#     message ="yoo"
#     vendoremail="mohammedhathimeasa@gmail.com"
#     send_mail(subject, message, settings.EMAIL_HOST_USER, [vendoremail])
#     return "Notification sent"