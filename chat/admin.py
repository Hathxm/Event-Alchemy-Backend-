from django.contrib import admin
from .models import ChatMessage,ChatRoom,Notification
# Register your models here.
admin.site.register(ChatMessage)
admin.site.register(ChatRoom)
admin.site.register(Notification)

