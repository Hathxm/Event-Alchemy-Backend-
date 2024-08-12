from django.urls import path
from .consumers import ChatConsumer,NotificationConsumer


websocket_urlpatterns = [
    path('ws/chat/<int:user_id>/<int:manager_id>', ChatConsumer.as_asgi()),
    path('ws/notifications/<int:user_id>', NotificationConsumer.as_asgi()),
    
]

