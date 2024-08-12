import json
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from .models import ChatRoom, ChatMessage,Notification
from managers.models import Managers, AllUsers
from django.core.files.base import ContentFile
import base64

class ChatConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.manager_id = self.scope['url_route']['kwargs']['manager_id']

        self.user = await self.get_user_instance(self.user_id)
        self.manager = await self.get_manager_instance(self.manager_id)

        if self.user and self.manager:
            self.group_name = f'chat_{min(self.user_id, self.manager_id)}_{max(self.user_id, self.manager_id)}'
            await self.channel_layer.group_add(self.group_name, self.channel_name)
            await self.accept()
            await self.send_existing_messages()
        else:
            await self.close()

    @database_sync_to_async
    def get_existing_messages(self):
        chatroom, _ = ChatRoom.objects.get_or_create(user=self.user, manager=self.manager)
        messages = ChatMessage.objects.filter(room=chatroom).order_by('timestamp')
        return [{
            'message': message.message,
            'sendername': message.sender.username,
            'is_read': message.is_read,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'file_url': message.file.url if message.file else None
        } for message in messages]

    async def send_existing_messages(self):
        messages = await self.get_existing_messages()
        for message in messages:
            await self.send_json(message)

    @database_sync_to_async
    def get_user_instance(self, user_id):
        return AllUsers.objects.filter(id=user_id).first()

    @database_sync_to_async
    def get_manager_instance(self, manager_id):
        return Managers.objects.filter(id=manager_id).first()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data.get('message', '')
        sendername = data.get('sendername')
        file_data = data.get('file_data', None)
        file_name = data.get('file_name', None)

        if file_data:
            file_url = await self.save_message_with_file(sendername, message, file_data, file_name)
        else:
            file_url = None
            await self.save_message(sendername, message)

        await self.channel_layer.group_send(
            self.group_name,
            {
                'type': 'chat_message',
                'message': message,
                'sendername': sendername,
                'file_url': file_url
            }
        )

    async def chat_message(self, event):
        await self.send_json({
            'message': event['message'],
            'sendername': event['sendername'],
            'file_url': event.get('file_url', None)
        })

    @database_sync_to_async
    def save_message(self, sendername, message):
        chatroom, _ = ChatRoom.objects.get_or_create(user=self.user, manager=self.manager)
        sender = AllUsers.objects.get(username=sendername)
        ChatMessage.objects.create(
            room=chatroom,
            sender=sender,
            message=message,
            is_read=False
        )

    @database_sync_to_async
    def save_message_with_file(self, sendername, message, file_data, file_name):
        chatroom, _ = ChatRoom.objects.get_or_create(user=self.user, manager=self.manager)
        sender = AllUsers.objects.get(username=sendername)
        format, imgstr = file_data.split(';base64,')
        file_content = ContentFile(base64.b64decode(imgstr), name=file_name)
        message_instance = ChatMessage.objects.create(
            room=chatroom,
            sender=sender,
            message=message,
            is_read=False,
            file=file_content
        )
        return message_instance.file.url if message_instance.file else None


class NotificationConsumer(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.user_group_name = f'user_{self.user_id}'

        # Join user group
        await self.channel_layer.group_add(
            self.user_group_name,
            self.channel_name
        )

        await self.accept()
        notifications = await self.get_notifications()
        for notification in notifications:
            await self.send(text_data=json.dumps({
                'message': notification.message,
                'is_read': notification.is_read
            }))

    @database_sync_to_async
    def get_notifications(self):
        return list(Notification.objects.filter(user_id=self.user_id).order_by('-created_at'))

    async def disconnect(self, close_code):
        # Leave user group
        await self.channel_layer.group_discard(
            self.user_group_name,
            self.channel_name
        )

    # Receive message from WebSocket
    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data['message']

        # Send message to user group
        await self.channel_layer.group_send(
            self.user_group_name,
            {
                'type': 'send_notification',
                'message': message
            }
        )

    # Receive message from user group
    async def send_notification(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))

