from django.db import models
from user.models import Booking
from managers.models import Managers,AllUsers

# Create your models here.

class ChatRoom(models.Model):
    user = models.ForeignKey(AllUsers, on_delete=models.CASCADE, related_name='user_chatrooms')
    manager = models.ForeignKey(Managers, on_delete=models.CASCADE, related_name='manager_chatrooms')
    created_at = models.DateTimeField(auto_now_add=True)
    

    class Meta:
        unique_together = ('user', 'manager')

    def __str__(self):
        return f'ChatRoom between {self.user.username} and {self.manager.username}'
    
class ChatMessage(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(AllUsers, on_delete=models.CASCADE, related_name='sent_messages')
    message = models.TextField()
    file = models.FileField(upload_to='chat_files/', null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f'Message from {self.sender.username} in {self.room}'
    
class Notification(models.Model):
    user = models.ForeignKey(AllUsers, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    booking = models.ForeignKey(Booking,on_delete=models.CASCADE)


