from django.shortcuts import render
from rest_framework.views import APIView
from managers.models import AllUsers,Managers
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from .models import Events
from .serializers import EventSerializer,AdminSerializer
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from user.models import Customusers,Booking
from user.serializers import CustomuserSerializer,BookingSerializer
from managers.serializers import ManagerSerializer
from django.contrib.auth import authenticate
from django.utils.crypto import get_random_string
from rest_framework.permissions import IsAuthenticated
from vendors.serializers import VendorSerializer
from vendors.models import Vendors




# Create your views here.

class login(APIView):
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
            
        except KeyError:
            return Response({"error": "Not sufficient data"})

        if not AllUsers.objects.filter(username=username).exists():
            return Response({"error": "Email doesn't exist"})

        user = authenticate(username=username,password=password)
        
       

     
        if user is None:
            return Response({"error": "Invalid Password"})

        refresh = RefreshToken.for_user(user)
        refresh['email'] = str(user.email)
        

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'isAuthenticated': user.is_active,
            'isAdmin':False,
            'isSuperUser':user.is_superuser,
            'username': user.username,
        }

        return Response(content, status=status.HTTP_200_OK)
    
class EventDetails(APIView):
    def get(self,request):
        events = Events.objects.all().order_by('-created_at')
        serializer = EventSerializer(events,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        # Manually create an Event instance
        event_name = request.data.get('eventname')
        description = request.data.get('description')
        image = request.FILES.get('image')

        if event_name and description:
            event = Events.objects.create(
                name=event_name,
                description=description,
                image=image
            )
            event.save()

            events=Events.objects.all().order_by('-created_at')

            # Serialize the created event
            serializer = EventSerializer(events,many=True)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response({"error": "Invalid data"}, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self,request):
        id=request.data.get('eventId')
        print(id)
        user=Events.objects.get(id=id)
        if user.is_deleted==True:
             user.is_deleted=False
        else:
             user.is_deleted=True
        user.save()
        return Response({'success':'user updated successfully'},status=status.HTTP_200_OK)
    
class AddManager(APIView):
    def post(self, request):
        username = request.data.get('username')
        name = request.data.get('name')
        email = request.data.get('email')
        password = get_random_string(length=6, allowed_chars='1234567890')
        event_type_name = request.data.get('eventType')
        hashed_password = make_password(password)

        errors = {}

        if AllUsers.objects.filter(username=username).exists():
            errors['username'] = 'Username already exists.'

        if Managers.objects.filter(email=email).exists():
            errors['email'] = 'Email already exists.'

        try:
            manager_type = Events.objects.get(name=event_type_name)
        except ObjectDoesNotExist:
            errors['eventType'] = 'Event type does not exist.'

        if errors:
            return Response(errors, status=status.HTTP_400_BAD_REQUEST)

        Managers.objects.create(
            username=username,
            first_name=name,
            email=email,
            password=hashed_password,
            manager_type=manager_type,
            is_Manager=True
        )

        send_manager_details(email, username, password)
        return Response(status=status.HTTP_200_OK)

def send_manager_details(email,username,password):
    # Construct email subject and message
    subject = 'You Manager Account Details At EventAlchemy.com'
    message = f' Use Your Username And Password to Log In \nUsername:{username}\npassword:{password}'
    
    # Send email
    send_mail(subject, message, "eventalchemy@gmail.com", [email], fail_silently=False)

class ManagerManagement(APIView):
    def patch(self,request):
        id=request.data.get('userId')
        print(id)
        user=Managers.objects.get(id=id)
        if user.is_active==True:
             user.is_active=False
        else:
             user.is_active=True
        user.save()
        return Response({'success':'user updated successfully'},status=status.HTTP_200_OK)
    
class ManagersView(APIView):
    def get(self,request):
        managers = Managers.objects.filter(is_Manager=True)
        serializer = ManagerSerializer(managers,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
        
class Users(APIView):
    def get(self,request):
        users = Customusers.objects.all()
        serializer = CustomuserSerializer(users,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UserManagement(APIView):
    def patch(self,request):
        id=request.data.get('userId')
        print(id)
        user=Customusers.objects.get(id=id)
        if user.is_active==True:
             user.is_active=False
        else:
             user.is_active=True
        user.save()
        return Response({'success':'user updated successfully'},status=status.HTTP_200_OK)
    
class EventManagement(APIView):
    def patch(self,request):
        id=request.data.get('eventId')
        print(id)
        user=Events.objects.get(id=id)
        if user.is_deleted==True:
             user.is_deleted=False
        else:
             user.is_deleted=True
        user.save()
        return Response({'success':'user updated successfully'},status=status.HTTP_200_OK)
    

class AdminDetails(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_authenticated:
            try:
                Admin = AllUsers.objects.get(username=user)
            except AllUsers.DoesNotExist:
                return Response({'error': 'Manager details not found'}, status=status.HTTP_404_NOT_FOUND)

            serializer = AdminSerializer(Admin)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        

class VendorRequestsView(APIView):
    def get(self, request):
        # Fetch all vendor requests with is_vendor set to False
        vendor_requests = Vendors.objects.filter(is_vendor=False)
        serializer = VendorSerializer(vendor_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class AcceptVendorView(APIView):
    def post(self, request, vendor_id):
        try:
            vendor = Vendors.objects.get(id=vendor_id)
            vendor.is_vendor = True  # Mark as accepted
            vendor.save()

            # Send a confirmation email or notification to the vendor
            # send_confirmation_email(vendor.email)

            return Response({'message': 'Vendor accepted successfully'}, status=status.HTTP_200_OK)
        except Vendors.DoesNotExist:
            return Response({'error': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RejectVendorView(APIView):
    def post(self, request, vendor_id):
        try:
            vendor = Vendors.objects.get(id=vendor_id)
            vendor.delete()  # Remove the vendor request

            return Response({'message': 'Vendor rejected successfully'}, status=status.HTTP_200_OK)
        except Vendors.DoesNotExist:
            return Response({'error': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ManagerProfileRatingsView(APIView):
    def get(self, request):
        manager_id = request.query_params.get('manager_id')

        if not manager_id:
            return Response({'error': 'Manager ID not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to retrieve the manager from the database
            manager = Managers.objects.get(id=manager_id)
            serializer = ManagerSerializer(manager)

            # Retrieve the bookings related to the manager
            bookings = Booking.objects.filter(manager=manager, status__name="Hosted")
            booking_serializer = BookingSerializer(bookings, many=True)

            # Combine manager data and bookings into a single response
            response_data = {
                'manager': serializer.data,
                'bookings': booking_serializer.data
            }

            return Response(response_data, status=status.HTTP_200_OK)
        
        except Managers.DoesNotExist:
            # Handle the case where the manager does not exist
            return Response({'error': 'Manager not found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            # Handle any other unexpected errors
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)