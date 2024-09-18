from django.shortcuts import render
from rest_framework.views import APIView
from .models import Vendors,vendorservices
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError,DatabaseError
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .serializers import VendorserviceSerializer,VendorSerializer
from managers.models import AllUsers 
from superadmin.serializers import LocationSerializer,ServiceSerializer
from superadmin.models import location,services
from chat.models import ChatMessage,ChatRoom
from user.serializers import BookingSerializer,ChatRoomSerializer
from .tasks import notify_vendors
from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
from django.db.models import Max,Sum,Count,Avg,ExpressionWrapper, FloatField,F,DurationField
from user.models import Booking,Booking_status
from django.db.models.functions import ExtractMonth, ExtractYear
from datetime import datetime, timedelta
import random
import string
from django.shortcuts import get_object_or_404




# Create your views here.

class Signup(APIView):
    def post(self, request):
        try:
            # Get user data from request
            email = request.data.get('email')
            username = request.data.get('username')

            if not email or not username:
                return Response({'error': 'Email and Username are required'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Check if username already exists
            if AllUsers.objects.filter(username=username).exists():
                return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
            elif Vendors.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP
            otp = get_random_string(length=6, allowed_chars='1234567890')

            # Send OTP to user's email
            send_otp_email(email, otp)
            
            return Response({'message': 'OTP sent to your email', 'otp': otp}, status=status.HTTP_200_OK)
        
        except Vendors.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        except ValueError as e:
            # Handle specific exceptions as needed
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # General exception handling
            return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
def send_otp_email(email, otp):
    # Construct email subject and message
    subject = 'Your OTP for account verification'
    message = f'Your OTP is: {otp}'
    
    # Send email
    send_mail(subject, message, "eventalchemy@gmail.com", [email], fail_silently=False)

  
class GoogleSignup(APIView):
    def post(self, request):
        try:
            token = request.data.get('token')
            if not token:
                return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Verify the token with Google
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), settings.GOOGLE_CLIENT_ID)

            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return Response({'error': 'Invalid token issuer'}, status=status.HTTP_400_BAD_REQUEST)

            email = idinfo.get('email')
            name = idinfo.get('name')
            username = idinfo.get('sub')  # Using the Google user ID as username
            
            if Vendors.objects.filter(email=email).exists():
                user = Vendors.objects.get(email=email)
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                refresh['username'] = str(user.username)

                return Response({
                    'email': user.email,
                    'username': user.username,
                    'name': user.first_name,
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }, status=status.HTTP_200_OK)
            else:
            
                user = Vendors.objects.create_user(
                    email=email, username=username, first_name=name, password=make_password(username)
                )
                refresh = RefreshToken.for_user(user)
                refresh['username'] = str(user.username)

                return Response({
                    'email': user.email,
                    'username': user.username,
                    'name': user.first_name,
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                }, status=status.HTTP_200_OK)

        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({'error': f'Something went wrong: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class OTP(APIView):
    def post(self, request):
        try:
            # Get the data from the request
            username = request.data.get('username')
            password = request.data.get('password')
            email = request.data.get('email')
            name = request.data.get('name')
            phone_number = request.data.get('phone_number')


            # Print the name for debugging purposes
            print(name)

            # Hash the password before saving
            hashed_password = make_password(password)

            # Create the user
            Vendors.objects.create(
                username=username, 
                password=hashed_password, 
                email=email,
                first_name=name
            )

            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)

        except IntegrityError as e:
            # Handle database integrity errors, e.g., unique constraint violations
            print(f"IntegrityError: {e}")
            if 'username' in str(e):
                error_message = "Username already exists"
            elif 'email' in str(e):
                error_message = "Email already exists"
            else:
                error_message = "Data integrity error"
            return Response({"error": error_message}, status=status.HTTP_400_BAD_REQUEST)

        except DatabaseError as e:
            # Handle general database errors
            print(f"DatabaseError: {e}")
            return Response({"error": "Database error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            # Handle unexpected errors
            print(f"Unexpected error: {e}")
            return Response({"error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class login(APIView):
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
            
        except KeyError:
            return Response({"error": "Not sufficient data"})

        if not Vendors.objects.filter(username=username).exists():
            return Response({"error": "username doesn't exist"})

        user = authenticate(username=username,password=password)
        
       

     
        if user is None:
            return Response({"error": "Invalid Password"})
        
        serializer=VendorSerializer(user)
        refresh = RefreshToken.for_user(user)
        refresh['username'] = str(user.username)

        

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'vendor_details':serializer.data,
        }

        return Response(content, status=status.HTTP_200_OK)
    
class Vendor_services(APIView):
    def get(self,request):
        user=request.user
        user=Vendors.objects.get(username=user)
        data = vendorservices.objects.filter(vendor=user).order_by('-created_at')
        print(f"data:{data}")
        serializer = VendorserviceSerializer(data,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    
class Vendor_Details(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_authenticated:
            try:
                User = Vendors.objects.get(username=user)
            except Vendors.DoesNotExist:
                return Response({'error': 'User details not found'}, status=status.HTTP_400_BAD_REQUEST)

            serializer = VendorSerializer(User)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        
class Services(APIView):
    def get(self, request):
        locations = location.objects.all()
        service = services.objects.all()
        
        locations_serializer = LocationSerializer(locations, many=True)
        services_serializer = ServiceSerializer(service, many=True)
        
        return Response({
            'locations': locations_serializer.data,
            'services': services_serializer.data
        }, status=status.HTTP_200_OK) 
    

class AddService(APIView):
    def post(self, request):
        try:
            user = request.user
            print(user)

            if not user.is_authenticated:
                return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
            
            try:
                vendor = Vendors.objects.get(username=user.username)
            except Vendors.DoesNotExist:
                return Response({'error': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)
            
            location_id = request.data.get('location')
            price = request.data.get('price')
            description = request.data.get('description')
            service_type_name = request.data.get('serviceType')
          

            if not all([location_id, price, description, service_type_name]):
                return Response({'error': 'Missing one or more required fields'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                service_type = services.objects.get(id=service_type_name)
            except services.DoesNotExist:
                return Response({'error': 'Service type not found'}, status=status.HTTP_404_NOT_FOUND)
            
            try:
                service_location = location.objects.get(id=location_id)
            except location.DoesNotExist:
                return Response({'error': 'Location not found'}, status=status.HTTP_404_NOT_FOUND)

            vendorservice = vendorservices.objects.create(
                vendor=vendor,
                service_type=service_type,
                location=service_location,
                description=description,
                price=price,
                is_active=True
            )

            updated_data = vendorservices.objects.filter(vendor=vendor).order_by('-created_at')
            serializer = VendorserviceSerializer(updated_data, many=True)  # Serializing a queryset, so use `many=True`

            return Response({'success': 'Service added successfully', 'updated_data': serializer.data}, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(e)
            
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class Prev_msgs(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Annotate chat rooms with the latest message timestamp and order by it
        chat_rooms = ChatRoom.objects.filter(user=user).annotate(
            last_message_time=Max('messages__timestamp')
        ).order_by('-last_message_time')
        
        serializer = ChatRoomSerializer(chat_rooms, many=True)
        return Response(serializer.data)


class UpdateProfile(APIView):
    def patch(self, request):
        user = request.user
       
        if user.is_authenticated:
            user_details = Vendors.objects.get(username=user)
            serializer = VendorSerializer(user_details, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                response_data = {
                    'message': 'User details updated successfully!',
                    'data': serializer.data
                }
                print("User details updated successfully:", serializer.data)
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                print("Validation errors:", serializer.errors)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            print("User is not authenticated")
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        
class VendorDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Retrieve the vendor associated with the current user
        try:
            vendor = Vendors.objects.get(username=request.user)
        except Vendors.DoesNotExist:
            return Response({'error': 'Vendor not found'}, status=404)

        # Get the year from the request body, defaulting to the current year
        year = request.data.get('year', None)
        if not year:
            year = datetime.now().year

        # Filter bookings by the vendor's services and the specified year
        bookings = Booking.objects.filter(services__vendor=vendor, date__year=year)

        # Calculate monthly and yearly revenue
        monthly_revenue = {}
        yearly_revenue = {}
        years_with_bookings = Booking.objects.filter(services__vendor=vendor).dates('date', 'year').distinct()

        for booking in bookings:
            start_time = datetime.combine(booking.date, booking.shift.start_time)
            end_time = datetime.combine(booking.date, booking.shift.end_time)
            if end_time < start_time:
                end_time += timedelta(days=1)
            shift_duration = end_time - start_time
            shift_duration_hours = shift_duration.total_seconds() / 3600
            service_revenue = 0
            for service in booking.services.all():
                service_revenue += service.price * shift_duration_hours
            month = booking.date.month
            if month not in monthly_revenue:
                monthly_revenue[month] = 0
            monthly_revenue[month] += service_revenue
            if year not in yearly_revenue:
                yearly_revenue[year] = 0
            yearly_revenue[year] += service_revenue

        monthly_revenue_data = [{'month': month, 'total_revenue': revenue} for month, revenue in monthly_revenue.items()]
        yearly_revenue_data = [{'year': year, 'total_revenue': revenue} for year, revenue in yearly_revenue.items()]
        years_data = [{'year': year.year} for year in years_with_bookings]
        serializer = BookingSerializer(bookings, many=True)

        return Response({
            'monthly_revenue': monthly_revenue_data,
            'yearly_revenue': yearly_revenue_data,
            'years': years_data,
            'bookings': serializer.data
        })


       
class ForgotPasswordView(APIView):

    def generate_otp(self, length=6):
        """Generate a random numeric OTP."""
        return ''.join(random.choices(string.digits, k=length))

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if not email:
            return Response({'message': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the email exists in the database
        try:
            user = Vendors.objects.get(email=email)
        except Vendors.DoesNotExist:
            return Response({'message': 'Email not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate a random numeric OTP
        otp = self.generate_otp()

        # Send the OTP via email
        try:
            send_mail(
                'Password Reset Request',
                f'Your one-time password (OTP) is: {otp}',
                settings.DEFAULT_FROM_EMAIL,  # Use the DEFAULT_FROM_EMAIL from settings
                [email],
                fail_silently=False,
            )
            return Response({'otp': otp, 'message': 'A one-time password has been sent to your email.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message': 'Failed to send email. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
 
    def get(self, request):
        email = request.query_params.get('email')  # Use `request.query_params` to retrieve query parameters
        print(email)
        user = Vendors.objects.get(email=email)
        serializer=VendorSerializer(user)
        refresh = RefreshToken.for_user(user)
        refresh['username'] = str(user.username)
        

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_details':serializer.data
        }

        return Response(content, status=status.HTTP_200_OK)
 

class Homepage(APIView):
    def get(self,request):
        booking_status = Booking_status.objects.get(name="Hosted")
        bookings_with_reviews = Booking.objects.filter(
            status=booking_status, 
            is_rated=True
        ).exclude(review__isnull=True).exclude(review__exact="")[:3]

        serializer = BookingSerializer(bookings_with_reviews,many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class ContactFormView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            # Parse JSON data from the request body
            name = request.data.get('name')
            email = request.data.get('email')
            message = request.data.get('message')

            # Email content
            subject = 'New Contact Form Submission'
            body = f"Name: {name}\nEmail: {email}\nMessage:\n{message}"
            from_email = 'your-email@gmail.com'  # Replace with your email
            recipient_list = ['mohammedhathimeasa@gmail.com']  # Replace with superadmin's email

            # Send email
            send_mail(subject, body, from_email, recipient_list)

            # If email is successfully sent, return 200 status
            return Response({'status': 'success', 'message': 'Email sent successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            # Log the error if needed and return 500 status with error message
            return Response({'status': 'error', 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class EditService(APIView):
    def patch(self, request):
        # Extract the user and service ID
        user = request.user
        user = Vendors.objects.get(username=user)
        service_id = request.data.get('service_id')

        # Get the service instance by ID
        service_instance = get_object_or_404(vendorservices, id=service_id)

        # Serialize and update the service
        serializer = VendorserviceSerializer(service_instance, data=request.data, partial=True)
        
        if serializer.is_valid():
            # Save the changes
            serializer.save()

            # Retrieve updated services
            services = vendorservices.objects.filter(vendor=user)
            services_serializer = VendorserviceSerializer(services, many=True)

            # Return updated services in a proper JSON response
            return Response({
               'success': 'Service added successfully', 'updated_data': services_serializer.data
            }, status=status.HTTP_200_OK)
        else:
            # Return validation errors if any
            return Response({
                "message": "Failed to update the service",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class ServiceManagement(APIView):
    def patch(self, request):
        service_id = request.data.get('serviceId')
        is_deleted = request.data.get('is_active')
        
     

        if service_id is None or is_deleted is None:
            return Response({'error': 'Service ID and status are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            service = vendorservices.objects.get(id=service_id)
        except vendorservices.DoesNotExist:
            return Response({'error': 'Service not found'}, status=status.HTTP_404_NOT_FOUND)

        service.is_deleted = is_deleted
        service.save()

        return Response({'success': 'Service status updated successfully'}, status=status.HTTP_200_OK)