from django.shortcuts import render,redirect
from .serializers import VenueSerializer,BookingSerializer
from managers.models import venues
from vendors.models import vendorservices
from rest_framework.permissions import IsAuthenticated
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from django.core.mail import send_mail,EmailMultiAlternatives
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string
from .models import Customusers,Booking,Shift,Booking_status,Service_Rating
from django.utils import timezone
from datetime import datetime
from django.conf import settings
from django.db import IntegrityError,DatabaseError
from rest_framework.exceptions import AuthenticationFailed,ParseError
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import CustomuserSerializer,ChatRoomSerializer
from vendors.serializers import VendorserviceSerializer
from superadmin.models import Events
from managers.models import Managers,AllUsers
from vendors.models import vendorservices
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.decorators import api_view
import random
from chat.models import ChatRoom,Notification
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from google.oauth2 import id_token
from google.auth.transport import requests
from django.urls import reverse
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.db.models import Max
from django.db import transaction
from django.shortcuts import get_object_or_404
import random
import string
from superadmin.serializers import EventSerializer






class landingpage(APIView):
    def get(self,request):
        data = Events.objects.all()
        serializer = EventSerializer(data,many = True)
        return JsonResponse(serializer.data, safe=False)
    
    
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
            
            if Customusers.objects.filter(email=email).exists():
                user = Customusers.objects.get(email=email)
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
            
                user = Customusers.objects.create_user(
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
            elif Customusers.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate OTP
            otp = get_random_string(length=6, allowed_chars='1234567890')

            # Send OTP to user's email
            send_otp_email(email, otp)
            
            return Response({'message': 'OTP sent to your email', 'otp': otp}, status=status.HTTP_200_OK)
        
        except Customusers.DoesNotExist:
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


class OTP(APIView):
    def post(self, request):
        try:
            # Get the data from the request
            username = request.data.get('username')
            password = request.data.get('password')
            email = request.data.get('email')
            name = request.data.get('name')

            # Print the name for debugging purposes
            print(name)

            # Hash the password before saving
            hashed_password = make_password(password)

            # Create the user
            Customusers.objects.create(
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
      
            
class resend_otp(APIView):
    def post(self,request):
            email=request.data.get('email')
            otp=resend_otp_mail(email)
            return Response({'message':'new otp send','otp':otp},status=status.HTTP_200_OK)
    


def resend_otp_mail(mail):
        otp = get_random_string(length=6, allowed_chars='1234567890')
        email=mail

        subject = 'Your OTP for account verification'
        message = f'Your OTP is: {otp}'

        send_mail(subject, message, "eventalchemy@gmail.com", [email], fail_silently=False)
        return otp


class Login(APIView):
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
          
        except KeyError:
            return Response({"error": "Not sufficient data"})
        
        if not Customusers.objects.filter(username=username).exists():
            return Response({"error": "Username doesnt exists"})

        user = authenticate(request, username=username, password=password)
        print(user)
        
        if user is None:
           return Response({"error": "Invalid Password"})
        
        
        
        
        
        refresh = RefreshToken.for_user(user)
        refresh['username'] = str(user.username)

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'isAuthenticated':user.is_active,
            'isAdmin': False,
            'isSuperAdmin': user.is_superuser,
            'username': user.username,
        }

        return Response(content, status=status.HTTP_200_OK)
    
class token_refresh(APIView):
      
      
      def post(self, request):
        user = request.user
        refresh_token = request.data.get('refresh')
   
        
        if not refresh_token:
            return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
       
        try:
            
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            new_refresh_token = str(refresh)
            

            

            # Return the new access token
            return Response({'access': access_token,'refresh':new_refresh_token}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class UserDetailsView(APIView):
    def get(self, request):
        user = request.user  # Assuming user authentication is implemented
        if user.is_authenticated:
            user_details = Customusers.objects.get(username=user)
            serialized_data = CustomuserSerializer(user_details)
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
         

class UpdateProfile(APIView):
    def patch(self, request):
        user = request.user
       
        if user.is_authenticated:
            user_details = Customusers.objects.get(username=user)
            serializer = CustomuserSerializer(user_details, data=request.data, partial=True)
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
        
    
class Venues(APIView):
    def get(self,request):
        id = request.query_params.get('id')
       
        event=Events.objects.get(id=id)
    
        venuess = venues.objects.filter(event_type=event,is_deleted=False)

        for i in venuess:
            print(i.image1)

      
        serializer=VenueSerializer(venuess,many=True)

        return Response({'data':serializer.data,'event_name':event.name})
        
class Venuedetail(APIView):
    def get(self,request):
        id = request.query_params.get('id')
        venue = venues.objects.get(id=id)
        serializer = VenueSerializer(venue) 
        return Response(serializer.data,status=status.HTTP_200_OK)
    
class Venueservices(APIView):
    def get(self, request):
        venue_id = request.query_params.get('id')
        
        if not venue_id:
            return Response({'error': 'Venue ID is required'}, status=400)
        
        try:
            venue = venues.objects.get(id=venue_id)
        except venues.DoesNotExist:
            return Response({'error': 'Venue not found'}, status=404)
        
        # Get the related event and its services
        event = venue.event_type
        services = event.services.all()
        
        # Find all vendor services that match these services
        vendor_services = vendorservices.objects.filter(service_type__in=services,location=venue.location,is_deleted=False)
        
        # Serialize the vendor services
        vendor_services_serializer = VendorserviceSerializer(vendor_services, many=True)
        
        return Response(vendor_services_serializer.data)
    
class Selected_services(APIView):
    def get(self, request):
        venue_id = request.query_params.get('id')
        services_ids = request.query_params.get('ids', '').strip()  # Using default value of empty string and stripping whitespace

        if not venue_id:
            return Response({'error': 'Venue ID is missing.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            venue = venues.objects.get(id=venue_id)
        except venues.DoesNotExist:
            return Response({'error': 'Venue not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Initialize an empty list for services
        services_data = []

        if services_ids:  # Check if services_ids is not empty
            try:
                services_ids_list = services_ids.split(',')
                services = vendorservices.objects.filter(id__in=services_ids_list)
                services_serializer = VendorserviceSerializer(services, many=True)
                services_data = services_serializer.data
            except Exception as e:
                # Log the error for debugging
                print(f"Error fetching services: {e}")
                return Response({'error': 'Invalid service IDs provided.'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            print("No services provided or services_ids is empty.")
        
        # Serialize venue data
        venue_serializer = VenueSerializer(venue)
      
        # Combine venue data with services data
        response_data = {
            'venue': venue_serializer.data,
            'services': services_data  # Use empty list if no services provided
        }

        return Response(response_data, status=status.HTTP_200_OK)
    

class UserDetails(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_authenticated:
            try:
                User = Customusers.objects.get(username=user)
            except Customusers.DoesNotExist:
                return Response({'error': 'User details not found'}, status=status.HTTP_404_NOT_FOUND)

            serializer = CustomuserSerializer(User)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
        
        
@api_view(['POST'])
def check_availability(request):
    venue_id = request.data.get('venue_id')
    date_str = request.data.get('date')

    if not all([venue_id, date_str]):
        return Response({'error': 'All fields are required'}, status=400)

    date = datetime.strptime(date_str, '%Y-%m-%d').date()

    bookings = Booking.objects.filter(venue_id=venue_id, date=date)

    # Get all shifts
    shifts = Shift.objects.all()

    available_shifts = []
    not_available_shifts = []

    for shift in shifts:
        is_available = True
        for booking in bookings:
            # Check for any overlap with existing bookings
            if not (shift.end_time <= booking.shift.start_time or shift.start_time >= booking.shift.end_time):
                is_available = False
                break

        if is_available:
            available_shifts.append({
                'name': shift.name,
                'start_time': shift.start_time,
                'end_time': shift.end_time
            })
        else:
            not_available_shifts.append({
                'name': shift.name,
                'start_time': shift.start_time,
                'end_time': shift.end_time
            })

    return Response({
        'available_shifts': available_shifts,
        'not_available_shifts': not_available_shifts
    }, status=200)


from datetime import datetime, timedelta

class Confirm_Booking(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            venue_id = request.data.get('venueId')
            services_ids = request.data.get('services')
            booking_details = request.data.get('bookingDetails')
            total_amount = request.data.get('totalAmount')
            advance_paid = request.data.get('amountToPay')

            user = get_object_or_404(Customusers, username=user.username)
            venue = get_object_or_404(venues, id=venue_id)
            shift_name = booking_details['shift']['name']
            shift = get_object_or_404(Shift, name=shift_name)

            # Create datetime objects for shift start and end times
            today = datetime.today().date()
            start_time = datetime.combine(today, shift.start_time)
            end_time = datetime.combine(today, shift.end_time)

            # Adjust for shifts that end after midnight
            if end_time < start_time:
                end_time += timedelta(days=1)

            # Calculate the shift duration in hours
            shift_duration = (end_time - start_time).total_seconds() / 3600

            managers = Managers.objects.filter(manager_type=venue.event_type)
            status = Booking_status.objects.get(name="Pending")
            if not managers.exists():
                return Response({"error": "No managers available for this event type."}, status=404)
            manager = random.choice(managers)

            with transaction.atomic():
                # Create the booking
                booking = Booking.objects.create(
                    customer=user,
                    venue=venue,
                    date=booking_details.get('date'),
                    shift=shift,
                    Total=total_amount,
                    amount_paid=advance_paid,
                    manager=manager,
                    event_type=venue.event_type,
                    status = status,
                )

                # Collect service IDs and vendor notifications
                service_ids_in_booking = []

                for service_id in list(set(services_ids)):
                    try:
                        service = vendorservices.objects.get(id=service_id)
                        booking.services.add(service)

                        # Calculate the service cost for the shift duration
                        service_cost = service.price * shift_duration
                        
                        # Calculate 25% advance payment for this service
                        vendor_payment = service_cost * 0.25
                        vendor = service.vendor
                        vendor.wallet += vendor_payment
                        advance_paid -= vendor_payment
                        vendor.save()

                        # Notify the vendor
                        vendor_notification_message = (
                            f"A new booking has been confirmed for your service {service.service_type.service_name} at venue {venue.venue_name} on {booking.date}."
                        )
                        Notification.objects.create(
                            user=vendor,
                            message=vendor_notification_message,
                            booking=booking
                        )

                        # Send notification to vendor's WebSocket channel
                        channel_layer = get_channel_layer()
                        async_to_sync(channel_layer.group_send)(
                            f'user_{vendor.id}',
                            {
                                'type': 'send_notification',
                                'message': vendor_notification_message
                            }
                        )

                        # Append service ID to list
                        service_ids_in_booking.append(service_id)

                    except vendorservices.DoesNotExist:
                        return Response({"error": f"Service with id {service_id} not found"}, status=404)

                # Add remaining advance to manager's wallet
                manager.wallet += advance_paid
                manager.save()

                # Notify the manager
                services_string = ', '.join(map(str, service_ids_in_booking))
                manager_notification_message = (
                    f"A new booking has been made for the venue {venue.venue_name} on {booking.date} With Services IDs: {services_string}."
                )
                Notification.objects.create(
                    user=manager,
                    message=manager_notification_message,
                    booking=booking
                )

                # Send notification to manager's WebSocket channel
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                     f'user_{manager.id}',
                    {
                        'type': 'send_notification',
                        'message': manager_notification_message
                    }
                )

            return Response({"success": "Booking created successfully"}, status=201)

        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=500)

        


class Fetch_bookings(APIView):
    def post(self,request):
        user = request.user
        bookings = Booking.objects.filter(customer=user)
        serializer = BookingSerializer(bookings,many=True)
        return Response(serializer.data,status=200)
        
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

    

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"email": "This field is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = Customusers.objects.filter(email=email).first()
        print(user)
        if user:
            token = default_token_generator.make_token(user)
            uid = user.pk
            print(uid)
            reset_link = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            )
            mail_subject = 'Password Reset Requested'
            message = render_to_string('password_reset_email.html', {
                'user': user,
                'reset_link': reset_link,
            })

            # Using EmailMultiAlternatives to send HTML email
            email_message = EmailMultiAlternatives(
                subject=mail_subject,
                body='',
                from_email='no-reply@myapp.com',
                to=[email],
            )
            email_message.attach_alternative(message, "text/html")
            email_message.send()

            return Response({"message": "Password reset link sent."}, status=status.HTTP_200_OK)
        else:
            return Response({"email": "No user found with this email address."}, status=status.HTTP_400_BAD_REQUEST)
        

        
class PasswordResetConfirmView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = uidb64
            user = Customusers.objects.get(pk=uid)
            print(user)
            if default_token_generator.check_token(user, token):
                return render(request, 'password_reset_confirm.html', {'valid_link': True, 'uidb64': uidb64, 'token': token})
            else:
                messages.info(request, 'Invalid Token. Please Request Again.')
                return render(request,'password_messages.html')  # Redirect to password reset request page or another appropriate page
        except (TypeError, ValueError, OverflowError, Customusers.DoesNotExist) as e:
            messages.error(request, 'Invalid link. Please Request Again.')
            return redirect('password_reset_request')  # Redirect to password reset request page or another appropriate page

    def post(self, request, uidb64, token):
        new_password = request.data.get('new_password')

        try:
            uid = uidb64
            user = Customusers.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset successfully.')
                return render(request, 'password_reset_confirm.html', {'valid_link': False})
            else:
                messages.error(request, 'Invalid Token. Please Request Again.')
                return render(request, 'password_reset_confirm.html', {'valid_link': False})
        except (TypeError, ValueError, OverflowError, Customusers.DoesNotExist):
            messages.error(request, 'Invalid link. Please Request Again.')
            return render(request, 'password_reset_confirm.html', {'valid_link': False})
        

class CancelBookingView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            booking_id = request.data.get('bookingId')
            email = request.data.get('email')
            phone_number = request.data.get('phone')

            if not email or not phone_number:
                return Response({"error": "Email and phone number are required."}, status=400)

            try:
                booking = Booking.objects.get(id=booking_id, customer=user)
            except Booking.DoesNotExist:
                return Response({"error": "Booking not found."}, status=404)

            with transaction.atomic():
                # Update the booking status to canceled
                bookingstatus = Booking_status.objects.get(name="Canceled")
                booking.status = bookingstatus
                booking.save()

                # Send notifications to the manager
                manager = booking.manager
                manager_message = f"Booking for venue {booking.venue.venue_name} on {booking.date} has been canceled."
                Notification.objects.create(
                    user=manager,
                    message=manager_message,
                    booking=booking
                )

                # Notify manager via WebSocket
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.group_send)(
                    f'user_{manager.id}',
                    {
                        'type': 'send_notification',
                        'message': manager_message
                    }
                )

                # Send notifications to the vendors
                vendors = booking.services.all().values_list('vendor', flat=True).distinct()
                vendor_message = f"A booking {booking.id} including your service on {booking.date} has been canceled."

                for vendor_id in vendors:
                    Notification.objects.create(
                        user_id=vendor_id,
                        message=vendor_message,
                        booking=booking
                    )

                    # Notify vendor via WebSocket
                    async_to_sync(channel_layer.group_send)(
                        f'user_{vendor_id}',
                        {
                            'type': 'send_notification',
                            'message': vendor_message
                        }
                    )

            return Response({"success": "Booking canceled successfully."}, status=200)

        except Exception as e:
            return Response({"error": str(e)}, status=500) 
        

            
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
            user = Customusers.objects.get(email=email)
        except Customusers.DoesNotExist:
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
        user = Customusers.objects.get(email=email)
        serializer=CustomuserSerializer(user)
        refresh = RefreshToken.for_user(user)
        refresh['username'] = str(user.username)
        

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_details':serializer.data
        }

        return Response(content, status=status.HTTP_200_OK)

class RateBookingView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        booking_id = request.query_params.get('booking_id')
        
        if not booking_id:
            return Response({'error': 'Booking ID not provided.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            booking = Booking.objects.get(id=booking_id, customer=user)
        except Booking.DoesNotExist:
            return Response({'error': 'Booking not found.'}, status=status.HTTP_404_NOT_FOUND)

        services_in_booking = booking.services.all()
        service_ratings = Service_Rating.objects.filter(booking=booking)
        service_ratings_dict = {
            rating.service.id: rating.rating for rating in service_ratings
        }

        services_with_ratings = []
        for service in services_in_booking:
            rating = service_ratings_dict.get(service.id, 0)
            services_with_ratings.append({
                'service_id': service.id,
                'service_name': service.service_type.service_name,
                'profile_pic': service.vendor.profile_pic.url if service.vendor.profile_pic else None,
                'service_image':service.service_type.image.url,
                'rating': rating
            })

        serializer = BookingSerializer(booking)

        return Response({
            'booking': serializer.data,
            'services_with_ratings': services_with_ratings
        }, status=status.HTTP_200_OK)


    def post(self, request):
        user = request.user
        booking_id = request.data.get('booking_id')
        
        try:
            booking = Booking.objects.get(id=booking_id, customer=user)
        except Booking.DoesNotExist:
            return Response({'error': 'Booking not found.'}, status=status.HTTP_404_NOT_FOUND)

        booking_rating = request.data.get('booking_rating')
        review = request.data.get('review')
        if booking_rating is not None:
            booking.rating = booking_rating
            booking.is_rated = True
            booking.review = review
            booking.save()
            manager = booking.manager
            manager_message = f"{booking.customer.first_name} has rated you {booking_rating} for the booking hosted on {booking.date} at {booking.venue.venue_name}."
            Notification.objects.create(
                user=manager,
                message=manager_message,
                booking=booking
            )

                # Notify manager via WebSocket
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'user_{manager.id}',
                {
                    'type': 'send_notification',
                    'message': manager_message
                }
            )

        service_ratings = request.data.get('service_ratings', [])
        for service_rating in service_ratings:
            service_id = service_rating.get('service_id')
            rating = service_rating.get('rating')

            service = vendorservices.objects.get(id=service_id)
            # Update or create service rating
            Service_Rating.objects.create(
                service=service,
                booking=booking,
                rating=rating
            )

        # Get all services associated with the booking
        services_in_booking = booking.services.all()

        # Retrieve ratings for the services in the booking
        updated_service_ratings = Service_Rating.objects.filter(booking=booking)
        service_ratings_dict = {
            rating.service.id: rating.rating for rating in updated_service_ratings
        }

        # Prepare a list of services with their updated ratings
        services_with_ratings = []
        for service in services_in_booking:
            rating = service_ratings_dict.get(service.id, 0)  # Default rating to 0 if not found
            services_with_ratings.append({
                'service_id': service.id,
                'service_name': service.service_type.service_name,
                'profile_pic':service.vendor.profile_pic if service.vendor.profile_pic else None,
                'service_image':service.service_type.image.url,
                'rating': rating
            })

        serializer = BookingSerializer(booking)

        return Response({
            'success': 'Ratings submitted successfully.',
            'booking': serializer.data,
            'services_with_ratings': services_with_ratings
        }, status=status.HTTP_200_OK)
    

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