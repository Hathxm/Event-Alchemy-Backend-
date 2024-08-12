from django.shortcuts import render,redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework import status
from .serializers import LocationSerializer,ManagerSerializer
from user.models import Booking,Booking_status
from user.serializers import BookingSerializer 
from rest_framework.permissions import IsAuthenticated
from .models import venues, Managers
from superadmin.models import location,Events,services
from user.serializers import VenueSerializer
from rest_framework.parsers import MultiPartParser, FormParser
from django.shortcuts import get_object_or_404
from user.serializers import CustomuserSerializer,ChatMessageSerializer,ChatRoomSerializer
from django.http import Http404
from superadmin.serializers import ServiceSerializer
from chat.models import ChatRoom,ChatMessage
from vendors.serializers import VendorserviceSerializer
from vendors.models import vendorservices
from django.urls import reverse
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes 
from django.contrib import messages
from django.core.mail import EmailMultiAlternatives
from django.db.models import Max,Sum
from django.db.models.functions import ExtractMonth, ExtractYear
from datetime import datetime
from django.conf import settings
from django.core.mail import send_mail
import random
import string
from django.db import transaction


# Create your views here.

class login(APIView):
    def post(self, request):
        try:
            username = request.data.get('username')
            password = request.data.get('password')
        except KeyError:
            return Response({"error": "Not sufficient data"})

        if not Managers.objects.filter(username=username).exists():
            return Response({"error": "Username doesn't exist"})

        user = authenticate(username=username,password=password)
        
        print(user)

     
        if user is None:
            return Response({"error": "Invalid Password"})
        
        serializer=ManagerSerializer(user)

        refresh = RefreshToken.for_user(user)
        refresh['username'] = str(user.username)
        

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'manager_details':serializer.data
        }

        return Response(content, status=status.HTTP_200_OK)
    
class ManagerDetails(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_authenticated:
            try:
                manager = Managers.objects.get(username=user)
            except Managers.DoesNotExist:
                return Response({'error': 'Manager details not found'}, status=status.HTTP_404_NOT_FOUND)

            serializer = ManagerSerializer(manager)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        


class ManageVenues(APIView):
    def post(self,request):
        event_type=request.data.get('manager_type')
        event = Events.objects.get(name=event_type)
        venue = venues.objects.filter(event_type=event).order_by('-created_at')
        serialized = VenueSerializer(venue,many=True)
        return Response(serialized.data)
    
class AddVenue(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        manager_type = request.data.get('manager_type')
        location_name = request.data.get('location')
        print("Received location:", manager_type)
        
        if not manager_type:
            return Response({"error": "Manager type is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to fetch event type
            event_type = Events.objects.get(name=manager_type)
        except Events.DoesNotExist:
            return Response({"error": "Event type for the given manager type does not exist"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to fetch location
            venue_location = location.objects.get(name=location_name)
            print(venue_location.id)
            request.data['location'] = venue_location.id
        except location.DoesNotExist:
            return Response({"error": "Location not found"}, status=status.HTTP_400_BAD_REQUEST)

        request.data['event_type'] = event_type.id

        serializer = VenueSerializer(data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            
            # Fetch the updated list of venues after adding the new venue
            venue_list = venues.objects.filter(event_type=event_type).order_by('-created_at')
            serialized_venues = VenueSerializer(venue_list, many=True)

            return Response(serialized_venues.data, status=status.HTTP_201_CREATED)
        else:
            print("Serializer errors:", serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        


    
class Locations(APIView):
    def get(self,request):
        locations = location.objects.all()
        serializer = LocationSerializer(locations,many=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    

class EditVenue(APIView):
    def patch(self, request):
        venue_id = request.data.get('venue_id')
        location_name = request.data.get('location')
        manager_type = request.data.get('manager_type')

        print("Received data:", request.data)  # Log the incoming request data

        if not venue_id:
            return Response({'error': 'Venue ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            venue = venues.objects.get(id=venue_id)
            print(f"Venue found: {venue}")  # Log the venue if found
        except venues.DoesNotExist:
            print("Venue not found")  # Log if venue is not found
            return Response({'error': 'Venue not found'}, status=status.HTTP_404_NOT_FOUND)

        # Update venue attributes based on request data, excluding image1 and location
        for key, value in request.data.items():
            if key not in ['image1', 'location']:
                print(f"Updating {key} to {value}")  # Log attribute updates
                setattr(venue, key, value[0] if isinstance(value, list) else value)

        # Update location if it's provided
        if location_name:
            try:
                location_instance = location.objects.get(name=location_name)
                print(f"Location found: {location_instance}")  # Log the location if found
                venue.location = location_instance
            except location.DoesNotExist:
                print(f"Location not found: {location_name}")  # Log if location is not found
                return Response({'error': f'Location "{location_name}" does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        # Conditionally update image
        if 'image1' in request.FILES:
            print("Updating image")  # Log image update
            venue.image1 = request.FILES['image1']

        # Save the venue
        venue.save()
        print("Venue updated successfully")  # Log successful save

        # Fetch the event type based on the manager type
        if manager_type:
            try:
                event_type = Events.objects.get(name=manager_type)
                print(f"Event type found: {event_type}")  # Log the event type if found
            except Events.DoesNotExist:
                print(f"Event type not found: {manager_type}")  # Log if event type is not found
                return Response({"error": "Event type for the given manager type does not exist"}, status=status.HTTP_400_BAD_REQUEST)

            # Fetch the updated list of venues for the manager type
            updated_venue_list = venues.objects.filter(event_type=event_type).order_by('-created_at')
            serialized_venues = VenueSerializer(updated_venue_list, many=True)
            return Response(serialized_venues.data, status=status.HTTP_200_OK)

        return Response({'message': 'Venue updated successfully'}, status=status.HTTP_200_OK)

        

    

class UpdateProfile(APIView):
    def patch(self, request):
        user = request.user
       
        if user.is_authenticated:
            user_details = Managers.objects.get(username=user)
            serializer = ManagerSerializer(user_details, data=request.data, partial=True)
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
        
class EventServices(APIView):
    def post(self, request):
        event_type = request.data.get('manager_type')
       
        
        try:
            event = Events.objects.get(name=event_type)
            services = event.services.all().order_by('-created_at')  # Ensure `services` is a related name or a foreign key relationship
            
            serialized = ServiceSerializer(services, many=True)
            print(serialized.data)
            return Response(serialized.data, status=200)
        except Events.DoesNotExist:
            return Response({"error": "Event not found"}, status=404)
        except Exception as e:
            print(e)
            return Response({"error": "Something went wrong"}, status=500)
        
class AddService(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        print(request.data)
        event_type = request.data.get('manager_type')
        service_name = request.data.get('name')
        service_image = request.data.get('image')
        
        print(event_type)
        
        try:
            event = Events.objects.get(name=event_type)
            new_service = services.objects.create(
                service_name=service_name,
                image=service_image
            )
            event.services.add(new_service)  # Ensure `services` is a related name or a foreign key relationship
            service = event.services.all().order_by('-created_at') 
            serialized = ServiceSerializer(service, many=True)
            print(serialized.data)
            return Response(serialized.data, status=201)
        except Events.DoesNotExist:
            return Response({"error": "Event not found"}, status=404)
        except Exception as e:
            print(e)
            return Response({"error": "Something went wrong"}, status=500)
        

class Prev_msgs(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Annotate chat rooms with the latest message timestamp and order by it
        chat_rooms = ChatRoom.objects.filter(manager=user).annotate(
            last_message_time=Max('messages__timestamp')
        ).order_by('-last_message_time')
        
        serializer = ChatRoomSerializer(chat_rooms, many=True)
        return Response(serializer.data)
 


from django.db.models import Avg

class Vendors(APIView):
    def post(self, request):
        manager_name = request.data.get('manager_name')
        
        try:
            # Get the manager and event based on manager_name
            manager = Managers.objects.get(username=manager_name)
            event = Events.objects.get(name=manager.manager_type)
            
            # Get all services associated with the event
            services = event.services.all()
            
            # Filter VendorServices where service is in the event's services
            vendor_services = vendorservices.objects.filter(service_type__in=services)
            
            # Annotate the average rating for each service
            vendor_services = vendor_services.annotate(avg_rating=Avg('service_rating__rating'))
            
            # Serialize the filtered vendor services
            serializer = VendorserviceSerializer(vendor_services, many=True)
            
            # Add the average rating to each serialized service
            data = serializer.data
            for service in data:
                service['avg_rating'] = vendor_services.get(id=service['id']).avg_rating or 0
            
            return Response({'data': data, 'manager_id': manager.id}, status=status.HTTP_200_OK)
        
        except Events.DoesNotExist:
            return Response({'error': 'Event not found'}, status=status.HTTP_404_NOT_FOUND)
        
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"email": "This field is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = Managers.objects.filter(email=email).first()
        print(user)
        if user:
            token = default_token_generator.make_token(user)
            uid = user.pk
            print(uid)
            reset_link = request.build_absolute_uri(
                reverse('password_reset_confirm_managers', kwargs={'uidb64': uid, 'token': token})
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
            user = Managers.objects.get(pk=uid)
            if default_token_generator.check_token(user, token):
                return render(request, 'password_reset_confirm.html', {'valid_link': True, 'uidb64': uidb64, 'token': token})
            else:
                messages.info(request, 'Invalid Token. Please Request Again.')
                return render(request,'password_messages.html')  # Redirect to password reset request page or another appropriate page
        except (TypeError, ValueError, OverflowError, Managers.DoesNotExist) as e:
            messages.error(request, 'Invalid link. Please Request Again.')
            return redirect('password_reset_request_managers')  # Redirect to password reset request page or another appropriate page

    def post(self, request, uidb64, token):
        new_password = request.data.get('new_password')

        try:
            uid = uidb64
            user = Managers.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                messages.success(request, 'Password has been reset successfully.')
                return render(request, 'password_reset_confirm.html', {'valid_link': False})
            else:
                messages.error(request, 'Invalid Token. Please Request Again.')
                return render(request, 'password_reset_confirm.html', {'valid_link': False})
        except (TypeError, ValueError, OverflowError, Managers.DoesNotExist):
            messages.error(request, 'Invalid link. Please Request Again.')
            return render(request, 'password_reset_confirm.html', {'valid_link': False})
        

class VenueManagement(APIView):
    def patch(self, request):
        venue_id = request.data.get('venue_id')

        if not venue_id:
            return Response({'error': 'Venue ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            venue = venues.objects.get(id=venue_id)
        except venues.DoesNotExist:
            return Response({'error': 'Venue not found'}, status=status.HTTP_404_NOT_FOUND)

        # Toggle the block status
        venue.is_deleted = not venue.is_deleted
        venue.save()

        return Response({'success': 'Venue status updated successfully'}, status=status.HTTP_200_OK)
    
class ServiceManagement(APIView):
    def patch(self, request):
        service_id = request.data.get('serviceId')
        is_deleted = request.data.get('is_deleted')
        
        print(service_id)
        print(is_deleted)

        if service_id is None or is_deleted is None:
            return Response({'error': 'Service ID and status are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            service = services.objects.get(id=service_id)
        except services.DoesNotExist:
            return Response({'error': 'Service not found'}, status=status.HTTP_404_NOT_FOUND)

        service.is_deleted = is_deleted
        service.save()

        return Response({'success': 'Service status updated successfully'}, status=status.HTTP_200_OK)
    
class VendorServiceManagement(APIView):
    def patch(self, request):
        vendor_id = request.data.get('vendorId')
        is_deleted = request.data.get('is_deleted')

        if vendor_id is None:
            return Response({'error': 'Vendor ID is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if is_deleted is None:
            return Response({'error': 'Deletion status is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            vendorservice = vendorservices.objects.get(id=vendor_id)
        except vendorservices.DoesNotExist:
            return Response({'error': 'Vendor not found'}, status=status.HTTP_404_NOT_FOUND)

        # Toggle the is_deleted status
        vendorservice.is_deleted = is_deleted
        vendorservice.save()

        return Response({'success': 'Vendor status updated successfully'}, status=status.HTTP_200_OK)
    



class ManagerDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Retrieve the manager associated with the current user
        manager = Managers.objects.get(username=request.user)
        if not manager:
            return Response({'error': 'Manager not found'}, status=404)

        # Get the year from the request body, defaulting to the current year
        year = request.data.get('year', None)
        if not year:
            year = datetime.now().year

        # Filter bookings by the manager's event type and year
        bookings = Booking.objects.filter(event_type=manager.manager_type, date__year=year,manager=manager)
        serializer = BookingSerializer(bookings,many=True)

        # Calculate monthly revenue for the specified year
        monthly_revenue = bookings.annotate(month=ExtractMonth('date')).values('month').annotate(
            total_revenue=Sum('Total')).order_by('month')

        # Prepare the monthly revenue data for the frontend
        monthly_revenue_data = [{'month': item['month'], 'total_revenue': item['total_revenue']} for item in monthly_revenue]

        # Calculate yearly revenue
        all_years_bookings = Booking.objects.filter(event_type=manager.manager_type)
        yearly_revenue = all_years_bookings.annotate(year=ExtractYear('date')).values('year').annotate(
            total_revenue=Sum('Total')).order_by('year')

        # Prepare the yearly revenue data for the frontend
        yearly_revenue_data = [{'year': item['year'], 'total_revenue': item['total_revenue']} for item in yearly_revenue]

        # Log for debugging
        print(f"Monthly revenue data for year {year}: {monthly_revenue_data}")
        print(f"Yearly revenue data: {yearly_revenue_data}")

        return Response({'monthly_revenue': monthly_revenue_data, 'yearly_revenue': yearly_revenue_data, 'bookings':serializer.data,'wallet':manager.wallet})




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
            user = Managers.objects.get(email=email)
        except Managers.DoesNotExist:
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
        user = Managers.objects.get(email=email)
        serializer=ManagerSerializer(user)
        refresh = RefreshToken.for_user(user)
        refresh['username'] = str(user.username)
        

        content = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_details':serializer.data
        }

        return Response(content, status=status.HTTP_200_OK)


class HostedBookingView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            booking_id = request.data.get('booking_id')
           

            try:
                booking = Booking.objects.get(id=booking_id, manager=user)
            except Booking.DoesNotExist:
                return Response({"error": "Booking not found."}, status=404)

            with transaction.atomic():
                # Update the booking status to hosted
                bookingstatus = Booking_status.objects.get(name="Hosted")
                booking.status = bookingstatus
                booking.save()

                # Send notifications to the manager
                # manager = booking.manager
                # manager_message = f"Booking for venue {booking.venue.venue_name} on {booking.date} has been canceled."
                # Notification.objects.create(
                #     user=manager,
                #     message=manager_message,
                #     booking=booking
                # )

                # # Notify manager via WebSocket
                # channel_layer = get_channel_layer()
                # async_to_sync(channel_layer.group_send)(
                #     f'manager_{manager.id}',
                #     {
                #         'type': 'send_notification',
                #         'message': manager_message
                #     }
                # )

                # # Send notifications to the vendors
                # vendors = booking.services.all().values_list('vendor', flat=True).distinct()
                # vendor_message = f"A booking {booking.id} including your service on {booking.date} has been canceled."

                # for vendor_id in vendors:
                #     Notification.objects.create(
                #         user_id=vendor_id,
                #         message=vendor_message,
                #         booking=booking
                #     )

                #     # Notify vendor via WebSocket
                #     async_to_sync(channel_layer.group_send)(
                #         f'vendor_{vendor_id}',
                #         {
                #             'type': 'send_notification',
                #             'message': vendor_message
                #         }
                #     )

            return Response({"success": "Booking canceled successfully."}, status=200)

        except Exception as e:
            return Response({"error": str(e)}, status=500) 