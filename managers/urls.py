from django.urls import path
from . import views

urlpatterns = [
    path('login',views.login.as_view()),
    path('details/',views.ManagerDetails.as_view(),name='managerdetails'),
    path('dashboard',views.ManagerDashboardView.as_view(),name='managerdashboard'),
    path('venues/',views.ManageVenues.as_view(),name='managevenues'),
    path('add-venue/', views.AddVenue.as_view(), name='add-venue'),
    path('edit-venue/', views.EditVenue.as_view(), name='edit-venue'),
    path('host-booking', views.HostedBookingView.as_view(), name='hosted_booking'),
    path('delete-venue/', views.VenueManagement.as_view(), name='delete-venue'),
    path('locations/',views.Locations.as_view(),name='locations'),
    path('updateprofile',views.UpdateProfile.as_view(),name='updateprofile'),
    path('event_services',views.EventServices.as_view(),name='Event_services'),
    path('serviceManagement/',views.ServiceManagement.as_view(),name='Event_services'),
    path('vendorServiceManagement', views.VendorServiceManagement.as_view(), name='vendor_service_management'),
    path('add_service',views.AddService.as_view(),name='add_services'),
    path('chats/prev_msgs',views.Prev_msgs.as_view(), name='previousmessages'),
    path('vendor_details',views.Vendors.as_view(), name='vendors'),
    path('auth/password_reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request_managers'),
    path('auth/password_reset_confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm_managers'),
    path('forgot-password', views.ForgotPasswordView.as_view(), name='forgot_password'),
    # path('verify-otp', views.VerifyOTPView.as_view(), name='verify_otp'),




     


    




   

]
