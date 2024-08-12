from django.urls import path
from . import views
from django.conf.urls.static import static
from django.conf import settings
urlpatterns = [
    path('', views.landingpage.as_view(),name="landing-pg"),
    path('signup', views.Signup.as_view(),name="signup"),
    path('otp', views.OTP.as_view(),name="otp"),
    path('resendotp', views.resend_otp.as_view(),name="resendotp"),
    path('contact', views.ContactFormView.as_view(),name="contact-page"),
    path('userlogin',views.Login.as_view(),name='login'),
    path('token/refresh',views.token_refresh.as_view(),name='token_refresh'),
    path('cancel-booking',views.CancelBookingView.as_view(),name='cancel_booking'),
    path('user/details/',views.UserDetailsView.as_view(), name='user-details'),
    path('updateprofile',views.UpdateProfile.as_view(), name='updatedetails'),
    path('venues',views.Venues.as_view(), name='venues'),
    path('venue_details',views.Venuedetail.as_view(), name='venuedetails'),
    path('venue_services',views.Venueservices.as_view(), name='venueservices'),
    path('selected_services',views.Selected_services.as_view(), name='selected_services'),
    path('userdetails/',views.UserDetails.as_view(), name='user-details'),
    path('check_availability', views.check_availability, name='check_availability'),
    path('create_order', views.Confirm_Booking.as_view(), name='confirmbooking'),
    path('fetch_bookings', views.Fetch_bookings.as_view(), name='fetchbookings'),
    path('chats/prev_msgs',views.Prev_msgs.as_view(), name='previousmessages'),
    path('google-signup',views.GoogleSignup.as_view(), name='google_signup'),
    path('auth/password_reset/', views.PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('auth/password_reset_confirm/<uidb64>/<token>/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('forgot-password', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('rate-booking', views.RateBookingView.as_view(), name='rate-booking'),


    #  path('auth/password_reset_complete/', views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),








    


   

    



    

]
urlpatterns=urlpatterns+static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)