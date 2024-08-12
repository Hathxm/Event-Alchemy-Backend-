from django.urls import path
from .import views

urlpatterns = [
    path('signup',views.Signup.as_view(),name="signup" ),
    path('otp',views.OTP.as_view(),name="otp" ),
    path('login',views.login.as_view(),name="login" ),
    path('contact',views.ContactFormView.as_view(),name="contact" ),
    path('home-reviews',views.Homepage.as_view(),name="home-review" ),
    path('vendor_services',views.Vendor_services.as_view(),name="vendorservices" ),
    path('dashboard',views.VendorDashboardView.as_view(),name="vendorservices" ),
    path('details',views.Vendor_Details.as_view(),name="vendor_details" ),
    path('services',views.Services.as_view(),name="services" ),
    path('addservice',views.AddService.as_view(),name="addservices" ),
    path('chats/prev_msgs',views.Prev_msgs.as_view(), name='previousmessages'),
    path('google-signup',views.GoogleSignup.as_view(), name='vendor_google_signup'),
    path('updateprofile/',views.UpdateProfile.as_view(),name="vendor_editprofile" ),
    


    










]