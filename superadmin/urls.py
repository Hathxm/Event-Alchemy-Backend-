from django.urls import path,include
from . import views
urlpatterns = [
    path('login/',views.login.as_view(),name='adminlogin'),
    path('details/',views.AdminDetails.as_view(),name='admindetails'),
    path('eventmanagement/',views.EventDetails.as_view(),name='eventdetails'),
    path('manager-profile',views.ManagerProfileRatingsView.as_view(),name='manager_profile_ratings'),
    path('addmanager/',views.AddManager.as_view(),name='addmanager'),
    path('managermanagement',views.ManagerManagement.as_view(), name='managermanagement'),
    # path('eventmanagement',views.EventManagement.as_view(), name='eventmanagement'),
    path('usermanagement',views.UserManagement.as_view(), name='usermanagement'),
    path('userdetails/',views.Users.as_view(),name='updateprofile'),
    path('managersdetails/', views.ManagersView.as_view(), name='managersdetails'),
    path('vendor-requests',views.VendorRequestsView.as_view(), name='vendor_request'),
    path('vendor-requests/<int:vendor_id>/accept/', views.AcceptVendorView.as_view(), name='accept-vendor'),
    path('vendor-requests/<int:vendor_id>/reject/', views.RejectVendorView.as_view(), name='reject-vendor'),

    






]