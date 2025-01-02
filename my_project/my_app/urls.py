from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
from django.contrib.auth.views import LogoutView
from .views import DashboardStatsAPIView
from .views import PatientRegistrationAPIView, PatientAccountListView, validate_patient_account, ValidateEmailView
from .views import PatientAccountListView
from .views import AppointmentCreateAPIView

urlpatterns = [

    path('', views.home, name='home'),
    path('home/', views.home, name='home'),


    # Super Admin URLs
    path('super-admin/login/', views.SuperAdminLoginView.as_view(), name='super_admin_login'),
    path('super-admin/logout/', views.super_admin_logout, name='super_admin_logout'),
    path('super-admin/dashboard/', views.super_admin_dashboard, name='super_admin_dashboard'),
    path('super-admin/show-temp-password/', views.show_temp_password, name='show_temp_password'),

    # Staff Management URLs
    path('staff-list/', views.staff_list, name='staff_list'),  # Add this line
    path('add-staff/', views.add_staff, name='add_staff'),
    path('delete-staff/<int:staff_id>/', views.delete_staff, name='delete_staff'),
    path('clear-temp-password-session/', views.clear_temp_password_session, name='clear_temp_password_session'),

    # Staff Login and Dashboard URLs
    path('staff-login/', views.staff_login, name='staff_login'),
    path('staff-dashboard/', views.staff_dashboard, name='staff_dashboard'),

    # Staff Profile URLs
    path('profile/', views.view_profile, name='view_profile'),
    path('profile/edit/', views.edit_own_profile, name='edit_own_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('profile/delete/', views.delete_account, name='delete_account'),
    
    # Patient Profile URLs
    path('patient-profile/', views.patient_view_profile, name='patient_view_profile'),
    path('patient-profile/edit/', views.patient_edit_own_profile, name='patient_edit_own_profile'),
    path('patient-profile-info/edit', views.edit_patient_info, name='patient_edit_info'),
    path('patient-profile/change-password/', views.patient_change_password, name='patient_change_password'),

    path('proceed/<int:ticket_id>/', views.proceed_next_patient, name='proceed_next_patient'),
    
    path('patients/', views.patient_list, name='patient_list'),
     path('api/patient-accounts/', PatientAccountListView.as_view(), name='patient-account-list'),
         path('api/patient-accounts/validate/', validate_patient_account, name='validate-patient-account'),
         path('api/patient-accounts/validate-email/', ValidateEmailView.as_view(), name='validate-email'),

    path('patients/<int:patient_id>/', views.patient_detail, name='patient_detail'),
    path('patients/<int:patient_id>/add-record/', views.add_medical_record, name='add_medical_record'),
    path('medical-record/<int:record_id>/', views.medical_record_detail, name='medical_record_detail'),

    path('add-patient/', views.add_patient, name='add_patient'),
    path('queue/', views.queue_view, name='queue'),
    path('queue/next/', views.next_patient, name='next_patient'),
    path('queue/display/', views.queue_display, name='queue_display'),


    path('logout/', LogoutView.as_view(next_page='home'), name='logout'),


    path('api/dashboard/<str:staff_type>/', DashboardStatsAPIView.as_view(), name='dashboard_api'),
    path('api/register/', PatientRegistrationAPIView.as_view(), name='patient-register'),
     path('api/patients/', PatientAccountListView.as_view(), name='patient-list'),
    path('patient/register/', views.patient_registration, name='patient_register'),
    path('patient/login/', views.patient_login, name='patient_login'),
    path('patient/dashboard/', views.patient_dashboard, name='patient_dashboard'),
    path('appointments/create/', AppointmentCreateAPIView.as_view(), name='appointment-create'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

