from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView
from .views import DashboardStatsAPIView

urlpatterns = [

    path('', views.home, name='home'),

    # Super Admin URLs
    path('super-admin/login/', views.super_admin_login, name='super_admin_login'),
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
    path('nurse-dashboard/', views.nurse_dashboard, name='nurse_dashboard'),
    path('dentist-dashboard/', views.dentist_dashboard, name='dentist_dashboard'),
    path('physician-dashboard/', views.physician_dashboard, name='physician_dashboard'),

    # Staff Profile URLs
    path('profile/', views.view_profile, name='view_profile'),
    path('profile/edit/', views.edit_own_profile, name='edit_own_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('profile/delete/', views.delete_account, name='delete_account'),

    #path('proceed/<int:ticket_id>/', views.proceed_next_patient, name='proceed_next_patient'),
    path('proceed/<int:ticket_id>/', views.proceed_next_patient, name='proceed_next_patient'),
    
    path('patients/', views.patient_list, name='patient_list'),
    path('patients/<int:patient_id>/', views.patient_detail, name='patient_detail'),
    path('patients/<int:patient_id>/add-record/', views.add_medical_record, name='add_medical_record'),

    path('add-patient/', views.add_patient, name='add_patient'),
    path('queue/', views.queue_view, name='queue'),
    path('logout/', LogoutView.as_view(next_page='staff_login'), name='logout'),

    path('nurse/home/', views.nurse_home, name='nurse_home'),
    path('dentist/home/', views.dentist_home, name='dentist_home'),
    path('physician/home/', views.physician_home, name='physician_home'),

     path('api/dashboard/<str:staff_type>/', DashboardStatsAPIView.as_view(), name='dashboard_api'),
]

