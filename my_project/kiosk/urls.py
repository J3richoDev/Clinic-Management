from django.urls import path
from . import views
from .views import LatestTicketView

app_name = 'kiosk'

urlpatterns = [
    path('', views.ticket_selection, name='ticket_selection'),
    path('create/<str:ticket_type>/', views.ticket_creation, name='ticket_creation'),
    path('', views.ticket_selection, name='kiosk'),  # Assign 'kiosk' as the name of this URL
    path('proceed/<int:ticket_id>/', views.proceed_next_patient, name='proceed_next_patient'),
    path('ticket-appointment/', views.ticket_appointment_view, name='ticket_appointment'),
    path('tickets/latest/', LatestTicketView.as_view(), name='latest-ticket'),
]
