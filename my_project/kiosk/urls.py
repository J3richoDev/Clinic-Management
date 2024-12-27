from django.urls import path
from . import views

app_name = 'kiosk'

urlpatterns = [
    path('', views.ticket_selection, name='ticket_selection'),
    path('create/<str:ticket_type>/', views.ticket_creation, name='ticket_creation'),
    path('', views.ticket_selection, name='kiosk'),  # Assign 'kiosk' as the name of this URL
    path('proceed/<int:ticket_id>/', views.proceed_next_patient, name='proceed_next_patient'),
    
]
