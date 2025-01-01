from django.shortcuts import render, redirect
from .forms import TicketForm
from kiosk.models import Ticket
from django.utils.timezone import now
from django.utils.timezone import localtime
from django.shortcuts import get_object_or_404
from django.http import HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt


def ticket_selection(request):
    """First page: Select ticket type"""
    if request.method == 'POST':
        ticket_type = request.POST.get('ticket_type')
        if ticket_type:
            return redirect('kiosk:ticket_creation', ticket_type=ticket_type)
    return render(request, 'ticket_selection.html')

from django.utils.timezone import now, localtime

def ticket_creation(request, ticket_type):
    if request.method == 'POST':
        form = TicketForm(request.POST, ticket_type=ticket_type)
        if form.is_valid():
            ticket = form.save(commit=False)
            ticket.ticket_type = ticket_type

            # Assign transaction group based on transaction type
            if ticket.transaction_type == 'CERTIFICATE':
                ticket.transaction_group = 'NURSE'
            elif ticket.transaction_type == 'DENTAL':
                ticket.transaction_group = 'DENTIST'
            elif ticket.transaction_type == 'MEDICAL':
                ticket.transaction_group = 'PHYSICIAN'
            else:
                ticket.transaction_group = 'NURSE'

            # ✅ Set scheduled_time to now() if it's a walk-in appointment
            if ticket_type.upper() == 'WALKIN':
                ticket.scheduled_time = now()
            
            # Handle ticket label logic based on transaction_group
            group = ticket.transaction_group
            being_served_exists = Ticket.objects.filter(label="Being Served", transaction_group=group).exists()
            next_exists = Ticket.objects.filter(label="Next", transaction_group=group).exists()

            if not being_served_exists:
                ticket.label = "Being Served"
            elif being_served_exists and not next_exists:
                ticket.label = "Next"
            else:
                # If both exist, leave label unchanged
                pass

            ticket.save()
            return render(request, 'ticket_success.html', {
                'ticket': ticket,
                'local_transaction_time': localtime(ticket.transaction_time)
            })

    else:
        form = TicketForm(ticket_type=ticket_type)
    return render(request, 'ticket_creation.html', {'form': form, 'ticket_type': ticket_type})

def nurse_dashboard(request):
    tickets = Ticket.objects.filter(
        transaction_group='NURSE',
        checked_in=False
    ).order_by(
        '-special_tag',  # Prioritize PWD/Senior Citizen
        'transaction_time'  # Oldest first
    )
    for idx, ticket in enumerate(tickets):
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"

        ticket.transaction_time_local = localtime(ticket.transaction_time)

        if ticket.transaction_type == "Other" and ticket.details:
            ticket.truncated_transaction_type = ticket.details[:15] + "..." if len(ticket.details) > 15 else ticket.details
        else:
            ticket.truncated_transaction_type = ticket.get_transaction_type_display()
    return render(request, 'nurse_dashboard.html', {'tickets': tickets})

def dentist_dashboard(request):
    tickets = Ticket.objects.filter(
        transaction_group='DENTIST',
        checked_in=False
    ).order_by(
        '-special_tag',
        'transaction_time'
    )
    for idx, ticket in enumerate(tickets):
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"
        ticket.transaction_time_local = localtime(ticket.transaction_time)

    return render(request, 'dentist_dashboard.html', {'tickets': tickets})

def physician_dashboard(request):
    tickets = Ticket.objects.filter(
        transaction_group='PHYSICIAN',
        checked_in=False
    ).order_by(
        '-special_tag',
        'transaction_time'
    )
    for idx, ticket in enumerate(tickets):
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"
        ticket.transaction_time_local = localtime(ticket.transaction_time)

    return render(request, 'physician_dashboard.html', {'tickets': tickets})

@csrf_exempt
def proceed_next_patient(request, ticket_id):
    # Fetch the ticket by the given ticket_id
    ticket = get_object_or_404(Ticket, id=ticket_id)

    # Mark the ticket as served
    ticket.checked_in = True
    ticket.save()

    # Redirect back to the referring page (dashboard)
    return redirect(request.META.get('HTTP_REFERER', '/'))

from django.shortcuts import render

def ticket_appointment_view(request):
    """
    Renders the ticket appointment template.
    """
    return render(request, 'ticket_appointment.html')


from rest_framework.generics import RetrieveAPIView
from .models import Ticket
from .serializers import TicketSerializer

class LatestTicketView(RetrieveAPIView):
    serializer_class = TicketSerializer

    def get_object(self):
        # Retrieve the latest ticket by created_at
        return Ticket.objects.order_by('-created_at').first()





