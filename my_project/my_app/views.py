from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.http import HttpResponse, HttpResponseForbidden
from django.contrib import messages
from django.utils.crypto import get_random_string
from .models import CustomUser
from .models import CustomUserManager
from .forms import ProfileForm, CustomPasswordChangeForm
from django.contrib.auth.forms import AuthenticationForm
from kiosk.models import Ticket
from django.db import models
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import localtime
from django.http import HttpResponseRedirect
from .models import Patient, MedicalRecord
from .forms import PatientForm, MedicalRecordForm
from .models import Patient
from django.db.models import Case, When, Value, IntegerField
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import HttpResponseForbidden
from django.utils.timezone import now
from rest_framework.views import APIView
from rest_framework.response import Response
from django.db.models import Count, Avg
from .models import Patient
from django.db.models import Q
from django.contrib.auth import update_session_auth_hash, logout, authenticate, login
from django.contrib.auth.views import LoginView


# Helper function to check if the user is a super admin
def is_super_admin(user):
    return user.is_superuser

class SuperAdminLoginView(LoginView):
    template_name = 'admin/super_admin_login.html'

# Super Admin Views
def super_admin_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user and user.is_authenticated:
            # Allow login for superusers and staff
            if user.is_superuser or user.is_staff:
                login(request, user)
                return redirect('staff_list')
            else:
                messages.error(request, "Unauthorized access.")
                return redirect('super_admin_login')
        else:
            messages.error(request, "Invalid credentials.")
            return redirect('super_admin_login')

    return render(request, 'admin/super_admin_login.html')

@user_passes_test(is_super_admin)
def super_admin_logout(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('home')

@user_passes_test(is_super_admin, login_url='super_admin_login')
def super_admin_dashboard(request):
    return render(request, 'admin/super_admin_dashboard.html', {'user': request.user})

@csrf_exempt
@user_passes_test(is_super_admin, login_url='super_admin_login')
def staff_list(request):
    query = request.GET.get('search', '').strip()
    if query:
        staff_members = CustomUser.objects.filter(
            Q(first_name__icontains=query) |
            Q(middle_name__icontains=query) | 
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        ).filter(is_superuser=False)  # Exclude superuser accounts
    else:
        staff_members = CustomUser.objects.filter(is_superuser=False)  # Exclude superuser accounts

    return render(request, 'admin/staff_list.html', {'staff_members': staff_members, 'search_query': query})

@user_passes_test(is_super_admin)
def add_staff(request):
    if request.method == "POST":
        first_name = request.POST.get("first_name").strip()
        middle_name = request.POST.get("middle_name", "").strip()
        last_name = request.POST.get("last_name").strip()
        role = request.POST.get("role")
        username = request.POST.get("username", "").strip()

        if not first_name or not last_name or not role:
            messages.error(request, "First name, last name, and role are required.")
            return redirect('staff_list')

        try:
            temp_password = get_random_string(12)
            middle_initials = ''.join([word[0].lower() for word in middle_name.split() if word])
            email = (
                f"{first_name.lower().replace(' ', '')}."
                f"{last_name.lower().replace(' ', '')}."
                f"{middle_initials}@buslu.edu.ph"
            ).strip(".")

            username = username if username else email

            staff = CustomUser.objects.create_user(
                username=username or email,
                password=temp_password,
                email=email,
                first_name=first_name,
                middle_name=middle_name,
                last_name=last_name,
                role=role,
                is_staff=True,
            )

            # Store the temporary password in session
            request.session['temp_password_for_user'] = {
                'username': staff.username,
                'password': temp_password
            }

            messages.success(request, f"Staff account for {staff.full_name} created successfully.")
            return redirect('staff_list')

        except Exception as e:
            messages.error(request, f"An error occurred while creating the staff: {e}")
            return redirect('staff_list')

    return render(request, 'admin/add_staff.html')

def show_temp_password(request):
    """
    View to show the temporary password for the newly created user.
    """
    temp_password_data = request.session.get('temp_password_for_user')
    
    if not temp_password_data:
        messages.error(request, "No temporary password available.")
        return redirect('staff_list')
    
    # Clear the session data after displaying
    del request.session['temp_password_for_user']
    
    return render(request, 'admin/show_temp_password.html', {
        'username': temp_password_data['username'],
        'temp_password': temp_password_data['password']
    })

@user_passes_test(is_super_admin)
def clear_temp_password_session(request):
    if 'temp_password_for_user' in request.session:
        del request.session['temp_password_for_user']
    return HttpResponse(status=204)

@user_passes_test(is_super_admin)
def delete_staff(request, staff_id):
    staff = get_object_or_404(CustomUser, id=staff_id)
    if request.method == 'POST':
        staff.delete()
        messages.success(request, f"{staff.full_name} has been deleted.")
    return redirect('staff_list')

# Staff Views
def staff_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        role = request.POST.get("role")

        user = authenticate(request, username=username, password=password)

        if user and not user.is_superuser:
            login(request, user)

            # Assign a unique session key for the user
            request.session['user_role'] = user.role

            # Redirect based on role
            if user.role == 'nurse':
                return redirect('nurse_dashboard')
            elif user.role == 'dentist':
                return redirect('dentist_dashboard')
            elif user.role == 'physician':
                return redirect('physician_dashboard')
            else:
                messages.error(request, "Invalid role.")
                return redirect('staff_login')
        else:
            messages.error(request, "Invalid credentials or unauthorized access.")
            return redirect('staff_login')

    return render(request, 'staff/staff_login.html')

@login_required
def nurse_dashboard(request):
    if request.user.role != 'nurse':
        return HttpResponseForbidden("You are not authorized to access this page.")
    # Queue data for nurses
    tickets = Ticket.objects.filter(
    transaction_group='NURSE',
    checked_in=False
).annotate(
    # Assign role priority: FACULTY (2), PERSONNEL (2), STUDENT (1)
    role_priority=Case(
        When(role='FACULTY', then=Value(2)),
        When(role='PERSONNEL', then=Value(2)),
        When(role='STUDENT', then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    ),
    # Special tag priority: PWD/SENIOR_CITIZEN (1), NONE (0)
    special_tag_priority=Case(
        When(special_tag='PWD', then=Value(1)),
        When(special_tag='SENIOR_CITIZEN', then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    )
).order_by(
    '-special_tag_priority',  # Highest special tag first
    '-role_priority',         # Highest role priority next
    'transaction_time'        # Oldest transaction time last
)

    for idx, ticket in enumerate(tickets):
        # Assign status labels
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"

        # Localize transaction time
        ticket.transaction_time_local = localtime(ticket.transaction_time)

        # Truncate details for "Others" and keep full text for tooltip
        if ticket.transaction_type == "Other" and ticket.details:
            ticket.truncated_details = ticket.details[:15] + "..."  # Show first 15 characters with "..."
        else:
            ticket.truncated_details = ticket.get_transaction_type_display()

    # Initialize patients with a default value (all patients)
    
    # Apply filters if present
    query = request.GET.get('q')
    role_filter = request.GET.get('role')
    patients = Patient.objects.all()

    if query:
            patients = patients.filter(first_name__icontains=query) | patients.filter(last_name__icontains=query)

    if role_filter:
            patients = patients.filter(role=role_filter)

    # Render the template with context
    return render(request, 'staff/nurse_dashboard.html', {
        'tickets': tickets,
        'patients': patients,
    })

@login_required
def dentist_dashboard(request):
    if request.user.role != 'dentist':
        return HttpResponseForbidden("You are not authorized to access this page.")
    # Retrieve tickets
    tickets = Ticket.objects.filter(
        transaction_group='DENTIST',
        checked_in=False
    ).annotate(
    # Assign role priority: FACULTY (2), PERSONNEL (2), STUDENT (1)
    role_priority=Case(
        When(role='FACULTY', then=Value(2)),
        When(role='PERSONNEL', then=Value(2)),
        When(role='STUDENT', then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    ),
    # Special tag priority: PWD/SENIOR_CITIZEN (1), NONE (0)
    special_tag_priority=Case(
        When(special_tag='PWD', then=Value(1)),
        When(special_tag='SENIOR_CITIZEN', then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    )
).order_by(
    '-special_tag_priority',  # Highest special tag first
    '-role_priority',         # Highest role priority next
    'transaction_time'        # Oldest transaction time last
)
    # Annotate tickets with labels
    for idx, ticket in enumerate(tickets):
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"

        ticket.transaction_time_local = localtime(ticket.transaction_time)

    # Retrieve patient list
    query = request.GET.get('q')
    role_filter = request.GET.get('role')
    patients = Patient.objects.all()
    if query:
        patients = patients.filter(first_name__icontains=query) | patients.filter(last_name__icontains=query)
    if role_filter:
        patients = patients.filter(role=role_filter)

    return render(request, 'staff/dentist_dashboard.html', {
        'tickets': tickets,
        'patients': patients,
    })

@login_required
def physician_dashboard(request):
    if request.user.role != 'physician':
        return HttpResponseForbidden("You are not authorized to access this page.")
    # Queue data for nurses
    tickets = Ticket.objects.filter(
        transaction_group='PHYSICIAN',
        checked_in=False

    ).annotate(
    # Assign role priority: FACULTY (2), PERSONNEL (2), STUDENT (1)
    role_priority=Case(
        When(role='FACULTY', then=Value(2)),
        When(role='PERSONNEL', then=Value(2)),
        When(role='STUDENT', then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    ),
    # Special tag priority: PWD/SENIOR_CITIZEN (1), NONE (0)
    special_tag_priority=Case(
        When(special_tag='PWD', then=Value(1)),
        When(special_tag='SENIOR_CITIZEN', then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    )
).order_by(
    '-special_tag_priority',  # Highest special tag first
    '-role_priority',         # Highest role priority next
    'transaction_time'        # Oldest transaction time last
)
    for idx, ticket in enumerate(tickets):
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"
        ticket.transaction_time_local = localtime(ticket.transaction_time)

    query = request.GET.get('q')
    role_filter = request.GET.get('role')
    patients = Patient.objects.all()
    if query:
        patients = patients.filter(first_name__icontains=query) | patients.filter(last_name__icontains=query)
    if role_filter:
        patients = patients.filter(role=role_filter)
            
    return render(request, 'staff/physician_dashboard.html', {
        'tickets': tickets,
        'patients': patients,
    })

def render_dashboard(request, transaction_group, template_name):
    tickets = Ticket.objects.filter(
        transaction_group=transaction_group,
        checked_in=False
    ).annotate(
        priority=models.Value(0, output_field=models.IntegerField())  # Default value
    )

    # Annotate with priority values
    for ticket in tickets:
        ticket.priority = ticket.get_priority()

    # Sort by priority and transaction time
    sorted_tickets = sorted(tickets, key=lambda x: (-x.priority, x.transaction_time))

    return render(request, template_name, {'tickets': sorted_tickets})

@login_required
def patient_dashboard(request):
    if request.user.role != 'patient':
        return HttpResponseForbidden("You are not authorized to access this page.")
    return render(request, 'patient_dashboard.html')

@login_required
def view_profile(request):
    return render(request, 'accounts/view_profile.html', {'user': request.user})

@login_required
def edit_own_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect('view_profile')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ProfileForm(instance=request.user)

    return render(request, 'accounts/edit_profile.html', {'form': form})

@login_required
def change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, request.user)  # Keep the user logged in
            messages.success(request, "Your password has been updated successfully.")
            return redirect('view_profile')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = CustomPasswordChangeForm(user=request.user)

    return render(request, 'accounts/change_password.html', {'form': form})

@login_required
def delete_account(request):
    if request.method == 'POST':
        request.user.delete()
        messages.success(request, "Your account has been deleted.")
        return redirect('staff_login')
    return render(request, 'accounts/delete_account.html')

def home(request):
    """Render the home page."""
    return render(request, 'home.html')  # Ensure you have a `home.html` template

def proceed_next_patient(request):
    # Get the top-priority ticket (the one "Being Served")
    ticket = Ticket.objects.filter(
        checked_in=False
    ).order_by(
        '-special_tag',  # Higher priority first
        'transaction_time'  # Oldest first
    ).first()

    if ticket:
        ticket.checked_in = True  # Mark as served
        ticket.save()

    # Redirect back to the dashboard
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

def patient_list(request):
    query = request.GET.get('q')
    if query:
        patients = Patient.objects.filter(
            first_name__icontains=query
        ) | Patient.objects.filter(
            last_name__icontains=query
        )
    else:
        patients = Patient.objects.all()

    return render(request, 'staff/patient_list.html', {'patients': patients})

def add_medical_record(request, patient_id):
    patient = get_object_or_404(Patient, id=patient_id)
    if request.method == "POST":
        form = MedicalRecordForm(request.POST)
        if form.is_valid():
            medical_record = form.save(commit=False)
            medical_record.patient = patient
            medical_record.attending_staff = request.user  # Assuming staff is logged in
            medical_record.save()
            return redirect('patient_detail', patient_id=patient.id)
    else:
        form = MedicalRecordForm()

    return render(request, 'staff/add_medical_record.html', {'form': form, 'patient': patient})

def patient_detail(request, patient_id):
    # Retrieve the patient by their ID or return a 404 if not found
    patient = get_object_or_404(Patient, id=patient_id)

    # Get all medical records associated with the patient
    medical_records = MedicalRecord.objects.filter(patient=patient).order_by('-date_time')

    return render(request, 'staff/patient_detail.html', {
        'patient': patient,
        'medical_records': medical_records
    })

def add_patient(request):
    if request.method == "POST":
        form = PatientForm(request.POST)
        if form.is_valid():
            patient = form.save(commit=False)
            patient.added_by = request.user  # Assuming logged-in user is the staff member
            patient.save()

            # Redirect based on staff role
            if request.user.role == 'Nurse':
                return redirect('nurse_dashboard')
            elif request.user.role == 'Dentist':
                return redirect('dentist_dashboard')
            elif request.user.role == 'Physician':
                return redirect('physician_dashboard')
            else:
                return redirect('home')  # Default fallback if no role matches
    else:
        form = PatientForm()

    return render(request, 'staff/add_patient.html', {'form': form})

@login_required
def queue_view(request):
    # Determine the transaction group based on the user's role
    if request.user.role in ['nurse', 'dentist', 'physician']:
        transaction_group = request.user.role.upper()
    else:
        return HttpResponseForbidden("You are not authorized to access this page.")

    # Fetch tickets for the user's transaction group
    tickets = Ticket.objects.filter(
        transaction_group=transaction_group,
        checked_in=False
    ).order_by(
        '-special_tag',  # Higher priority (PWD/Senior Citizen) first
        'transaction_time'  # Oldest first
    )

    # Annotate each ticket with a label
    for idx, ticket in enumerate(tickets):
        if idx == 0:
            ticket.label = "Being Served"
        elif idx == 1:
            ticket.label = "Next"
        else:
            ticket.label = "In Queue"

        # Localize transaction time for display
        ticket.transaction_time_local = localtime(ticket.transaction_time)

        # Optional: Truncate details for "Other" transaction types
        if ticket.transaction_type == "Other" and ticket.details:
            ticket.truncated_details = ticket.details[:15] + "..."  # Show first 15 characters with "..."
        else:
            ticket.truncated_details = ticket.get_transaction_type_display()

    return render(request, 'staff/queue.html', {'tickets': tickets})

@login_required
def nurse_home(request):
    if request.user.role != 'nurse':
        return HttpResponseForbidden("Unauthorized Access")
    
    dashboard_data = ''
    context = {
        'total_patients': dashboard_data['total_patients'],
        'transaction_summary': dashboard_data['transaction_summary'],
    }

    return render_staff_home(request, 'staff/nurse_home.html', 'NURSE')

@login_required
def dentist_home(request):
    if request.user.role != 'dentist':
        return HttpResponseForbidden("Unauthorized Access")

    return render_staff_home(request, 'staff/dentist_home.html', 'DENTIST')

@login_required
def physician_home(request):
    if request.user.role != 'physician':
        return HttpResponseForbidden("Unauthorized Access")

    return render_staff_home(request, 'staff/physician_home.html', 'PHYSICIAN')

# Reusable helper function for dashboard logic
def render_staff_home(request, template_name, transaction_group):
    # Real-time statistics
    total_patients = Patient.objects.count()
    today_appointments = Ticket.objects.filter(
        transaction_time__date=now().date(),
        transaction_group=transaction_group
    ).count()

    # Patient demographics
    patient_roles = Patient.objects.values('role').annotate(total=Count('id'))

    # Clinic performance insights
    total_tickets = Ticket.objects.filter(transaction_group=transaction_group).count()

    # Context to pass to templates
    context = {
        'total_patients': total_patients,
        'today_appointments': today_appointments,
        'patient_roles': patient_roles,
        'total_tickets': total_tickets,
    }
    return render(request, template_name, context)

class DashboardStatsAPIView(APIView):
    """
    API view to retrieve real-time stats based on staff type.
    """
    def get(self, request, staff_type):
        # Filter patients by staff type
        patients = Patient.objects.filter(staff_type=staff_type)

        # Statistics
        total_patients = patients.count()
        gender_stats = patients.values('gender').annotate(count=Count('gender'))
        avg_age = patients.aggregate(Avg('age'))

        data = {
            "total_patients": total_patients,
            "gender_stats": list(gender_stats),
            "average_age": avg_age["age__avg"],
        }
        return Response(data)