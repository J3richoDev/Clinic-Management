from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.utils.crypto import get_random_string
from django.utils.timezone import localtime, now
from .models import CustomUser, PatientAccount, MedicalRecord
from kiosk.models import Ticket
from .forms import ProfileForm, CustomPasswordChangeForm, PatientForm, MedicalRecordForm, PatientEditForm
from django.db import connection
from django.db.models import Case, When, Value, IntegerField, Count, Avg, Q, ExpressionWrapper, DurationField, F
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.views import LoginView
from django.views.decorators.csrf import csrf_exempt
from .forms import PatientAccountForm



def home(request):
    return render(request, 'home.html')

# Helper function to check if the user is a super admin
def is_super_admin(user):
    return user.is_superuser

class SuperAdminLoginView(LoginView):
    template_name = 'admin/super_admin_login.html'
    
    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')

        # Authenticate using the custom backend
        user = authenticate(self.request, username=username, password=password)
        if user is not None and user.is_superuser:
            login(self.request, user)
            return redirect('staff_list')
        else:
            form.add_error(None, "Invalid credentials or unauthorized access.")
            return self.form_invalid(form)

    def form_invalid(self, form):
        messages.error(self.request, "Invalid credentials. Please try again.")
        return super().form_invalid(form)

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
     return redirect('staff_list')

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
        first_name = request.POST.get("first_name", "").strip()
        middle_name = request.POST.get("middle_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        role = request.POST.get("role")
        username = request.POST.get("username", "").strip()

        if not first_name or not last_name or not role:
            messages.error(request, "First name, last name, and role are required.")
            return redirect('staff_list')

        try:
            temp_password = get_random_string(12)
            middle_initials = (
                ''.join([word[0].lower() for word in middle_name.split() if word])
                if middle_name else 'x'
            )

            # Base Email Template
            base_email = (
                f"{first_name.lower().replace(' ', '')}."
                f"{last_name.lower().replace(' ', '')}."
                f"{middle_initials}@bulsu.edu.ph"
            ).strip(".")

            email = base_email
            counter = 1

            # Check if the email already exists, increment if needed
            while CustomUser.objects.filter(email=email).exists():
                email = f"{base_email.split('@')[0]}{counter}@{base_email.split('@')[1]}"
                counter += 1

            # Set username if not provided
            username = username if username else email

            staff = CustomUser.objects.create_user(
                username=username,
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

            messages.success(request, f"Staff account for {staff.full_name} created successfully with email {email}.")
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
    errors = {}
    if request.method == "POST":
        identifier = request.POST.get("username")  # Can be username or email
        password = request.POST.get("password")

        # Validation for empty fields
        if not identifier:
            errors['username'] = "Username or Email is required."
        if not password:
            errors['password'] = "Password is required."

        if not errors:
            # Check if the identifier is an email
            user = None
            if "@" in identifier:
                try:
                    user_obj = CustomUser.objects.get(email=identifier)
                    user = authenticate(request, username=user_obj.username, password=password)
                except CustomUser.DoesNotExist:
                    errors['general'] = "Invalid email or password."
            else:
                # Assume it's a username
                user = authenticate(request, username=identifier, password=password)

            if user and not user.is_superuser:
                login(request, user)
                request.session['user_role'] = user.role
                return redirect('staff_dashboard')
            else:
                errors['general'] = "Invalid credentials or unauthorized access."

    return render(request, 'staff/staff_login.html', {'errors': errors})

from django.db.models import Count

@login_required
def staff_dashboard(request):
    user = request.user
    today = timezone.now().date()
    start_of_week = today - timedelta(days=today.weekday())
    start_of_month = today.replace(day=1)

    # Metrics
    total_patients_today = MedicalRecord.objects.filter(attending_staff=user, date_time__date=today).count()
    pending_appointments = Ticket.objects.filter(transaction_group=user.role.upper(), ticket_type='APPOINTMENT', checked_in=False).count()
    current_queue_status = Ticket.objects.filter(transaction_group=user.role.upper(), checked_in=False).count()

    # **4. Average Consultation Duration (Using Raw SQL Query for SQLite)**
    consultation_duration = (
        Ticket.objects.filter(checked_in_time__isnull=False)  # Only include tickets with valid checked_in_time
        .annotate(queue_time=ExpressionWrapper(
            F('checked_in_time') - F('scheduled_time'),
            output_field=DurationField()
        ))
        .aggregate(average_queue_time=Avg('queue_time'))['average_queue_time']
    )
    
    average_consultation_duration = 0
    if consultation_duration:
        total_seconds = int(consultation_duration.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60

        if hours > 0 and minutes > 0:
            average_consultation_duration = f"{hours} hr {minutes} min"
        elif hours > 0:
            average_consultation_duration = f"{hours} hr"
        else:
            average_consultation_duration = f"{minutes} min"

    weekly_patients = MedicalRecord.objects.filter(attending_staff=user, date_time__date__gte=start_of_week).count()
    monthly_patients = MedicalRecord.objects.filter(attending_staff=user, date_time__date__gte=start_of_month).count()

    recent_records = MedicalRecord.objects.filter(attending_staff=user).order_by('-date_time')[:10]

    # Aggregate Initial Diagnosis Counts
    diagnosis_counts = MedicalRecord.objects.values('initial_diagnosis').annotate(count=Count('initial_diagnosis')).order_by('-count')

    return render(request, 'staff/staff_dashboard.html', {
        'recent_records': recent_records,
        'total_patients_today': total_patients_today,
        'pending_appointments': pending_appointments,
        'current_queue_status': current_queue_status,
        'average_consultation_duration': average_consultation_duration,
        'weekly_patients': weekly_patients,
        'monthly_patients': monthly_patients,
        'diagnosis_counts': diagnosis_counts,
    })
  
    
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


def patient_view_profile(request):
    if not request.session.get('patient_id'):
        return redirect('patient_login')

    patient_id = request.session.get('patient_id')
    
    user = get_object_or_404(PatientAccount, id=patient_id)
    
    return render(request, 'patients/view_acc.html', {'user': user})

def patient_edit_own_profile(request):
    
    if not request.session.get('patient_id'):
        return redirect('patient_login')

    patient_id = request.session.get('patient_id')
    
    user = get_object_or_404(PatientAccount, id=patient_id)
    
    
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect('patient_view_profile')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ProfileForm(instance=user)

    return render(request, 'patients/edit_acc.html', {'form': form, 'user':user})

def edit_patient_info(request):
    if not request.session.get('patient_id'):
        return redirect('patient_login')

    patient_id = request.session.get('patient_id')
    patient = get_object_or_404(PatientAccount, id=patient_id)
    
    if request.method == 'POST':
        form = PatientEditForm(request.POST, instance=patient)
        if form.is_valid():
            form.save()
            messages.success(request, 'Patient information updated successfully.')
            return redirect('patient_view_profile')
    else:
        form = PatientEditForm(instance=patient)
    
    context = {
        'form': form,
        'patient': patient
    }
    return render(request, 'patients/edit_info.html', context)

def patient_change_password(request):
    
    if not request.session.get('patient_id'):
        return redirect('patient_login')

    patient_id = request.session.get('patient_id')
    
    patient_user = get_object_or_404(PatientAccount, id=patient_id)
    
    if request.method == 'POST':
        form = CustomPasswordChangeForm(user=patient_user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, patient_user)  # Keep the user logged in
            messages.success(request, "Your password has been updated successfully.")
            return redirect('patient_view_profile')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = CustomPasswordChangeForm(user=patient_user)

    return render(request, 'patients/change_pw.html', {'form': form})


@login_required
def delete_account(request):
    if request.method == 'POST':
        request.user.delete()
        messages.success(request, "Your account has been deleted.")
    return redirect('home')


def proceed_next_patient(request):
    # Get the top-priority ticket (the one "Being Served")
    ticket = Ticket.objects.filter(
        checked_in=False
    ).order_by(
        '-special_tag',  # Higher priority first
        'scheduled_time'  # Oldest first
    ).first()

    if ticket:
        ticket.checked_in = True  # Mark as served
        ticket.save()

    # Redirect back to the dashboard
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

def patient_list(request):
    query = request.GET.get('q')
    role = request.GET.get('role')
    
    patients = PatientAccount.objects.all()

    if query:
        patients = patients.filter(
            first_name__icontains=query
        ) | patients.filter(
            last_name__icontains=query
        ) | patients.filter(
            middle_name__icontains=query
        )

    if role:
        patients = patients.filter(role=role)

    return render(request, 'staff/patient_list.html', {'patients': patients})

def add_medical_record(request, patient_id):
    patient = get_object_or_404(PatientAccount, id=patient_id)
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
    patient = get_object_or_404(PatientAccount, id=patient_id)

    # Get all medical records associated with the patient
    medical_records = MedicalRecord.objects.filter(patient=patient).order_by('-date_time')

    return render(request, 'staff/patient_detail.html', {
        'patient': patient,
        'medical_records': medical_records
    })
    
def medical_record_detail(request, record_id):
    # Retrieve the medical record by its ID or return a 404 if not found
    record = get_object_or_404(MedicalRecord, id=record_id)
    
    return render(request, 'staff/medical_record_detail.html', {
        'record': record
    })

def add_patient(request):
    if request.method == "POST":
        form = PatientForm(request.POST)
        if form.is_valid():
            contact_number = form.cleaned_data.get('contact_number')
            
            # Check if the contact number already exists in PatientAccount
            if PatientAccount.objects.filter(contact_number=contact_number).exists():
                form.add_error('contact_number', 'A patient with this contact number already exists.')
            else:
                patient = form.save(commit=False)
                patient.added_by = request.user  # Assuming logged-in user is the staff member
                patient.save()
                return redirect('staff_dashboard')  # Redirect to staff dashboard after saving
    else:
        form = PatientForm()

    return render(request, 'staff/add_patient.html', {'form': form})

@login_required
def queue_view(request):
    if request.user.role not in ['nurse', 'dentist', 'physician']:
        return HttpResponseForbidden("You are not authorized to access this page.")
    
    current_date = localtime(now()).date()

    # Fetch tickets for the user's transaction group
    tickets = Ticket.objects.filter(
        transaction_group=request.user.role.upper(),
        checked_in=False,
        scheduled_time__date=current_date
    )

    # Priority Definitions
    role_priority = {
        'PERSONNEL': 1,
        'FACULTY': 2,
        'STUDENT': 3
    }

    special_tag_priority = {
        'PWD': 1,
        'Senior Citizen': 2
    }

    def sort_walkin(ticket):
        """Sorting logic for walk-in tickets."""
        # Special Tag Priority
        special_tag_rank = special_tag_priority.get(ticket.special_tag, 99)  # Default to 99 if no special tag
        # Role Priority
        role_rank = role_priority.get(ticket.role, 4)  # Default to 4 if role is undefined
        # Scheduled Time
        scheduled_time = ticket.scheduled_time or now()
        
        return (
            special_tag_rank,  # Prioritize special tag
            role_rank,  # Then prioritize role
            scheduled_time  # Lastly, prioritize by scheduled time
        )

    # Separate tickets into categories
    being_served = None
    next_ticket = None
    appointment_tickets = []
    walkin_tickets = []

    for ticket in tickets:
        if ticket.label == "Being Served":
            being_served = ticket
        elif ticket.label == "Next":
            next_ticket = ticket
        elif ticket.ticket_type == 'APPOINTMENT':
            appointment_tickets.append(ticket)
        else:
            walkin_tickets.append(ticket)

    # Sort appointment and walk-in tickets
    appointment_tickets.sort(key=lambda t: t.scheduled_time or now())
    walkin_tickets.sort(key=sort_walkin)

    # Prepare the final queue
    final_queue = []

    # Step 1: Always preserve 'Being Served' and 'Next'
    if being_served:
        being_served.label = "Being Served"
        final_queue.append(being_served)
    if next_ticket:
        next_ticket.label = "Next"
        final_queue.append(next_ticket)

    # Step 2: Process remaining appointment tickets
    for ticket in appointment_tickets:
        if ticket != being_served and ticket != next_ticket:
            ticket.label = "In Queue"
            final_queue.append(ticket)

    # Step 3: Process remaining walk-in tickets
    for ticket in walkin_tickets:
        if ticket != being_served and ticket != next_ticket:
            ticket.label = "In Queue"
            final_queue.append(ticket)

    # Step 4: Ensure no ticket overwrites 'Being Served' or 'Next'
    if not being_served and final_queue:
        final_queue[0].label = "Being Served"
    if not next_ticket and len(final_queue) > 1:
        final_queue[1].label = "Next"

    return render(request, 'staff/queue.html', {'tickets': final_queue})


@login_required
def queue_display(request):
    if request.user.role not in ['nurse', 'dentist', 'physician']:
        return HttpResponseForbidden("You are not authorized to access this page.")
    
    current_date = localtime(now()).date()

    # Fetch tickets for the user's transaction group
    tickets = Ticket.objects.filter(
        transaction_group=request.user.role.upper(),
        checked_in=False,
        scheduled_time__date=current_date
    )

    # Priority Definitions
    role_priority = {
        'PERSONNEL': 1,
        'FACULTY': 2,
        'STUDENT': 3
    }

    special_tag_priority = {
        'PWD': 1,
        'Senior Citizen': 2
    }

    def sort_walkin(ticket):
        """Sorting logic for walk-in tickets."""
        # Special Tag Priority
        special_tag_rank = special_tag_priority.get(ticket.special_tag, 99)  # Default to 99 if no special tag
        # Role Priority
        role_rank = role_priority.get(ticket.role, 4)  # Default to 4 if role is undefined
        # Scheduled Time
        scheduled_time = ticket.scheduled_time or now()
        
        return (
            special_tag_rank,  # Prioritize special tag
            role_rank,  # Then prioritize role
            scheduled_time  # Lastly, prioritize by scheduled time
        )

    # Separate tickets into categories
    being_served = None
    next_ticket = None
    appointment_tickets = []
    walkin_tickets = []

    for ticket in tickets:
        if ticket.label == "Being Served":
            being_served = ticket
        elif ticket.label == "Next":
            next_ticket = ticket
        elif ticket.ticket_type == 'APPOINTMENT':
            appointment_tickets.append(ticket)
        else:
            walkin_tickets.append(ticket)

    # Sort appointment and walk-in tickets
    appointment_tickets.sort(key=lambda t: t.scheduled_time or now())
    walkin_tickets.sort(key=sort_walkin)

    # Prepare the final queue
    final_queue = []

    # Step 1: Always preserve 'Being Served' and 'Next'
    if being_served:
        being_served.label = "Being Served"
        final_queue.append(being_served)
    if next_ticket:
        next_ticket.label = "Next"
        final_queue.append(next_ticket)

    # Step 2: Process remaining appointment tickets
    for ticket in appointment_tickets:
        if ticket != being_served and ticket != next_ticket:
            ticket.label = "In Queue"
            final_queue.append(ticket)

    # Step 3: Process remaining walk-in tickets
    for ticket in walkin_tickets:
        if ticket != being_served and ticket != next_ticket:
            ticket.label = "In Queue"
            final_queue.append(ticket)

    # Step 4: Ensure no ticket overwrites 'Being Served' or 'Next'
    if not being_served and final_queue:
        final_queue[0].label = "Being Served"
    if not next_ticket and len(final_queue) > 1:
        final_queue[1].label = "Next"

    return render(request, 'staff/queue_display.html', {'tickets': final_queue})

@login_required
def next_patient(request):
    if request.user.role not in ['nurse', 'dentist', 'physician']:
        return HttpResponseForbidden("You are not authorized to perform this action.")

    # Define role priority mapping
    role_priority = {
        'PERSONNEL': 1,
        'FACULTY': 2,
        'STUDENT': 3
    }

    # Custom sorting function
    def ticket_sort_key(ticket):
        special_tag_priority = ticket.special_tag in ['PWD', 'Senior Citizen']
        role_rank = role_priority.get(ticket.role, 4)  # Default rank 4 if role is undefined
        return (
            not special_tag_priority,  # Prioritize special tags
            role_rank,  # Prioritize role (PERSONNEL > FACULTY > STUDENT)
            ticket.scheduled_time or now()  # Prioritize by scheduled time
        )

    # Fetch all active tickets excluding 'Being Served' and 'Next'
    remaining_tickets = Ticket.objects.filter(
        transaction_group=request.user.role.upper(),
        checked_in=False
    ).exclude(
        label__in=["Being Served", "Next"]
    )

    # Apply sorting logic
    sorted_tickets = sorted(remaining_tickets, key=ticket_sort_key)

    # Step 1: Handle 'Being Served' → Mark as 'Done'
    being_served_ticket = Ticket.objects.filter(label="Being Served").first()
    if being_served_ticket:
        being_served_ticket.label = "Done"
        being_served_ticket.checked_in = True
        being_served_ticket.checked_in_time = now()
        being_served_ticket.save()

    # Step 2: Promote 'Next' → 'Being Served'
    next_ticket = Ticket.objects.filter(label="Next").first()
    if next_ticket:
        next_ticket.label = "Being Served"
        next_ticket.save()

    # Step 3: Promote the First Remaining Ticket → 'Next'
    if sorted_tickets:
        third_ticket = sorted_tickets[0]
        third_ticket.label = "Next"
        third_ticket.save()

    return redirect('queue')


class DashboardStatsAPIView(APIView):
    """
    API view to retrieve real-time stats based on staff type.
    """
    def get(self, request, staff_type):
        # Filter patients by staff type
        patients = PatientAccount.objects.filter(staff_type=staff_type)

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
    
def patient_registration(request):
    

    return render(request, 'patients/register.html')

from rest_framework import generics
from .models import PatientAccount
from .serializers import PatientAccountSerializer
from rest_framework.permissions import AllowAny

class PatientRegistrationAPIView(generics.CreateAPIView):
    """
    Handles patient registration with improved validation error responses.
    """
    queryset = PatientAccount.objects.all()
    serializer_class = PatientAccountSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            self.perform_create(serializer)
            return Response(
                {"message": "Registration successful!"},
                status=status.HTTP_201_CREATED
            )
        
        # Handle validation errors explicitly
        error_response = {}
        for field, errors in serializer.errors.items():
            error_response[field] = errors[0] if isinstance(errors, list) else errors
        
        return Response(
            {"errors": error_response},
            status=status.HTTP_400_BAD_REQUEST
        )


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.sessions.models import Session
from .forms import PatientLoginForm
from .models import PatientAccount
from django.contrib.auth import authenticate


def patient_login(request):
    if request.method == 'POST':
        form = PatientLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            patient = authenticate(request, email=email, password=password)
            if patient:
                # Set session for the authenticated patient
                request.session['patient_id'] = patient.id
                request.session['patient_email'] = patient.email
                return redirect('patient_dashboard')
            else:
                # Add non-field error
                form.add_error(None, "Invalid email or password.")
    else:
        form = PatientLoginForm()

    return render(request, 'patients/patient_login.html', {'form': form})


def patient_dashboard(request):
    if not request.session.get('patient_id'):
        return redirect('patient_login')

    patient_id = request.session.get('patient_id')
    try:
        patient = PatientAccount.objects.get(id=patient_id)
        medical_records = MedicalRecord.objects.filter(patient=patient).order_by('-date_time')
    except PatientAccount.DoesNotExist:
        messages.error(request, 'Session expired. Please log in again.')
        return redirect('patient_login')
    
    return render(request, 'patients/patient_dashboard.html', {'patient': patient, 'medical_records': medical_records})


# my_app/views.py

from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from kiosk.models import Ticket
from .serializers import AppointmentSerializer

class AppointmentCreateAPIView(generics.CreateAPIView):
    queryset = Ticket.objects.all()
    serializer_class = AppointmentSerializer

    def perform_create(self, serializer):
        serializer.save(
            ticket_type='APPOINTMENT',
            transaction_time=timezone.now()
        )

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
from rest_framework.generics import ListAPIView
from .models import PatientAccount
from .serializers import PatientAccountListSerializer

class PatientAccountListView(ListAPIView):
    queryset = PatientAccount.objects.all()
    serializer_class = PatientAccountListSerializer

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import PatientAccount

@api_view(['POST'])
def validate_patient_account(request):
    """
    Validate if a patient's details or contact number already exist.
    """
    first_name = request.data.get('first_name')
    last_name = request.data.get('last_name')
    date_of_birth = request.data.get('date_of_birth')
    age = request.data.get('age')
    contact_number = request.data.get('contact_number')

    # Check if there's an exact match for the patient details (excluding contact_number)
    matching_records = PatientAccount.objects.filter(
        first_name=first_name,
        last_name=last_name,
        date_of_birth=date_of_birth,
        age=age
    )

    if matching_records.exists():
        for record in matching_records:
            if record.contact_number == contact_number:
                # Exact match, allow to proceed
                return Response({"message": "Validation successful."}, status=status.HTTP_200_OK)
        
        # Check if the contact_number exists globally (excluding matching records)
        global_conflict = PatientAccount.objects.exclude(id__in=matching_records.values_list('id', flat=True)) \
                                                .filter(contact_number=contact_number).exists()
        if global_conflict:
            return Response({"message": "Contact number already exists for another patient."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Details match, but contact_number is unique
        return Response({"message": "Patient exists, but contact number is different."}, status=status.HTTP_200_OK)

    # Global check for contact_number uniqueness
    if PatientAccount.objects.filter(contact_number=contact_number).exists():
        return Response({"message": "Contact number already exists."}, status=status.HTTP_400_BAD_REQUEST)

    return Response({"message": "Validation successful."}, status=status.HTTP_200_OK)



from rest_framework import status, generics
from rest_framework.response import Response
from .models import PatientAccount
from .serializers import PatientAccountListSerializer

class ValidateEmailView(generics.GenericAPIView):
    """
    API endpoint to validate email duplication.
    """
    serializer_class = PatientAccountListSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')

        if not email:
            return Response({'message': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        if PatientAccount.objects.filter(email=email).exists():
            return Response({'message': 'Email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'message': 'Email is valid and available.'}, status=status.HTTP_200_OK)

