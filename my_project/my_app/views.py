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
from .forms import ProfileForm, CustomPasswordChangeForm, PatientForm, MedicalRecordForm
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
            middle_initials = ''.join([word[0].lower() for word in middle_name.split() if word])

            # Base Email Template
            base_email = (
                f"{first_name.lower().replace(' ', '')}."
                f"{last_name.lower().replace(' ', '')}."
                f"{middle_initials}@buslu.edu.ph"
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
    pending_appointments = Ticket.objects.filter(transaction_group=user.role.upper(), scheduled_time__date=today, checked_in=False).count()
    current_queue_status = Ticket.objects.filter(transaction_group=user.role.upper(), scheduled_time__date=today, checked_in=False).count()

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

    return render(request, 'patients/edit_acc.html', {'form': form})

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
    # Determine the transaction group based on the user's role
    if request.user.role in ['nurse', 'dentist', 'physician']:
        transaction_group = request.user.role.upper()
    else:
        return HttpResponseForbidden("You are not authorized to access this page.")

    current_date = localtime(now()).date()

    # Fetch tickets for the user's transaction group
    tickets = Ticket.objects.filter(
        transaction_group=transaction_group,
        checked_in=False,
        scheduled_time__date=current_date
    ).order_by(
        '-special_tag',  # Higher priority (PWD/Senior Citizen) first
        'scheduled_time'  # Oldest first
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
        ticket.transaction_time_local = localtime(ticket.scheduled_time)

        # Optional: Truncate details for "Other" transaction types
        if ticket.transaction_type == "Other" and ticket.details:
            ticket.truncated_details = ticket.details[:15] + "..."  # Show first 15 characters with "..."
        else:
            ticket.truncated_details = ticket.get_transaction_type_display()

    return render(request, 'staff/queue.html', {'tickets': tickets})

@login_required
def queue_display(request):
    # Fetch tickets currently being served and next in line
    if request.user.role in ['nurse', 'dentist', 'physician']:
        transaction_group = request.user.role.upper()
    else:
        return HttpResponseForbidden("You are not authorized to access this page.")

    current_date = localtime(now()).date()

    # Fetch tickets for the user's transaction group
    tickets = Ticket.objects.filter(
        transaction_group=transaction_group,
        checked_in=False,
        scheduled_time__date=current_date
    ).order_by(
        '-special_tag',  # Higher priority (PWD/Senior Citizen) first
        'scheduled_time'  # Oldest first
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
        ticket.transaction_time_local = localtime(ticket.scheduled_time)

        # Optional: Truncate details for "Other" transaction types
        if ticket.transaction_type == "Other" and ticket.details:
            ticket.truncated_details = ticket.details[:15] + "..."  # Show first 15 characters with "..."
        else:
            ticket.truncated_details = ticket.get_transaction_type_display()

    return render(request, 'staff/queue_display.html', {'tickets': tickets})

@login_required
def next_patient(request):
    # Determine the transaction group based on the user's role
    if request.user.role in ['nurse', 'dentist', 'physician']:
        transaction_group = request.user.role.upper()
    else:
        return HttpResponseForbidden("You are not authorized to perform this action.")

    # Fetch the queue for this transaction group
    tickets = Ticket.objects.filter(
        transaction_group=transaction_group,
        checked_in=False
    ).order_by(
        '-special_tag',  # Higher priority (PWD/Senior Citizen) first
        'scheduled_time'  # Oldest first
    )

    if tickets.exists():
        # Mark the current "Being Served" ticket as checked-in
        current_ticket = tickets.first()
        current_ticket.checked_in = True
        current_ticket.checked_in_time = now()
        current_ticket.save()

        # Logically, the next ticket in the queue will become "Being Served"
        next_ticket = tickets[1] if len(tickets) > 1 else None
        if next_ticket:
            next_ticket.label = "Being Served"

    return redirect('queue')

# Reusable helper function for dashboard logic
def render_staff_home(request, template_name, transaction_group):
    # Real-time statistics
    total_patients = PatientAccount.objects.count()
    today_appointments = Ticket.objects.filter(
        scheduled_time__date=now().date(),
        transaction_group=transaction_group
    ).count()

    # Patient demographics
    patient_roles = PatientAccount.objects.values('role').annotate(total=Count('id'))

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
from .serializers import PatientAccountSerializer

class PatientAccountListView(ListAPIView):
    """
    API endpoint to list all PatientAccounts.
    """
    queryset = PatientAccount.objects.all()
    serializer_class = PatientAccountSerializer


class ValidatePatientDataView(APIView):
    """
    Validate duplicate email and contact number.
    """
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        contact_number = request.data.get('contact_number')

        errors = {}

        if email and PatientAccount.objects.filter(email=email).exists():
            errors['email'] = "This email is already in use."

        if contact_number and PatientAccount.objects.filter(contact_number=contact_number).exists():
            errors['contact_number'] = "This contact number is already in use."

        if errors:
            return Response({'errors': errors}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Data is valid."}, status=status.HTTP_200_OK)