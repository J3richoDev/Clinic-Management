from django.contrib import admin
from .models import CustomUser
from django.utils.crypto import get_random_string

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    # Display fields in the admin list view
    list_display = ('email', 'role', 'is_staff', 'is_active')  # Use 'email' for display
    list_filter = ('role', 'is_staff', 'is_active')  # Add filtering options in the admin
    search_fields = ('email', 'first_name', 'last_name', 'role')  # Add search functionality

    # Fields editable in the admin form
    fields = ('email', 'first_name', 'last_name', 'middle_name', 'role', 'is_staff', 'is_active', 'profile_picture')  # Editable fields in the form

    def save_model(self, request, obj, form, change):
        """
        Override save_model to handle temporary password generation
        and email assignment for new users.
        """
        if not obj.pk:  # If it's a new object
            if not obj.is_superuser:  # Ensure this logic does not affect superusers
                # Generate a temporary password
                temp_password = get_random_string(8)
                obj.set_password(temp_password)

                # Generate email based on first name, last name, and middle name
                if obj.first_name and obj.last_name:
                    middle_initial = f"{obj.middle_name[0].lower()}" if obj.middle_name else ""
                    obj.email = f"{obj.first_name.lower()}.{obj.last_name.lower()}.{middle_initial}@buslu.edu.ph".strip(".")
                else:
                    obj.email = f"user{CustomUser.objects.count() + 1}@buslu.edu.ph"  # Fallback email

        super().save_model(request, obj, form, change)

    def password_display(self, obj):
        """
        Display the temporary password for new users in the admin interface.
        Mask passwords if they have already been changed.
        """
        if not obj.password_changed and not obj.is_superuser:
            return "Temporary Password Set"
        return "********"  # Mask the password for security reasons

    password_display.short_description = "Password Status"

    def get_queryset(self, request):
        """
        Exclude superusers from the queryset for non-superuser admin users.
        """
        queryset = super().get_queryset(request)
        if not request.user.is_superuser:
            queryset = queryset.exclude(is_superuser=True)  # Hide superusers from regular admins
        return queryset
