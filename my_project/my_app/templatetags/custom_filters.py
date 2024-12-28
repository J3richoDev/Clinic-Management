from django import template
from django.utils.timezone import now
from datetime import datetime,date

register = template.Library()

@register.filter
def replace_underscore(value):
    """Replaces underscores with spaces in the given string."""
    return value.replace('_', ' ')

@register.filter
def get_item(value, key):
    """Retrieve an item from a list by key."""
    for item in value:
        if item.id == int(key):
            return item
    return None

@register.filter
def is_overdue(end_date):
    try:
        # If the input is already a date object, use it directly
        if isinstance(end_date, date):
            end_date_obj = end_date
        else:
            # Parse the string into a date object
            end_date_obj = datetime.strptime(end_date, "%b. %d, %Y").date()

        # Compare with today's date
        return end_date_obj < now().date()
    except (ValueError, TypeError):
        # Return False if parsing fails or input is invalid
        return False

@register.filter
def is_image(file_name):
    """Check if a file name corresponds to an image format."""
    return file_name.lower().endswith(('.jpg', '.jpeg', '.png'))