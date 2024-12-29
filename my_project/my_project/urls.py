"""
URL configuration for my_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView  # Add this import
from my_app.views import home

urlpatterns = [
    path('admin/', admin.site.urls),  # Django's built-in admin
    path('my_app/super-admin/', include('my_app.urls')),  # Your custom super admin
    path('my_app/', include('my_app.urls')),  # Include my_app URLs
    path('kiosk/', include('kiosk.urls')),  # New standalone kiosk app
    path('', home, name='home'),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    #path('admin/', admin.site.urls),
    #path('super-admin/', include('superadmin.urls')),  # Custom super admin interface
    #path('my_app/', include('my_app.urls')),  # Include app URLs
#]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


