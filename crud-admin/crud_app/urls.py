from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('api/collection/', views.CollectionView.as_view()),
    path('api/download_sample_csv/', views.SampleExportView.as_view()),
    path('api/collection/<str:pk>/', views.CollectionView.as_view()),
    path('api/organization/', views.OrganizationView.as_view()),
    path('api/business/', views.BusinessView.as_view()),
    path('api/bizapp/', views.BizAppView.as_view()),
    path('api/business/<str:pk>/', views.BusinessView.as_view()),
    path('api/code_generator/', views.service_generator),
]