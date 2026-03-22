from django.urls import path
from .views import HealthCheckView, ScanHistoryView, ScanSubmitView, ScanStatusView, ScanStreamView, ScanSourceView

urlpatterns = [
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('history/', ScanHistoryView.as_view(), name='scan-history'),
    path('scan/', ScanSubmitView.as_view(), name='scan-submit'),
    path('scan/<str:scan_id>/', ScanStatusView.as_view(), name='scan-status'),
    path('scan/<str:scan_id>/stream/', ScanStreamView.as_view(), name='scan-stream'),
    path('scan/<str:scan_id>/source/', ScanSourceView.as_view(), name='scan-source'),
]
