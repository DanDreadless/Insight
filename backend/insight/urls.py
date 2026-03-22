from django.http import HttpRequest, HttpResponse
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


def security_txt(request: HttpRequest) -> HttpResponse:
    """SEC-14: Serve /.well-known/security.txt for responsible disclosure."""
    content = (
        'Contact: security@vault1337.com\r\n'
        'Expires: 2027-01-01T00:00:00.000Z\r\n'
        'Preferred-Languages: en\r\n'
        'Canonical: https://insight.vault1337.com/.well-known/security.txt\r\n'
    )
    return HttpResponse(content, content_type='text/plain; charset=utf-8')


urlpatterns = [
    path('.well-known/security.txt', security_txt, name='security-txt'),
    path('api/', include('scanner.urls')),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
