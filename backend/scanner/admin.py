from django.contrib import admin
from .models import ScanFeedback, ScanJob, Finding


@admin.register(ScanFeedback)
class ScanFeedbackAdmin(admin.ModelAdmin):
    list_display = ('id', 'url_truncated', 'reason', 'actual_verdict', 'expected_verdict', 'resolved', 'submitted_at')
    list_filter = ('reason', 'actual_verdict', 'resolved')
    search_fields = ('url', 'note')
    readonly_fields = ('scan', 'url', 'submitted_at', 'actual_verdict', 'findings_snapshot', 'submitter_ip')
    ordering = ('-submitted_at',)
    actions = ['mark_resolved']

    @admin.display(description='URL')
    def url_truncated(self, obj):
        return obj.url[:80] + '…' if len(obj.url) > 80 else obj.url

    @admin.action(description='Mark selected as resolved')
    def mark_resolved(self, request, queryset):
        updated = queryset.update(resolved=True)
        self.message_user(request, f'{updated} feedback record(s) marked as resolved.')


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ('id', 'url_truncated', 'status', 'verdict', 'created_at')
    list_filter = ('status', 'verdict')
    search_fields = ('url',)
    readonly_fields = ('id', 'created_at', 'completed_at', 'submitter_ip', 'content_hash')

    @admin.display(description='URL')
    def url_truncated(self, obj):
        return obj.url[:80] + '…' if len(obj.url) > 80 else obj.url


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ('severity', 'category', 'title', 'scan')
    list_filter = ('severity', 'category')
    search_fields = ('title', 'description')
