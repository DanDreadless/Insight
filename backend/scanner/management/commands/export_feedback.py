"""
Export unresolved ScanFeedback records to backend/feedback/cases.json.

Usage:
    python manage.py export_feedback
    python manage.py export_feedback --all   # include already-resolved cases
"""
import json
import os

from django.conf import settings
from django.core.management.base import BaseCommand

from scanner.models import ScanFeedback


class Command(BaseCommand):
    help = 'Export feedback cases to backend/feedback/cases.json for detection engineering'

    def add_arguments(self, parser):
        parser.add_argument(
            '--all',
            action='store_true',
            help='Include cases already marked as resolved',
        )

    def handle(self, *args, **options):
        qs = ScanFeedback.objects.all() if options['all'] else ScanFeedback.objects.filter(resolved=False)

        cases = []
        for fb in qs.order_by('submitted_at'):
            cases.append({
                'id': fb.pk,
                'url': fb.url,
                'scan_id': str(fb.scan_id) if fb.scan_id else None,
                'submitted_at': fb.submitted_at.isoformat(),
                'reason': fb.reason,
                'note': fb.note,
                'actual_verdict': fb.actual_verdict,
                # null until the developer reviews and sets the expected outcome
                'expected_verdict': fb.expected_verdict or None,
                'resolved': fb.resolved,
                'findings': fb.findings_snapshot,
            })

        out_dir = os.path.join(settings.BASE_DIR, 'feedback')
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, 'cases.json')

        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(cases, f, indent=2, ensure_ascii=False)

        needs_review = sum(1 for c in cases if not c['expected_verdict'])
        ready = len(cases) - needs_review

        self.stdout.write(self.style.SUCCESS(
            f'Exported {len(cases)} case(s) to {out_path}'
        ))
        if needs_review:
            self.stdout.write(self.style.WARNING(
                f'  {needs_review} case(s) need expected_verdict set before testing'
            ))
        if ready:
            self.stdout.write(
                f'  {ready} case(s) ready to test (expected_verdict set)'
            )
