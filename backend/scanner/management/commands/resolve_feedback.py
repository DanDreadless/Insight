"""
Mark one or more ScanFeedback records as resolved.

Resolved records are excluded from future export_feedback runs and
are removed from backend/feedback/cases.json if it exists.

Usage:
    python manage.py resolve_feedback 3 7 12
    python manage.py resolve_feedback --all   # resolve everything pending
"""
import json
import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from scanner.models import ScanFeedback


class Command(BaseCommand):
    help = 'Mark ScanFeedback records as resolved and remove from cases.json'

    def add_arguments(self, parser):
        parser.add_argument(
            'ids',
            nargs='*',
            type=int,
            help='IDs of ScanFeedback records to resolve',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Resolve all unresolved feedback records',
        )

    def handle(self, *args, **options):
        if not options['ids'] and not options['all']:
            raise CommandError('Provide at least one ID, or --all to resolve everything.')

        if options['all']:
            updated = ScanFeedback.objects.filter(resolved=False).update(resolved=True)
            self.stdout.write(self.style.SUCCESS(f'Resolved all {updated} pending feedback record(s).'))
        else:
            ids = options['ids']
            found = ScanFeedback.objects.filter(pk__in=ids)
            if not found.exists():
                raise CommandError(f'No ScanFeedback records found for IDs: {ids}')
            updated = found.update(resolved=True)
            self.stdout.write(self.style.SUCCESS(f'Resolved {updated} feedback record(s): {ids}'))

        # Update cases.json in-place if it exists — remove resolved entries
        cases_path = os.path.join(settings.BASE_DIR, 'feedback', 'cases.json')
        if os.path.exists(cases_path):
            with open(cases_path, 'r', encoding='utf-8') as f:
                cases = json.load(f)

            resolved_ids = set(
                ScanFeedback.objects.filter(resolved=True).values_list('pk', flat=True)
            )
            remaining = [c for c in cases if c['id'] not in resolved_ids]
            removed = len(cases) - len(remaining)

            with open(cases_path, 'w', encoding='utf-8') as f:
                json.dump(remaining, f, indent=2, ensure_ascii=False)

            if removed:
                self.stdout.write(f'Removed {removed} resolved case(s) from {cases_path}')
