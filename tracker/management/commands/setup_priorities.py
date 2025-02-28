from django.core.management.base import BaseCommand
from tracker.models import Priority

class Command(BaseCommand):
    help = 'Setup default ticket priorities'

    def handle(self, *args, **kwargs):
        priorities = [
            {'name': 'Low', 'color': 'success'},
            {'name': 'Medium', 'color': 'warning'},
            {'name': 'High', 'color': 'danger'},
            {'name': 'Critical', 'color': 'dark'}
        ]

        for priority in priorities:
            Priority.objects.get_or_create(
                name=priority['name'],
                defaults={'color': priority['color']}
            )
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created priority "{priority["name"]}"')
            )