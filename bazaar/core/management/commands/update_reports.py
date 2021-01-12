from django.core.management.base import BaseCommand, CommandError

from bazaar.core.tasks import *


class Command(BaseCommand):
    help = 'Update existing reports'

    def add_arguments(self, parser):
        parser.add_argument('hash', nargs=1, type=str)
        parser.add_argument('tasks', nargs=1, type=str)

    def handle(self, *args, **options):
        sha256 = options['hash'][0]
        tasks = options['tasks']

        if 'm' in tasks:
            print(f'Start mobsf_analysis for {sha256}')
            async_task(mobsf_analysis, sha256)
        if 'b' in tasks:
            print(f'Start malware_bazaar_analysis for {sha256}')
            malware_bazaar_analysis(sha256)
        if 'a' in tasks:
            print(f'Start apkid_analysis for {sha256}')
            async_task(apkid_analysis, sha256)
        if 's' in tasks:
            print(f'Start ssdeep_analysis for {sha256}')
            async_task(ssdeep_analysis, sha256)
        if 'c' in tasks:
            print(f'Start extract_classes for {sha256}')
            async_task(extract_classes, sha256)
        if 'q' in tasks:
            print(f'Start quark_analysis for {sha256}')
            async_task(quark_analysis, sha256)

        # for poll_id in options['poll_ids']:
        #     try:
        #         poll = Poll.objects.get(pk=poll_id)
        #     except Poll.DoesNotExist:
        #         raise CommandError('Poll "%s" does not exist' % poll_id)
        #
        #     poll.opened = False
        #     poll.save()
        #
        #     self.stdout.write(self.style.SUCCESS('Successfully closed poll "%s"' % poll_id))
