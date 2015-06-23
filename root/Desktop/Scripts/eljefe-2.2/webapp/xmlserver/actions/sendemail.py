from lib.cuckoo.core.database import Database
from django.core.mail import send_mail
from ElJefeUtils import ActionTemplate


class Action(ActionTemplate):
    NAME = "Send Email"
    DESCRIPTION = "Send email alert"

    def Act(self, event, flt):
        """
        username = models.CharField(max_length=64)
        event_timestamp = models.DateTimeField()
        binary = models.ForeignKey(binaries,related_name='bin')
        parent_binary = models.ForeignKey(binaries,related_name='parent_bin')
        station = models.ForeignKey(stations,related_name="stations_id")
        """
        filter_fields = flt._meta.get_all_field_names()
        filter_fields.remove('id')
        filter_fields.remove('actions')
        field_data = ""
        for field in filter_fields:
            field_data += '%s: %s \n' % (field, str(getattr(flt, field)))

        data = {}
        data['username'] = event.username
        data['ip'] = event.station.ip_address
        data['station'] = event.station.hostname
        data['binary'] = event.binary.file_path
        data['parent_binary'] = event.parent_binary.file_path
        data['date'] = event.event_timestamp
        data['filter'] = flt
        data['filter_data'] = field_data


        body = """
        The following filter has been triggered:

        Filter: %(filter)s
        Data: %(filter_data)s

        Event Information:

        Username: %(username)s
        Station:  %(station)s
        Binary:   %(binary)s
        Parent binary: %(parent_binary)s
        Date: %(date)s
        """
        send_mail('El Jefe - Alert',
                  body % data,
                  'alert@eljefe.immunityinc.com',
                  ['admin@immunityinc.com'],
                  fail_silently=False)


