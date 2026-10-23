"""The shared DNS text encoder serves both full files and records-only imports."""
from pathlib import Path
import sys
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import zonefile


class ZoneFileTests(TestCase):
    def test_txt_quotes_backslashes_and_line_breaks_stay_inside_one_record(self):
        """Keep TXT quotes, backslashes and line breaks in one record line."""
        record = {"name": "txt", "type": "TXT", "value": 'quote"slash\\line\nnext\r'}
        expected = 'txt 3600 IN TXT "quote\\"slash\\\\line\\010next\\013"'
        self.assertEqual(zonefile.build_record_line(record), expected)
        rendered = zonefile.build_zone_file("bench.example", 2, [record])
        self.assertEqual(rendered.splitlines()[-1], expected)

    def test_mail_and_alias_targets_are_absolute_and_priority_is_retained(self):
        """Render absolute MX/CNAME targets while retaining MX priority."""
        for value in ("mail.example", "mail.example."):
            self.assertEqual(zonefile.build_record_data(
                {"type": "MX", "value": value, "priority": 20}), "20 mail.example.")
            self.assertEqual(zonefile.build_record_data(
                {"type": "CNAME", "value": value}), "mail.example.")
