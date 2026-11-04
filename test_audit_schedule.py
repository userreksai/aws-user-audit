"""Beijing schedule boundaries and configurable closed daily report windows."""
from datetime import datetime, time, timedelta, timezone
import unittest
from zoneinfo import ZoneInfo

from audit_schedule import latest_report_date, parse_clock
from aws_daily_audit import resolve_window


class ScheduleClockTests(unittest.TestCase):
    def test_hhmm_clock_accepts_minute_precision_and_midnight(self):
        self.assertEqual(parse_clock("10:05"), time(10, 5))
        self.assertEqual(parse_clock("00:00"), time(0))
        self.assertEqual(parse_clock("23:59"), time(23, 59))

    def test_bad_clock_values_cannot_be_silently_coerced(self):
        for value in ("10:5", "1:05", "24:00", "10:60", "10:05:00", "10：05",
                      " 10:05", "10:05\n", "1٣:05", "10:0５", "", None, True, 1005):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_clock(value, "DAILY_MAIL_TIME")

    def test_latest_report_uses_configured_end_before_at_and_after_boundary(self):
        for now, expected in (
            (datetime(2026, 11, 4, 1, 59, 59, tzinfo=timezone.utc), "2026-11-03"),
            (datetime(2026, 11, 4, 2, 0, tzinfo=timezone.utc), "2026-11-04"),
            (datetime(2026, 11, 4, 2, 5, tzinfo=timezone.utc), "2026-11-04"),
        ):
            with self.subTest(now=now):
                self.assertEqual(latest_report_date(now), expected)

    def test_latest_report_uses_beijing_instead_of_host_or_input_zone(self):
        now = datetime(2026, 11, 3, 18, 5, tzinfo=ZoneInfo("America/Los_Angeles"))
        self.assertEqual(latest_report_date(now), "2026-11-04")
        before = datetime(2027, 1, 1, 1, 59, tzinfo=timezone.utc)
        self.assertEqual(latest_report_date(before), "2026-12-31")

    def test_midnight_and_custom_end_minute_define_latest_finished_report(self):
        now = datetime(2026, 11, 3, 16, 0, tzinfo=timezone.utc)
        self.assertEqual(latest_report_date(now, end_time="00:00"), "2026-11-04")
        at_1004 = datetime(2026, 11, 4, 2, 4, tzinfo=timezone.utc)
        self.assertEqual(latest_report_date(at_1004, end_time="10:05"), "2026-11-03")
        self.assertEqual(latest_report_date(at_1004 + timedelta(minutes=1), end_time="10:05"), "2026-11-04")

    def test_naive_time_and_invalid_window_end_fail(self):
        with self.assertRaises(ValueError):
            latest_report_date(datetime(2026, 11, 4, 10, 5))
        with self.assertRaises(ValueError):
            latest_report_date(datetime(2026, 11, 4, 2, 5, tzinfo=timezone.utc), end_time="25:00")


class ConfiguredDailyWindowTests(unittest.TestCase):
    now = datetime(2026, 11, 4, 2, 5, tzinfo=timezone.utc)

    def window(self, day="2026-11-04", *, start="10:00", end="10:00", now=None):
        return resolve_window(day, "Asia/Shanghai", now=now or self.now, daily=True,
                              daily_start=start, daily_end=end)

    def test_requested_1000_to_1000_is_exactly_24_hours(self):
        day, start, end, partial = self.window()
        self.assertEqual(day, "2026-11-04")
        self.assertEqual(start, datetime(2026, 11, 3, 2, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 11, 4, 2, tzinfo=timezone.utc))
        self.assertEqual(end - start, timedelta(days=1))
        self.assertFalse(partial)

    def test_adjacent_24_hour_reports_share_only_the_boundary(self):
        _, _, earlier_end, _ = self.window("2026-11-03")
        _, later_start, _, _ = self.window("2026-11-04")
        self.assertEqual(earlier_end, later_start)

    def test_arbitrary_minutes_and_midnight_have_actual_configured_bounds(self):
        _, start, end, _ = self.window(start="06:17", end="06:23")
        self.assertEqual(start, datetime(2026, 11, 2, 22, 17, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 11, 3, 22, 23, tzinfo=timezone.utc))
        self.assertEqual(end - start, timedelta(days=1, minutes=6))
        _, start, end, _ = self.window(start="00:00", end="00:00")
        self.assertEqual(start, datetime(2026, 11, 2, 16, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 11, 3, 16, tzinfo=timezone.utc))

    def test_cross_year_dates_do_not_use_string_or_host_date_math(self):
        day, start, end, partial = self.window("2027-01-01", now=datetime(2027, 1, 1, 2, 5, tzinfo=timezone.utc))
        self.assertEqual(day, "2027-01-01")
        self.assertEqual(start, datetime(2026, 12, 31, 2, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2027, 1, 1, 2, tzinfo=timezone.utc))
        self.assertFalse(partial)

    def test_unfinished_report_is_rejected_without_shortening_to_current_time(self):
        with self.assertRaises(ValueError):
            self.window(now=datetime(2026, 11, 4, 1, 59, 59, tzinfo=timezone.utc))
        with self.assertRaises(ValueError):
            self.window("2026-11-05")

    def test_old_single_account_default_retains_25_hour_compatibility(self):
        _, start, end, _ = resolve_window("2026-11-04", "Asia/Shanghai", now=self.now, daily=True)
        self.assertEqual(end - start, timedelta(hours=25))
        self.assertEqual(start, datetime(2026, 11, 2, 23, tzinfo=timezone.utc))
        self.assertEqual(end, datetime(2026, 11, 4, 0, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
