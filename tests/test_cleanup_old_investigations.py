"""Tests for cleanup_old_investigations.py"""

import os
import time
import pytest
from unittest.mock import patch

from cleanup_old_investigations import cleanup_old_investigations, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_file(directory, filename, content="test", age_days=0):
    """Create a file and optionally backdate its modification time."""
    filepath = os.path.join(directory, filename)
    with open(filepath, "w") as f:
        f.write(content)
    if age_days > 0:
        old_time = time.time() - (age_days * 86400)
        os.utime(filepath, (old_time, old_time))
    return filepath


# ---------------------------------------------------------------------------
# Basic cleanup behaviour
# ---------------------------------------------------------------------------

class TestCleanupOldInvestigations:
    """Core cleanup logic tests."""

    def test_deletes_old_json_files(self, tmp_path):
        """Old investigation_*.json files beyond retention are deleted."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        old_file = _create_file(str(temp_dir), "investigation_user_20260101.json", age_days=45)

        deleted, freed = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"), retention_days=30
        )

        assert deleted == 1
        assert freed > 0
        assert not os.path.exists(old_file)

    def test_keeps_recent_json_files(self, tmp_path):
        """Files within the retention window are not deleted."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        recent_file = _create_file(str(temp_dir), "investigation_user_20260401.json", age_days=5)

        deleted, freed = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"), retention_days=30
        )

        assert deleted == 0
        assert freed == 0
        assert os.path.exists(recent_file)

    def test_deletes_old_html_reports(self, tmp_path):
        """Old Investigation_Report_*.html files are deleted."""
        reports_dir = tmp_path / "reports"
        user_inv = reports_dir / "user-investigations"
        user_inv.mkdir(parents=True)
        old_html = _create_file(str(user_inv), "Investigation_Report_user_20260101.html", age_days=45)

        deleted, freed = cleanup_old_investigations(
            temp_dir=str(tmp_path / "temp"), reports_dir=str(reports_dir), retention_days=30
        )

        assert deleted == 1
        assert not os.path.exists(old_html)

    def test_keeps_recent_html_reports(self, tmp_path):
        """HTML reports within retention are preserved."""
        reports_dir = tmp_path / "reports"
        user_inv = reports_dir / "user-investigations"
        user_inv.mkdir(parents=True)
        recent_html = _create_file(str(user_inv), "Investigation_Report_user_20260401.html", age_days=2)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(tmp_path / "temp"), reports_dir=str(reports_dir), retention_days=30
        )

        assert deleted == 0
        assert os.path.exists(recent_html)

    def test_mixed_old_and_recent(self, tmp_path):
        """Only old files are removed when both old and recent exist."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        old = _create_file(str(temp_dir), "investigation_old.json", age_days=60)
        recent = _create_file(str(temp_dir), "investigation_recent.json", age_days=5)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"), retention_days=30
        )

        assert deleted == 1
        assert not os.path.exists(old)
        assert os.path.exists(recent)

    def test_combined_json_and_html_cleanup(self, tmp_path):
        """Both JSON and HTML old files are counted together."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        reports_dir = tmp_path / "reports"
        user_inv = reports_dir / "user-investigations"
        user_inv.mkdir(parents=True)

        _create_file(str(temp_dir), "investigation_a.json", age_days=40)
        _create_file(str(user_inv), "Investigation_Report_a.html", age_days=40)

        deleted, freed = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(reports_dir), retention_days=30
        )

        assert deleted == 2
        assert freed > 0


# ---------------------------------------------------------------------------
# SCRUBBED files (should be skipped)
# ---------------------------------------------------------------------------

class TestScrubbedFiles:
    """SCRUBBED files are sanitized for GitHub and must never be deleted."""

    def test_skips_scrubbed_json(self, tmp_path):
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        scrubbed = _create_file(str(temp_dir), "investigation_SCRUBBED_user.json", age_days=60)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"), retention_days=30
        )

        assert deleted == 0
        assert os.path.exists(scrubbed)

    def test_skips_scrubbed_html(self, tmp_path):
        reports_dir = tmp_path / "reports"
        user_inv = reports_dir / "user-investigations"
        user_inv.mkdir(parents=True)
        scrubbed = _create_file(str(user_inv), "Investigation_Report_SCRUBBED_user.html", age_days=60)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(tmp_path / "temp"), reports_dir=str(reports_dir), retention_days=30
        )

        assert deleted == 0
        assert os.path.exists(scrubbed)


# ---------------------------------------------------------------------------
# Filename pattern filtering
# ---------------------------------------------------------------------------

class TestFilenameFiltering:
    """Only files matching the expected naming patterns are considered."""

    def test_ignores_non_investigation_json(self, tmp_path):
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        other = _create_file(str(temp_dir), "config.json", age_days=60)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"), retention_days=30
        )

        assert deleted == 0
        assert os.path.exists(other)

    def test_ignores_non_report_html(self, tmp_path):
        reports_dir = tmp_path / "reports"
        user_inv = reports_dir / "user-investigations"
        user_inv.mkdir(parents=True)
        other = _create_file(str(user_inv), "dashboard.html", age_days=60)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(tmp_path / "temp"), reports_dir=str(reports_dir), retention_days=30
        )

        assert deleted == 0
        assert os.path.exists(other)

    def test_ignores_non_json_investigation_files(self, tmp_path):
        """A file named investigation_*.txt should not be picked up."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        txt_file = _create_file(str(temp_dir), "investigation_user.txt", age_days=60)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"), retention_days=30
        )

        assert deleted == 0
        assert os.path.exists(txt_file)


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------

class TestDryRun:
    """Dry run should report but not delete."""

    def test_dry_run_does_not_delete(self, tmp_path):
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        old_file = _create_file(str(temp_dir), "investigation_dry.json", age_days=60)

        deleted, freed = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"),
            retention_days=30, dry_run=True
        )

        assert deleted == 1
        assert freed > 0
        # File must still exist
        assert os.path.exists(old_file)

    def test_dry_run_output(self, tmp_path, capsys):
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        _create_file(str(temp_dir), "investigation_dry.json", age_days=60)

        cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"),
            retention_days=30, dry_run=True
        )

        captured = capsys.readouterr()
        assert "[DRY RUN]" in captured.out
        assert "Would delete" in captured.out


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases: missing dirs, empty dirs, permission errors."""

    def test_missing_temp_dir(self, tmp_path):
        """Non-existent temp directory should not raise."""
        deleted, freed = cleanup_old_investigations(
            temp_dir=str(tmp_path / "nonexistent"),
            reports_dir=str(tmp_path / "also_nonexistent"),
            retention_days=30
        )

        assert deleted == 0
        assert freed == 0

    def test_empty_directories(self, tmp_path):
        """Empty directories produce zero deletes."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        reports_dir = tmp_path / "reports"
        user_inv = reports_dir / "user-investigations"
        user_inv.mkdir(parents=True)

        deleted, freed = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(reports_dir), retention_days=30
        )

        assert deleted == 0
        assert freed == 0

    def test_permission_error_continues(self, tmp_path, capsys):
        """If os.remove raises, the error is logged and processing continues."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        _create_file(str(temp_dir), "investigation_perm.json", age_days=60)
        _create_file(str(temp_dir), "investigation_ok.json", age_days=60)

        with patch("cleanup_old_investigations.os.path.getmtime", side_effect=PermissionError("denied")):
            deleted, _ = cleanup_old_investigations(
                temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"),
                retention_days=30
            )

        captured = capsys.readouterr()
        assert "Error processing" in captured.out

    def test_retention_one_day(self, tmp_path):
        """Retention of 1 day should delete files older than 1 day."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        _create_file(str(temp_dir), "investigation_a.json", age_days=2)

        deleted, _ = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"),
            retention_days=1
        )

        assert deleted == 1

    def test_space_freed_is_accurate(self, tmp_path):
        """Space freed should equal the sum of deleted file sizes."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        content = "x" * 1024  # 1 KB
        _create_file(str(temp_dir), "investigation_a.json", content=content, age_days=60)
        _create_file(str(temp_dir), "investigation_b.json", content=content, age_days=60)

        _, freed = cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"),
            retention_days=30
        )

        assert freed == 2048  # 2 x 1024

    def test_no_files_message(self, tmp_path, capsys):
        """When no files need deletion, a friendly message is printed."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()

        cleanup_old_investigations(
            temp_dir=str(temp_dir), reports_dir=str(tmp_path / "reports"),
            retention_days=30
        )

        captured = capsys.readouterr()
        assert "No files to delete" in captured.out


# ---------------------------------------------------------------------------
# CLI / main() tests
# ---------------------------------------------------------------------------

class TestMain:
    """Test the argparse-based main() entry point."""

    def test_main_dry_run(self, tmp_path):
        """main() passes --dry-run correctly."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        _create_file(str(temp_dir), "investigation_cli.json", age_days=60)

        with patch(
            "sys.argv",
            ["cleanup_old_investigations.py", "--dry-run", "--temp-dir", str(temp_dir),
             "--reports-dir", str(tmp_path / "reports")]
        ):
            main()

        # File should still exist because dry-run
        assert os.path.exists(str(temp_dir / "investigation_cli.json"))

    def test_main_custom_days(self, tmp_path):
        """main() respects --days flag."""
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        _create_file(str(temp_dir), "investigation_days.json", age_days=10)

        with patch(
            "sys.argv",
            ["cleanup_old_investigations.py", "--days", "7", "--temp-dir", str(temp_dir),
             "--reports-dir", str(tmp_path / "reports")]
        ):
            main()

        assert not os.path.exists(str(temp_dir / "investigation_days.json"))

    def test_main_invalid_days(self, capsys):
        """main() rejects --days 0."""
        with patch("sys.argv", ["cleanup_old_investigations.py", "--days", "0"]):
            main()

        captured = capsys.readouterr()
        assert "at least 1 day" in captured.out
