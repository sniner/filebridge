"""Tests for filebridge models, specifically Metadata mtime conversion."""

from datetime import datetime, timedelta, timezone

from filebridge.models import Metadata, ListResponse


class TestMetadataMtimeConversion:
    """Test mtime field conversion from string to datetime."""

    def test_mtime_iso8601_z_suffix(self):
        """Test parsing ISO8601 with Z suffix (UTC)."""
        metadata = Metadata.model_validate({
            "name": "test.txt",
            "is_dir": False,
            "mtime": "2024-01-15T14:30:00Z",
        })
        assert metadata.mtime is not None
        assert isinstance(metadata.mtime, datetime)
        assert metadata.mtime.year == 2024
        assert metadata.mtime.month == 1
        assert metadata.mtime.day == 15
        assert metadata.mtime.hour == 14
        assert metadata.mtime.minute == 30
        assert metadata.mtime.second == 0
        assert metadata.mtime.tzinfo == timezone.utc

    def test_mtime_iso8601_with_timezone(self):
        """Test parsing ISO8601 with explicit timezone."""
        metadata = Metadata.model_validate({
            "name": "test.txt",
            "is_dir": False,
            "mtime": "2024-01-15T14:30:00+00:00",
        })
        assert metadata.mtime is not None
        assert isinstance(metadata.mtime, datetime)
        assert metadata.mtime.tzinfo == timezone.utc

    def test_mtime_none(self):
        """Test handling None mtime value."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mtime=None
        )
        assert metadata.mtime is None

    def test_mtime_missing(self):
        """Test handling missing mtime field."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False
        )
        assert metadata.mtime is None

    def test_mtime_invalid_string(self):
        """Test handling invalid mtime string."""
        metadata = Metadata.model_validate({
            "name": "test.txt",
            "is_dir": False,
            "mtime": "invalid-date-string",
        })
        # Should return None for invalid strings rather than raising
        assert metadata.mtime is None

    def test_mtime_already_datetime(self):
        """Test that existing datetime objects are preserved."""
        test_datetime = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mtime=test_datetime
        )
        assert metadata.mtime == test_datetime

    def test_mtime_with_microseconds(self):
        """Test parsing ISO8601 with microseconds."""
        metadata = Metadata.model_validate({
            "name": "test.txt",
            "is_dir": False,
            "mtime": "2024-01-15T14:30:00.123456Z",
        })
        assert metadata.mtime is not None
        assert metadata.mtime.microsecond == 123456

    def test_mtime_different_timezones(self):
        """Test parsing ISO8601 with different timezone offsets."""
        # Test CET timezone (+01:00)
        metadata_cet = Metadata.model_validate({
            "name": "test.txt",
            "is_dir": False,
            "mtime": "2024-01-15T14:30:00+01:00",
        })
        assert metadata_cet.mtime is not None
        assert metadata_cet.mtime.utcoffset() == timedelta(hours=1)

        # Test EST timezone (-05:00)
        metadata_est = Metadata.model_validate({
            "name": "test.txt",
            "is_dir": False,
            "mtime": "2024-01-15T14:30:00-05:00",
        })
        assert metadata_est.mtime is not None
        assert metadata_est.mtime.utcoffset() == timedelta(hours=-5)

        # Verify timezone preservation
        utc_cet = metadata_cet.mtime.astimezone(timezone.utc)
        utc_est = metadata_est.mtime.astimezone(timezone.utc)

        # CET 14:30 should be UTC 13:30
        assert utc_cet.hour == 13
        assert utc_cet.minute == 30

        # EST 14:30 should be UTC 19:30
        assert utc_est.hour == 19
        assert utc_est.minute == 30


class TestListResponseWithMetadata:
    """Test ListResponse containing Metadata with mtime conversion."""

    def test_list_response_with_mtimes(self):
        """Test ListResponse properly converts mtime in all items."""
        response = ListResponse.model_validate({
            "items": [
                {
                    "name": "file1.txt",
                    "is_dir": False,
                    "size": 100,
                    "mtime": "2024-01-15T14:30:00Z",
                },
                {
                    "name": "file2.txt",
                    "is_dir": False,
                    "size": 200,
                    "mtime": "2024-02-20T10:15:30Z",
                },
            ],
        })
        assert len(response.items) == 2

        # Check first item
        assert response.items[0].mtime is not None
        assert isinstance(response.items[0].mtime, datetime)
        assert response.items[0].mtime.year == 2024
        assert response.items[0].mtime.month == 1

        # Check second item
        assert response.items[1].mtime is not None
        assert isinstance(response.items[1].mtime, datetime)
        assert response.items[1].mtime.year == 2024
        assert response.items[1].mtime.month == 2

    def test_list_response_mixed_mtimes(self):
        """Test ListResponse with mix of valid and None mtimes."""
        response = ListResponse.model_validate({
            "items": [
                {
                    "name": "file1.txt",
                    "is_dir": False,
                    "size": 100,
                    "mtime": "2024-01-15T14:30:00Z",
                },
                {
                    "name": "file2.txt",
                    "is_dir": False,
                    "size": 200,
                    # No mtime field
                },
                {
                    "name": "file3.txt",
                    "is_dir": False,
                    "size": 300,
                    "mtime": None,
                },
            ],
        })
        assert len(response.items) == 3

        # First item should have datetime
        assert response.items[0].mtime is not None
        assert isinstance(response.items[0].mtime, datetime)

        # Second item should have None (missing field)
        assert response.items[1].mtime is None

        # Third item should have None (explicit None)
        assert response.items[2].mtime is None


class TestMetadataOtherFields:
    """Test that other Metadata fields still work correctly."""

    def test_metadata_basic_fields(self):
        """Test basic Metadata fields are unchanged."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            size=1024,
            sha256="abc123"
        )
        assert metadata.name == "test.txt"
        assert metadata.is_dir is False
        assert metadata.size == 1024
        assert metadata.sha256 == "abc123"
        assert metadata.mtime is None

    def test_metadata_directory(self):
        """Test directory Metadata."""
        metadata = Metadata.model_validate({
            "name": "mydir",
            "is_dir": True,
            "size": 0,
            "mtime": "2024-01-15T14:30:00Z",
        })
        assert metadata.is_dir is True
        assert metadata.mtime is not None
        assert isinstance(metadata.mtime, datetime)
