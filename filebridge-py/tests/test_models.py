"""Tests for filebridge models, specifically Metadata mdate conversion."""

from datetime import datetime, timezone
import pytest

from filebridge.models import Metadata, ListResponse


class TestMetadataMdateConversion:
    """Test mdate field conversion from string to datetime."""

    def test_mdate_iso8601_z_suffix(self):
        """Test parsing ISO8601 with Z suffix (UTC)."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mdate="2024-01-15T14:30:00Z"
        )
        assert metadata.mdate is not None
        assert isinstance(metadata.mdate, datetime)
        assert metadata.mdate.year == 2024
        assert metadata.mdate.month == 1
        assert metadata.mdate.day == 15
        assert metadata.mdate.hour == 14
        assert metadata.mdate.minute == 30
        assert metadata.mdate.second == 0
        assert metadata.mdate.tzinfo == timezone.utc

    def test_mdate_iso8601_with_timezone(self):
        """Test parsing ISO8601 with explicit timezone."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mdate="2024-01-15T14:30:00+00:00"
        )
        assert metadata.mdate is not None
        assert isinstance(metadata.mdate, datetime)
        assert metadata.mdate.tzinfo == timezone.utc

    def test_mdate_none(self):
        """Test handling None mdate value."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mdate=None
        )
        assert metadata.mdate is None

    def test_mdate_missing(self):
        """Test handling missing mdate field."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False
        )
        assert metadata.mdate is None

    def test_mdate_invalid_string(self):
        """Test handling invalid mdate string."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mdate="invalid-date-string"
        )
        # Should return None for invalid strings rather than raising
        assert metadata.mdate is None

    def test_mdate_already_datetime(self):
        """Test that existing datetime objects are preserved."""
        test_datetime = datetime(2024, 1, 15, 14, 30, 0, tzinfo=timezone.utc)
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mdate=test_datetime
        )
        assert metadata.mdate == test_datetime
        assert metadata.mdate is test_datetime  # Should be the same object

    def test_mdate_with_microseconds(self):
        """Test parsing ISO8601 with microseconds."""
        metadata = Metadata(
            name="test.txt",
            is_dir=False,
            mdate="2024-01-15T14:30:00.123456Z"
        )
        assert metadata.mdate is not None
        assert metadata.mdate.microsecond == 123456

    def test_mdate_different_timezones(self):
        """Test parsing ISO8601 with different timezone offsets."""
        # Test CET timezone (+01:00)
        metadata_cet = Metadata(
            name="test.txt",
            is_dir=False,
            mdate="2024-01-15T14:30:00+01:00"
        )
        assert metadata_cet.mdate is not None
        assert metadata_cet.mdate.tzinfo is not None
        assert str(metadata_cet.mdate.tzinfo) == "UTC+01:00"
        
        # Test EST timezone (-05:00)
        metadata_est = Metadata(
            name="test.txt",
            is_dir=False,
            mdate="2024-01-15T14:30:00-05:00"
        )
        assert metadata_est.mdate is not None
        assert metadata_est.mdate.tzinfo is not None
        assert str(metadata_est.mdate.tzinfo) == "UTC-05:00"
        
        # Verify timezone preservation
        from datetime import timezone
        utc_cet = metadata_cet.mdate.astimezone(timezone.utc)
        utc_est = metadata_est.mdate.astimezone(timezone.utc)
        
        # CET 14:30 should be UTC 13:30
        assert utc_cet.hour == 13
        assert utc_cet.minute == 30
        
        # EST 14:30 should be UTC 19:30
        assert utc_est.hour == 19
        assert utc_est.minute == 30


class TestListResponseWithMetadata:
    """Test ListResponse containing Metadata with mdate conversion."""

    def test_list_response_with_mdates(self):
        """Test ListResponse properly converts mdate in all items."""
        api_data = {
            "items": [
                {
                    "name": "file1.txt",
                    "is_dir": False,
                    "size": 100,
                    "mdate": "2024-01-15T14:30:00Z"
                },
                {
                    "name": "file2.txt",
                    "is_dir": False,
                    "size": 200,
                    "mdate": "2024-02-20T10:15:30Z"
                }
            ]
        }
        
        response = ListResponse(**api_data)
        assert len(response.items) == 2
        
        # Check first item
        assert response.items[0].mdate is not None
        assert isinstance(response.items[0].mdate, datetime)
        assert response.items[0].mdate.year == 2024
        assert response.items[0].mdate.month == 1
        
        # Check second item
        assert response.items[1].mdate is not None
        assert isinstance(response.items[1].mdate, datetime)
        assert response.items[1].mdate.year == 2024
        assert response.items[1].mdate.month == 2

    def test_list_response_mixed_mdates(self):
        """Test ListResponse with mix of valid and None mdates."""
        api_data = {
            "items": [
                {
                    "name": "file1.txt",
                    "is_dir": False,
                    "size": 100,
                    "mdate": "2024-01-15T14:30:00Z"
                },
                {
                    "name": "file2.txt",
                    "is_dir": False,
                    "size": 200
                    # No mdate field
                },
                {
                    "name": "file3.txt",
                    "is_dir": False,
                    "size": 300,
                    "mdate": None
                }
            ]
        }
        
        response = ListResponse(**api_data)
        assert len(response.items) == 3
        
        # First item should have datetime
        assert response.items[0].mdate is not None
        assert isinstance(response.items[0].mdate, datetime)
        
        # Second item should have None (missing field)
        assert response.items[1].mdate is None
        
        # Third item should have None (explicit None)
        assert response.items[2].mdate is None


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
        assert metadata.mdate is None

    def test_metadata_directory(self):
        """Test directory Metadata."""
        metadata = Metadata(
            name="mydir",
            is_dir=True,
            size=0,
            mdate="2024-01-15T14:30:00Z"
        )
        assert metadata.is_dir is True
        assert metadata.mdate is not None
        assert isinstance(metadata.mdate, datetime)