import pytest

from app.zia.insights import InsightsError, parse_trend


def test_parse_trend_finds_nested_block():
    body = {"data": {"WEB_TRAFFIC": {"no_grouping": {"entries": [{"name": "x", "total": 3,
            "trend": {"time_stamp": [1000, 2000], "values": [1, 2]}}]}}}}
    assert parse_trend(body) == [{"t": 1000, "bytes": 1.0}, {"t": 2000, "bytes": 2.0}]


def test_parse_trend_without_data():
    with pytest.raises(InsightsError):
        parse_trend({"data": {}})
