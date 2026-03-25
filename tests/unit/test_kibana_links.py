"""Unit tests for kibana_link_service — deep link generation."""

import pytest
from unittest.mock import patch
from services.kibana_link_service import get_kibana_url, generate_kibana_link, format_kibana_link


class TestGetKibanaUrl:

    def test_returns_url(self):
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"}):
            assert get_kibana_url() == "http://kibana:5601"

    def test_strips_trailing_slash(self):
        with patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601/"}):
            assert get_kibana_url() == "http://kibana:5601"

    def test_returns_none_when_empty(self):
        with patch.dict("os.environ", {"KIBANA_URL": ""}):
            assert get_kibana_url() is None

    def test_returns_none_when_missing(self):
        with patch.dict("os.environ", {}, clear=True):
            assert get_kibana_url() is None


class TestGenerateKibanaLink:

    BASE = "http://kibana:5601"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_alert_link(self):
        url = generate_kibana_link("alert", {"id": "abc-123"})
        assert url == f"{self.BASE}/app/security/alerts?query=kibana.alert.uuid:abc-123"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_rule_link(self):
        url = generate_kibana_link("rule", {"id": "rule-1"})
        assert url == f"{self.BASE}/app/security/rules/id/rule-1"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_case_link(self):
        url = generate_kibana_link("case", {"id": "case-1"})
        assert url == f"{self.BASE}/app/security/cases/case-1"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_timeline_link(self):
        url = generate_kibana_link("timeline", {"id": "tl-1"})
        assert "timelines?timeline=" in url

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_entity_analytics_link(self):
        url = generate_kibana_link("entity_analytics")
        assert url == f"{self.BASE}/app/security/entity_analytics"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_alerts_link(self):
        url = generate_kibana_link("alerts")
        assert url == f"{self.BASE}/app/security/alerts"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_detection_rules_link(self):
        url = generate_kibana_link("detection_rules")
        assert url == f"{self.BASE}/app/security/rules"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_unknown_page_returns_none(self):
        assert generate_kibana_link("nonexistent") is None

    @patch.dict("os.environ", {"KIBANA_URL": ""})
    def test_returns_none_without_kibana_url(self):
        assert generate_kibana_link("alerts") is None


class TestFormatKibanaLink:

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_markdown_format(self):
        result = format_kibana_link("alerts", label="View Alerts")
        assert result == "[View Alerts](http://kibana:5601/app/security/alerts)"

    @patch.dict("os.environ", {"KIBANA_URL": "http://kibana:5601"})
    def test_default_label(self):
        result = format_kibana_link("alerts")
        assert result.startswith("[View in Kibana]")

    @patch.dict("os.environ", {"KIBANA_URL": ""})
    def test_empty_when_no_kibana(self):
        assert format_kibana_link("alerts") == ""
