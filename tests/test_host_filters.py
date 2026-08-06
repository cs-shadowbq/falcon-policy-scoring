"""Tests for host group ID / tag parsing and client-side host filtering."""
import pytest

from falcon_policy_scoring.utils.filters import (
    parse_host_group_ids,
    parse_tags,
    normalize_tag,
    filter_hosts,
)


class TestParseHostGroupIds:
    """Tests for parse_host_group_ids."""

    def test_none_returns_none(self):
        assert parse_host_group_ids(None) is None

    def test_empty_returns_none(self):
        assert parse_host_group_ids('') is None
        assert parse_host_group_ids('  ,  ') is None

    def test_splits_and_strips(self):
        assert parse_host_group_ids('gid1, gid2 ,gid3') == ['gid1', 'gid2', 'gid3']

    def test_single(self):
        assert parse_host_group_ids('abc123') == ['abc123']


class TestNormalizeTag:
    """Tests for the default tag-prefix behavior."""

    def test_bare_tag_gets_default_prefix(self):
        assert normalize_tag('prod') == 'FalconGroupingTags/prod'

    def test_falcon_prefix_preserved(self):
        assert normalize_tag('FalconGroupingTags/prod') == 'FalconGroupingTags/prod'

    def test_sensor_prefix_preserved(self):
        assert normalize_tag('SensorGroupingTags/dmz') == 'SensorGroupingTags/dmz'

    def test_prefix_detection_case_insensitive_canonicalizes(self):
        # Lower-case prefix input is canonicalized; suffix is preserved as-is
        assert normalize_tag('falcongroupingtags/Prod') == 'FalconGroupingTags/Prod'
        assert normalize_tag('sensorgroupingtags/DMZ') == 'SensorGroupingTags/DMZ'

    def test_whitespace_stripped(self):
        assert normalize_tag('  prod  ') == 'FalconGroupingTags/prod'


class TestParseTags:
    """Tests for parse_tags."""

    def test_none_returns_none(self):
        assert parse_tags(None) is None

    def test_empty_returns_none(self):
        assert parse_tags('') is None

    def test_mixed_bare_and_prefixed(self):
        assert parse_tags('prod,SensorGroupingTags/dmz') == [
            'FalconGroupingTags/prod',
            'SensorGroupingTags/dmz',
        ]


def _host(device_id, groups=None, tags=None, platform='Windows',
          all_passed=False, any_failed=False):
    return {
        'device_id': device_id,
        'hostname': device_id,
        'platform': platform,
        'groups': groups or [],
        'tags': tags or [],
        'all_passed': all_passed,
        'any_failed': any_failed,
    }


class TestFilterHostsGroupsAndTags:
    """Client-side group/tag filtering semantics (values OR, categories AND)."""

    def test_group_ids_or(self):
        hosts = [
            _host('a', groups=['g1']),
            _host('b', groups=['g2']),
            _host('c', groups=['g3']),
        ]
        result = filter_hosts(hosts, group_ids=['g1', 'g2'])
        assert {h['device_id'] for h in result} == {'a', 'b'}

    def test_tags_or_case_insensitive(self):
        hosts = [
            _host('a', tags=['FalconGroupingTags/prod']),
            _host('b', tags=['SensorGroupingTags/dmz']),
            _host('c', tags=['FalconGroupingTags/dev']),
        ]
        result = filter_hosts(hosts, tags=['falcongroupingtags/prod', 'SensorGroupingTags/dmz'])
        assert {h['device_id'] for h in result} == {'a', 'b'}

    def test_groups_and_tags_combine_with_and(self):
        hosts = [
            _host('a', groups=['g1'], tags=['FalconGroupingTags/prod']),
            _host('b', groups=['g1'], tags=['FalconGroupingTags/dev']),
            _host('c', groups=['g2'], tags=['FalconGroupingTags/prod']),
        ]
        result = filter_hosts(hosts, group_ids=['g1'], tags=['FalconGroupingTags/prod'])
        assert {h['device_id'] for h in result} == {'a'}

    def test_no_group_or_tag_filter_passes_all(self):
        hosts = [_host('a'), _host('b')]
        assert len(filter_hosts(hosts)) == 2

    def test_missing_groups_field_excluded_when_filtering(self):
        hosts = [{'device_id': 'a', 'platform': 'Windows'}]  # no 'groups' key
        assert filter_hosts(hosts, group_ids=['g1']) == []
