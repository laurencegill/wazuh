#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, mock_open, Mock

import pytest

import wazuh.syscheck as syscheck
from wazuh.exception import WazuhInternalError, WazuhError

mocked_rbac = [True, []]
mocked_status = [{'status': 'active'}, {}, {'status': 'random'}]
mocked_restart_message = "Restarting Syscheck/Rootcheck"
mocked_delete_message = "Syscheck database deleted"
mocked_agent_ids = {'items': [{'id': '001'}, {'id': '002'}, {'id': '003'}], 'totalItems': '3'}
mocked_version = [{'version': 'Wazuh v3.6.0'}, {'version': 'Wazuh v3.8.0'}]
mocked_conn_query_results = [('2019-06-14 07:58:10', 'Starting syscheck scan.'),
                             ('2019-06-14 07:58:30', 'Ending syscheck scan.')]
mocked_last_scan_res = [[{'start_scan': None,
                          'end_scan': None}],
                        [{'start_scan': 1559134512,
                          'end_scan': 1559134532}]]
mocked_items = [{
        "date": 1538556788,
        "file": "/etc/fstab",
        "gid": "0",
        "gname": "root",
        "inode": 17166176,
        "md5": "29d99e7092b7fa01b7f8bcac233c099d",
        "mtime": 1536059852,
        "perm": "100644",
        "sha1": "b1fa37ec27abe5ae0870cb1c11744dce8440f96d",
        "sha256": "009780ae79c19bbd4352901f0516b361c0eff5a77bbaf6af1c5d77bf1d16d665",
        "size": 541,
        "type": "file",
        "uid": "0",
        "uname": "root"
    },
    {
        "date": 1559134512,
        "file": "/etc/crypttab",
        "gid": "0",
        "gname": "root",
        "inode": 16777283,
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "mtime": 1559134532,
        "perm": "100600",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "size": 0,
        "type": "file",
        "uid": "0",
        "uname": "root"
    }
]
mocked_total_items = 5122
mocked_files = [mocked_items, mocked_total_items]
mock_date = 1538556788


@patch('wazuh.syscheck.OssecQueue.close', return_value="Done")
@patch('wazuh.syscheck.OssecQueue.send_msg_to_agent', return_value=mocked_restart_message)
@patch('wazuh.syscheck.OssecQueue.__init__', return_value=None)
@patch('wazuh.syscheck.Agent.get_basic_information', side_effect=[mocked_status[0], mocked_status[1]])
@patch('wazuh.syscheck._run_local', return_value=mocked_restart_message)
def test_run(*mocked_args):
    # Test with agent_id 000
    result = syscheck.run(agent_id='000', rbac=mocked_rbac)
    assert result == "Restarting Syscheck/Rootcheck"

    # Test with agent_id 001 and agent_status = active
    result = syscheck.run(agent_id='001', rbac=mocked_rbac)
    assert result == "Restarting Syscheck/Rootcheck"

    # Test with agent_id 001 and an empty agent_status
    with pytest.raises(WazuhInternalError, match='.* 1601 .*'):
        syscheck.run(agent_id='001', rbac=mocked_rbac)


@patch('wazuh.syscheck.OssecQueue.close', return_value="Done")
@patch('wazuh.syscheck.OssecQueue.send_msg_to_agent', return_value=mocked_restart_message)
@patch('wazuh.syscheck.OssecQueue.__init__', return_value=None)
@patch('wazuh.syscheck._run_local', side_effect="Done")
def test_run_all(*mocked_args):
    result = syscheck.run_all(rbac=mocked_rbac)
    assert result == "Restarting Syscheck/Rootcheck"


def test_private_run_local():
    with patch('builtins.open', mock_open(read_data='MOCK_SYSCHECK_RESTART')):
        result = syscheck._run_local()
        assert result == "Restarting Syscheck/Rootcheck locally"


@patch('wazuh.syscheck._clear', return_value=mocked_delete_message)
def test_clear(*mocked_args):
    result = syscheck.clear(agent_id='001', rbac=mocked_rbac)
    assert result == "Syscheck database deleted"


@patch('wazuh.syscheck.Agent.get_agents_overview', return_value=mocked_agent_ids)
@patch('wazuh.syscheck._clear', return_value=mocked_delete_message)
def test_clear_all(*mocked_args):
    result = syscheck.clear_all(rbac=mocked_rbac)
    assert result == "Syscheck databases deleted"


@patch('wazuh.syscheck.WazuhDBConnection.execute', side_effect="Done")
@patch('wazuh.syscheck.WazuhDBConnection.__init__', return_value=None)
@patch('wazuh.syscheck.Agent.get_basic_information', side_effect=[mocked_status[0], mocked_status[1]])
def test_private_clear(*mocked_args):
    result = syscheck._clear('001')
    assert result == "Syscheck database deleted"


@patch('wazuh.syscheck.Agent._load_info_from_agent_db', side_effect=[mocked_last_scan_res[0], mocked_last_scan_res[1]])
@patch('wazuh.database.Connection.__iter__', return_value=iter(mocked_conn_query_results))
@patch('wazuh.syscheck.Connection.execute', return_value="Done")
@patch('wazuh.syscheck.Connection.__init__', return_value=None)
@patch('wazuh.syscheck.glob', side_effect=[None, ['Mocked db']])
@patch('wazuh.syscheck.Agent.get_basic_information', side_effect=[KeyError, mocked_version[0], mocked_version[0],
                                                                  mocked_version[1], mocked_version[1]])
@patch('wazuh.syscheck.Agent.__init__', return_value=None)
def test_last_scan(*mocked_args):
    for i in range(1, 6):
        if i == 2:
            with pytest.raises(WazuhInternalError, match='.* 1600 .*'):
                syscheck.last_scan(agent_id='001', rbac=mocked_rbac)
        else:
            result = syscheck.last_scan(agent_id='001', rbac=mocked_rbac)
            assert isinstance(result, dict)
            assert set(result.keys()) == {'start', 'end'}


@pytest.mark.parametrize('sort, select, filters', [
    (None, None, {}),
    ({'fields': ["date", "mtime"]}, None, {}),
    ({'fields': ["wrong"]}, None, {}),
    (None, ["date", "mtime"], {}),
    (None, ["wrong"], {}),
    (None, ["date", "mtime"], {'hash': '29d99e7092b7fa01b7f8bcac233c099d'})
])
@patch('wazuh.syscheck.datetime', Mock(fromtimestamp=Mock(return_value=mock_date)))
@patch('wazuh.syscheck.Agent._load_info_from_agent_db', return_value=mocked_files)
def test_files(mock_load, sort, select, filters):
    if sort and sort['fields'][0] == "wrong":
        with pytest.raises(WazuhError, match='.* 1403 .*'):
            syscheck.files(agent_id='001', sort=sort, select=select, filters=filters, rbac=mocked_rbac)
    elif select and select[0] == "wrong":
        with pytest.raises(WazuhError, match='.* 1724 .*'):
            syscheck.files(agent_id='001', sort=sort, select=select, filters=filters, rbac=mocked_rbac)
    else:
        result = syscheck.files(agent_id='001', sort=sort, select=select, filters=filters, rbac=mocked_rbac)
        assert isinstance(result, dict)
        assert set(result.keys()) == {'items', 'totalItems'}
