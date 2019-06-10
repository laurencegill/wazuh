# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from functools import wraps
from wazuh.exception import WazuhError
from api.authentication import decode_token
import re


def get_user_permissions(**kwargs):

    # We strip "Bearer " from the Authorization header of the request to get the token
    jwt_token = kwargs['auth'][7:]

    payload = decode_token(jwt_token)

    permissions = payload['rbac_policies']
    mode = payload['mode']

    return mode, permissions


def get_required_permissions(actions: list = None, resources: str = None, *args, **kwargs):

    # We expose required resources for the request
    m = re.search("^(\w+\:\w+:){(\w+)}$", resources)
    res_list = list()
    # If we find a regex match we obtain the dynamic resource/s
    if m:
        try:
            res_base = m.group(1)
            # Dynamic resources ids are found within the {}
            params = kwargs[m.group(2)]
            # We check if params is a list of resources or a single one in a string
            if isinstance(params, list):
                for param in params:
                    res_list.append("{0}{1}".format(res_base, param))
            else:
                res_list.append("{0}{1}".format(res_base, params))
        # KeyError occurs if required dynamic resources can't be found within request parameters
        except KeyError as e:
            raise WazuhError(4000, extra_message=str(e))
    # If we don't find a regex match we obtain the static resource/s
    else:
        res_list.append(resources)

    # Create dict of required policies with action:set(resources) pairs
    req_permissions = dict()
    for action in actions:
        req_permissions[action] = set(res_list)

    return req_permissions


def match_pairs(mode: bool = False, user_permissions: list = None, req_permissions: dict = None):

    # We run through all required permissions for the request
    for req_action, req_resources in req_permissions.items():
        # allow_match is used to keep track when a required permission is matched by a policy with an allow effect
        allow_match = False
        # We run through the user permissions to find a match with the required permissions
        for policy in user_permissions:
            # We find if action and resources match
            action_match = req_action in policy['actions']
            res_match = req_resources.issubset(policy['resources'])
            # When any policy with a deny effect matches, we deny the request directly
            if action_match and res_match and policy['effect'] == "deny":
                return False
            # When any policy with an allow effect matches, we set a match in allow_match and
            # break out to continue with required permissions
            elif action_match and res_match and policy['effect'] == "allow":
                allow_match = True
                break
            # We continue running through the user permissions if no match is found in actual policy
        # If we have an allow match or we are using black list mode we continue with next required permission
        if allow_match or mode:
            continue
        # Otherwise, if we are using white list mode and no match is found for the required permission
        # we deny the request
        else:
            return False
    # If we don't find a deny match or we find an allow match for all policies in white list mode we allow the request
    return True


def matches_privileges(actions: list = None, resources: str = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            mode, user_permissions = get_user_permissions(**kwargs)
            required_permissions = get_required_permissions(actions, resources, *args, **kwargs)
            allow = match_pairs(mode, user_permissions, required_permissions)
            if allow:
                del kwargs['auth']
                return func(*args, **kwargs)
            else:
                raise WazuhError(4000)
        return wrapper
    return decorator
