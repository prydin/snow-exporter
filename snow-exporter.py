import argparse
import datetime
import json
import os.path
import sys
import time
from datetime import timedelta
from functools import lru_cache
from urllib.parse import urlencode

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TS_DIR = os.path.expanduser("~/.snow-exporter")
TS_FILENAME = os.path.expanduser("~/.snow-exporter/timestamp.txt")
ops_headers = {"Content-Type": "application/json", "Accept": "application/json"}

def check_response(response):
    print(response.content)
    if response.status_code not in range(200, 299):
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.content)
        sys.exit(1)
    return response

def get_snow_relationships(snow_base, kind, target, start_date, auth):
    query = urlencode({
        "sysparm_query": f"sys_updated_on>{start_date.replace(microsecond=0).isoformat()}^parent.sys_class_name={target}",
        "sysparm_limit": 1000,
        "sysparm_fields": "parent,parent.name,child,child.name"
    })
    return check_response(requests.get(snow_base + "cmdb_rel_ci?" + query, auth=auth)).json()["result"]

def create_ops_app(ops_base, name):
    payload = {
        "resourceKey": {
            "name": name,
            "adapterKindKey": "Container",
            "resourceKindKey": "Application"
        },
        "autoResolveMembership": True,
        "membershipDefinition": {
            "rules":
                [
                    {
                        "resourceKindKey": {
                            "adapterKind": "VMWARE",
                            "resourceKind": "VirtualMachine"
                        },
                        "propertyConditionRules": [
                                {
                                "key": "ServiceNow|Tags",
                                "stringValue": "|" + name + "|",
                                "compareOperator": "CONTAINS"
                            }
                        ]
                    }
                ]
            }
        }
    return check_response(requests.post(ops_base + "/suite-api/api/resources/groups", json=payload, headers=ops_headers, verify=False))

def ops_authenticate(ops_base, username, password, auth_source):
    cred_payload = {"username": username, "password": password}
    if auth_source:
        cred_payload["authSource"] = auth_source
    credentials = json.dumps(cred_payload)
    result = requests.post(url=ops_base + "/suite-api/api/auth/token/acquire",
                           data=credentials,
                           verify=False, headers=ops_headers)
    if result.status_code != 200:
        print(str(result.status_code) + " " + str(result.content))
        exit(1)
    json_data = json.loads(result.content)
    token = json_data["token"]
    ops_headers["Authorization"] = "vRealizeOpsToken " + token

@lru_cache(maxsize=1000)
def get_ops_object_by_name(ops_base, adapter_kind, resource_kind, name):
    query = {
        "adapterKind": [adapter_kind],
        "resourceKind": [resource_kind],
        "name": [name],
    }
    result = requests.post(f"{ops_base}/suite-api/api/resources/query", json=query, headers=ops_headers, verify=False)
    check_response(result)
    resources = result.json()["resourceList"]
    for r in resources:
        if r["resourceKey"]["name"] == name:
            return r
    return None

def set_ops_properties(ops_base, id, group_names):
    payload = {
        "property-content":
            [
                {
                    "statKey": "ServiceNow|Tags",
                    "timestamps": [ int(time.time())*1000 ],
                    "values": [group_names]
                }
            ]
        }
    print(payload)
    return check_response(requests.post(f"{ops_base}/suite-api/api/resources/{id}/properties", json=payload, headers=ops_headers, verify=False))

def main():
    parser = argparse.ArgumentParser(
        prog='snow-exporter',
        description='Exports relationships from ServiceNow and uses them to create applications in VCF Ops',
    )
    parser.add_argument('-H', '--host', required=True, help="The VCF Operations host")
    parser.add_argument('-u', '--user', required=True, help="The VCF Operations user")
    parser.add_argument('-p', '--password', required=True, help="The VCF Operations password")
    parser.add_argument("-a", '--authsource', required=False, help="The VCF Operations authentication source. Defaults to local")
    parser.add_argument("--snowhost", required=True, help="The ServiceNow host")
    parser.add_argument("--snowuser", required=True, help="The ServiceNow user")
    parser.add_argument("--snowpassword", required=True, help="The ServiceNow password")
    parser.add_argument("-A", "--all", action="store_true", help="Process all relationships even if not changed")
    parser.add_argument("-t", "--tsfile", required=False, default=TS_FILENAME, help="Name of file storing latest timestamp. Default is ~/.snow-exporter/")
    parser.add_argument('-U', '--unsafe', required=False, action="store_true", help="Skip SSL verification. This is not recommended in production!")

    # Extract arguments
    args = parser.parse_args()
    ops_base = f"https://{args.host}"
    snow_base = f"https://{args.snowhost}/api/now/table/"
    snow_auth = (args.snowuser, args.snowpassword)

    # Check for timestamp file
    if not args.all:
        tsfile = args.tsfile
        try:
            with open(tsfile, "r") as f:
                ts = f.read()
        except FileNotFoundError:
            ts = "1970-01-01T00:00:00"
    else:
        ts = "1970-01-01T00:00:00"
    start_date = datetime.datetime.fromisoformat(ts) - timedelta(minutes=5)  # Go back five minutes to account for clock errors

    ops_authenticate(ops_base, args.user, args.password, args.authsource)

    # Get all relationships that have changed since last run
    relationships = get_snow_relationships(snow_base,"something", "cmdb_ci_appl", start_date, snow_auth)
    vm_to_apps = {}
    app_seen = {}
    vm_not_present = {} # "Anti-cache" to avoid looking for nonexistent VMs
    for r in relationships:
        app_name = r["parent.name"]
        vm_name = r["child.name"]

        # Don't bother to look for VMs we know don't exist
        if vm_name in vm_not_present:
            continue

        # Look up the VM in ops. We only care about VMs that are present in ops
        ops_vm = get_ops_object_by_name(ops_base, "VMWARE", "VirtualMachine", vm_name)
        if not ops_vm:
            vm_not_present[vm_name] = True
            continue
        vm_id = ops_vm["identifier"]

        # Look up the application in ops
        if app_name not in app_seen:
            app_seen[app_name] = True
        if not vm_name in vm_to_apps:
            vm_to_apps[vm_id] = "|" + app_name + "|"
        else:
            vm_to_apps[vm_id] += "|" + app_name + "|"
    print(vm_to_apps)

    # Update resource properties
    for (k, v) in vm_to_apps.items():
        set_ops_properties(ops_base, k, v)

    # Create application objects if needed
    for app_name in app_seen.keys():
        ops_app = get_ops_object_by_name(ops_base, "Container", "Application", app_name)
        print(app_name, ops_app)
        if not ops_app:
            print(create_ops_app(ops_base, app_name))

    # Write new timestamp
    if not args.all:
        tsdir = os.path.dirname(tsfile)
        os.makedirs(tsdir, exist_ok=True)
        with open(tsfile, "w") as f:
            f.write(datetime.datetime.now(datetime.timezone.utc).isoformat())

if __name__ == '__main__':
    main()
