import getpass
import pprint
import requests
import os
import datetime
from tableausdk import *
from tableausdk.Extract import *

API_URL = "https://api.zerofox.com/1.0/alerts/"

extract_file = "alerts.tde"
LIMIT = 200000
'''FILTERS = {
    'severity': '3'
}
'''
FILTERS = ''

def main():
    pp = pprint.PrettyPrinter(indent=2)

    key = raw_input("API Key: ")

    limit = 100
    offset = 0

    # Create TDE extract file

    if os.path.isfile(extract_file):
        os.remove(extract_file)

    ExtractAPI.initialize()
    tdefile = Extract(extract_file)

    # Create the table definition
    # Data types: INTEGER, DOUBLE, BOOLEAN, DATE, DATETIME, DURATION, CHAR_STRING, UNICODE_STRING
    tableDef = TableDefinition()
    tableDef.addColumn('alert_id', Type.CHAR_STRING)
    tableDef.addColumn('timestamp', Type.DATETIME)
    tableDef.addColumn('alert_type', Type.CHAR_STRING)
    tableDef.addColumn('alert_status', Type.CHAR_STRING)
    tableDef.addColumn('alert_network', Type.CHAR_STRING)
    tableDef.addColumn('notes', 16) #UNICODE_STRING
    tableDef.addColumn('metadata', 16) #UNICODE_STRING
    tableDef.addColumn('rule_name', Type.CHAR_STRING)
    tableDef.addColumn('severity', Type.INTEGER)
    tableDef.addColumn('asset_name', 16) #UNICODE_STRING
    tableDef.addColumn('asset_image', Type.CHAR_STRING)
    tableDef.addColumn('perpetrator_username', 16) #UNICODE_STRING
    tableDef.addColumn('perpetrator_displayname', 16) #UNICODE_STRING
    tableDef.addColumn('perpetrator_type', Type.CHAR_STRING)
    tableDef.addColumn('perpetrator_image', Type.CHAR_STRING)
    tableDef.addColumn('takedown_request_time', Type.DATETIME)
    tableDef.addColumn('takedown_accept_time', Type.DATETIME)
    tableDef.addColumn('close_time', Type.DATETIME)

    # Create table in image of tableDef
    table = tdefile.addTable('Extract', tableDef)

    rowcount = 0

    done = 'n'
    while done == 'n':
        response = get_page(key, limit, offset)
        alerts = response['alerts']
        if len(alerts) == 0:
            done = 'y'
            break
        for alert in alerts:
            newrow = createrow(alert,tableDef)

            table.insert(newrow)

            rowcount +=1
            if rowcount >= LIMIT:
                done = 'y'
                break

        offset += 100
    tdefile.close()
    ExtractAPI.cleanup()
    print str(rowcount) + " alerts processed"

def createrow(alert,tableDef):
    newrow = Row(tableDef)
    newrow.setCharString(0, str(alert['id']))
    d = datetime.datetime.strptime(alert['timestamp'], '%Y-%m-%dT%H:%M:%S+00:00')
    newrow.setDateTime(1, d.year, d.month, d.day, d.hour, d.minute, d.second, 0)
    newrow.setCharString(2, alert['alert_type'])
    newrow.setCharString(3, alert['status'])
    newrow.setCharString(4, keyCheck('network', alert, ''))
    newrow.setString(5, keyCheck('notes', alert, ''))
    newrow.setString(6, keyCheck('metadata', alert, ''))
    newrow.setCharString(7, keyCheck('rule_name', alert, ''))
    newrow.setInteger(8, alert['severity'])
    newrow.setString(9, keyCheck('name', alert['asset'], ''))
    newrow.setCharString(10, alert['asset']['image'])
    newrow.setString(11, keyCheck('username', alert['perpetrator'], ''))
    newrow.setString(12, keyCheck('display_name', alert['perpetrator'], ''))
    newrow.setCharString(13, keyCheck('type', alert['perpetrator'], ''))
    newrow.setCharString(14, keyCheck('image', alert['perpetrator'], ''))
    for log in alert['logs']:
        if log['action'] == 'request takedown':
            d = datetime.datetime.strptime(log['timestamp'], '%Y-%m-%dT%H:%M:%S+00:00')
            newrow.setDateTime(15, d.year, d.month, d.day, d.hour, d.minute, d.second, 0)
        if log['action'] == 'accept takedown':
            d = datetime.datetime.strptime(log['timestamp'], '%Y-%m-%dT%H:%M:%S+00:00')
            newrow.setDateTime(16, d.year, d.month, d.day, d.hour, d.minute, d.second, 0)
        if log['action'] == 'close' or log['action'] == 'close due to whitelist':
            d = datetime.datetime.strptime(log['timestamp'], '%Y-%m-%dT%H:%M:%S+00:00')
            newrow.setDateTime(17, d.year, d.month, d.day, d.hour, d.minute, d.second, 0)
    return newrow

def keyCheck(key, arr, default):
    if key in arr.keys():
        val = arr[key]
        if val is None:
            return ''
        else:
            return unicode(val)
    else:
        return default

def get_page(key, limit, offset):
    filters = {
        'limit': limit,
        'offset': offset
    }
    
    headers = {
        'Authorization' : 'Token ' + key
    }

    filters.update(FILTERS)
    print filters
    r = requests.get(API_URL, params=filters, headers=headers)
    if r.status_code >= 300:
        print "error: status code %d" % r.status_code
        return {'count': 0, 'alerts': []}

    response = r.json()
    return response

main()

