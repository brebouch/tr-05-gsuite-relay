######################################################
#
# XDR Integration Module Transforms
#
######################################################

import uuid
from datetime import datetime, timedelta


def set_time(offset):
    return {
        'start_time': str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")),
        'end_time': str((datetime.now() + timedelta(hours=offset)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

    }


def get_disposition(status):
    if status.lower() == 'malicious':
        return current_app.config['DISPOSITIONS']['malicious']
    elif status.lower() == 'suspicious':
        return current_app.config['DISPOSITIONS']['suspicious']
    elif status.lower() == 'clean':
        return current_app.config['DISPOSITIONS']['clean']
    elif status.lower() == 'common':
        return current_app.config['DISPOSITIONS']['common']
    else:
        return current_app.config['DISPOSITIONS']['unknown']


def get_verdict(observable_value, observable_type, disposition, valid_time):
    '''
        Format the observable disposition into the CTIM format
    '''
    if disposition[0] == 1:
        disposition_name = 'Clean'
    elif disposition[0] == 2:
        disposition_name = 'Malicious'
    elif disposition[0] == 3:
        disposition_name = 'Suspicious'
    elif disposition[0] == 4:
        disposition_name = 'Common'
    elif disposition[0] == 5:
        disposition_name = 'Unknown'
    else:
        disposition_name = 'Unknown'
    return {
        'type': 'verdict',
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition': disposition[0],
        'disposition_name': disposition_name,
        'valid_time': valid_time
    }


def get_judgement(source_uri, observable_value, observable_type, disposition, valid_time):

    return {
        'id': f'transient:judgement-{uuid.uuid4()}',
        'observable': {'value': observable_value, 'type': observable_type},
        'disposition': disposition[0],
        'disposition_name': disposition[1],
        'type': 'judgement',
        'schema_version': '1.0.1',
        'source': 'Patrick Generic Serverless Relay',
        'confidence': 'Low',
        'priority': 90,
        'severity': 'Medium',
        'valid_time': valid_time,
        'source_uri': source_uri
    }


def set_observable(observable_type, observable_value):
    return {
                "value": observable_value,
                "type": observable_type
            }


def set_relation(src, related, relation, origin):
    return {
        "origin": origin,
        "relation": relation,
        "source": src,
        "related": related
    }


def set_target(target_type, observables, start, end):
    return {
        "type": target_type,
        "observables": observables,
        "observed_time": {
            "start_time": start,
            "end_time": end,
        }
    }


def get_sighting_doc(source, description):
    times = set_time(1)
    return {
        "description": description,
        "schema_version": "1.1.3",
        "relations": [
        ],
        "observables": [
        ],
        "type": "sighting",
        "source": source,
        "targets": [
        ],
        "resolution": "detected",
        "internal": True,
        "count": 1,
        "id": f'transient:sighting-{uuid.uuid4()}',
        "severity": "Unknown",
        "tlp": "white",
        "confidence": "High",
        "observed_time": {
            "start_time": times['start_time'],
            "end_time": times['end_time']
        },
        "sensor": "network.sensor"
    }


def get_model():
    return {
            "sightings": {
                "count": 0,
                "docs": [
                ]
            }
        }


