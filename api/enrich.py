from functools import partial
import json
from flask import Blueprint

from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data
from api import gmail

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    auth = get_jwt()
    ob = get_observables()
    for o in ob:
        if o['type'] == 'email':
            if o['value'].split('@')[1] in auth['internal_domains']:
                g = gmail.Gmail(auth['service_account'], auth['delegated_email'])
                sightings = g.get_messages(o['value'])
                return jsonify_data(sightings)
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
