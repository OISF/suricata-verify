#! /usr/bin/env python3
import json
from contextlib import redirect_stdout

schema_path = "../mendel.ids/etc/schema.json"
schema = json.load(open(schema_path))
schema["additionalProperties"] = True
schema["properties"]["dns"]["additionalProperties"] = True
schema["properties"]["anomaly"]["additionalProperties"] = True
schema["properties"]["stats"]["additionalProperties"] = True
schema["properties"]["stats"]["properties"]["flow"]["additionalProperties"] = True
schema["properties"]["stats"]["properties"]["app_layer"]["properties"]["flow"]["additionalProperties"] = True
schema["properties"]["stats"]["properties"]["app_layer"]["properties"]["tx"]["additionalProperties"] = True
schema["properties"]["stats"]["properties"]["decoder"]["additionalProperties"] = True
schema["properties"]["stats"]["properties"]["flow"]["properties"]["mgr"]["additionalProperties"] = True

with open(schema_path, 'w') as fp:
        json.dump(schema, fp, indent=4)

