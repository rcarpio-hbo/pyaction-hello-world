import json
import os

def read_json (path: str):
    """reads json files and returns JSON object as dict"""

    if not os.path.exists(path):
        raise FileNotFoundError(f'Report file not found: "{path}"')

    f = open(path)
    data = json.load(f)
    f.close()
    return data