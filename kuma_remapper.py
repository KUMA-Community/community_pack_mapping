import json
import re
import argparse
import light_crypter as lc

RE_STRING = '(T\\d+\\.?\\d+)'


def get_techniques(actions):
    techniques = []
    keys = actions.keys()
    for key in keys:
        if 'enrichment' in actions[key]:
            for e in actions[key]['enrichment']:
                if e['targetField'] == "Technique":
                    t = e['constant']
                    techniques.extend(re.findall(RE_STRING, t))
    return techniques


def main():
    with open(INPUT_FILE, 'rb') as f:
        data = f.read()

    key = lc.password_to_key(PASSWORD)
    raw_resources = lc.decrypt(data, key)

    resources = raw_resources['resources']

    with open(INPUT_MITRE, 'r') as f:
        mitre = json.load(f)

    for r in resources:
        # only correlation rules
        if (r['kind'] == 'correlationRule'
                # only rules without MITRE mapping
                and (r['encoded']['payload']['mitre'] is None or not r['encoded']['payload']['mitre'])
                # not operational rules
                and r['encoded']['payload']['kind'] in ['simple', 'standard']):
            techniques = get_techniques(r['encoded']['payload']['actions'])
            for t in techniques:
                for m in mitre:
                    if t == m['TechniqueID']:
                        mapping = {
                            "TacticID": m['TacticID'],
                            "TacticName": m['TacticName'],
                            "TechniqueID": m['TechniqueID'],
                            "TechniqueName": m['TechniqueName']
                        }
                        if r['encoded']['payload']['mitre'] is None:
                            r['encoded']['payload']['mitre'] = [mapping]
                        else:
                            r['encoded']['payload']['mitre'].append(mapping)

    encrypted_data = lc.encrypt(raw_resources, key)
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(encrypted_data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MITRE re-mapping for KUMA 3.2')
    parser.add_argument('-i', '--input', help='Path to KUMA resource file exported from WebUI', type=str, required=True)
    parser.add_argument('-p', '--password', help='Password for decrypt and encrypt KUMA resource file', type=str,
                        required=True)
    parser.add_argument('-m', '--mitre', help='Path to MITRE mapping from KUMA.', type=str, required=True)
    parser.add_argument('--output', help='(Optional) Path to output file. Default: remappedRules', default='remappedRules',
                        type=str)

    args = parser.parse_args()

    INPUT_FILE = args.input
    OUTPUT_FILE = args.output
    INPUT_MITRE = args.mitre
    PASSWORD = args.password

    print(f'Your rules now in file `{OUTPUT_FILE}` encrypted by password `{PASSWORD}`\n' +
          'You can import them into WebUI KUMA')

    main()
