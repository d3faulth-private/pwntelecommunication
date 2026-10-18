#!/usr/bin/env python3
"""Offline normalized-event detector; no networking, packet generation or blocking."""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

MAX_BYTES = 10 * 1024 * 1024
ALIAS = re.compile(r'[A-Za-z][A-Za-z0-9_.:-]{0,79}\Z')
RULES = ('SIG-01', 'SIG-02', 'MAP-01', 'MAP-03')
ROOT = Path(__file__).resolve().parents[1]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def alias(value):
    return isinstance(value, str) and ALIAS.fullmatch(value) is not None


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def load_bytes(path):
    with open(path, 'rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'input exceeds 10 MiB limit')
    return data


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def decode(text):
    return json.loads(text, object_pairs_hook=no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON number')))


def validate_policy(p):
    require(isinstance(p, dict), 'policy must be an object')
    require(set(p) == {'schema_version', 'approved_peers', 'map_allowed_tuples',
                       'rate_limit_per_peer_operation_60s'}, 'unexpected policy fields')
    require(type(p['schema_version']) is int and p['schema_version'] == 1, 'policy schema must be 1')
    peers = p['approved_peers']
    require(isinstance(peers, list) and peers, 'approved_peers must be nonempty')
    ids = set()
    for peer in peers:
        require(isinstance(peer, dict) and set(peer) == {'id', 'ip', 'source_port', 'point_code', 'routing_context'}, 'invalid peer fields')
        require(alias(peer['id']) and peer['id'] not in ids, 'invalid or duplicate peer alias')
        ids.add(peer['id'])
        ipaddress.ip_address(peer['ip'])
        require(integer(peer['source_port'], 1, 65535), 'invalid source port')
        require(isinstance(peer['point_code'], str) and re.fullmatch(r'[0-7]\.\d{1,3}\.[0-7]', peer['point_code']) is not None and int(peer['point_code'].split('.')[1]) <= 255, 'invalid ITU point code')
        require(integer(peer['routing_context'], 0, 4294967295), 'invalid routing context')
    tuples = p['map_allowed_tuples']
    require(isinstance(tuples, list), 'MAP allowlist must be a list')
    for item in tuples:
        require(isinstance(item, dict) and set(item) == {'peer_id', 'direction', 'operation', 'application_context', 'destination_alias'}, 'invalid MAP tuple fields')
        require(all(alias(v) for v in item.values()), 'MAP tuple values must be aliases')
        require(item['direction'] in ('inbound', 'outbound'), 'invalid MAP direction')
    threshold = p['rate_limit_per_peer_operation_60s']
    require(threshold is None or integer(threshold, 1, 1000000), 'invalid rate threshold')
    return p


def analyze(raw, policy):
    p = validate_policy(policy)
    report = {'schema_version': 1, 'mode': 'offline_normalized_events',
              'enforcement': False, 'events_processed': 0, 'duplicates_skipped': 0,
              'alerts': [], 'data_quality': [], 'blocked': [],
              'evaluated': {rule: 0 for rule in RULES},
              'unsupported_rules': ['MAP-02'], 'verdict': 'NOT_TESTED'}
    seen = {}
    windows = defaultdict(deque)
    last_time = None
    for number, line in enumerate(raw.decode('utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = decode(line)
            require(isinstance(event, dict), 'event must be an object')
            common = {'timestamp_utc', 'sensor_id', 'event_id', 'scenario_id', 'protocol', 'peer_id', 'direction', 'kind'}
            require(common <= set(event), 'missing common field')
            require(all(alias(event[k]) for k in common - {'timestamp_utc'}), 'invalid alias')
            require(event['direction'] in ('inbound', 'outbound'), 'invalid direction')
            stamp = event['timestamp_utc']
            require(isinstance(stamp, str) and stamp.endswith('Z'), 'timestamp must use UTC Z')
            now = datetime.fromisoformat(stamp[:-1] + '+00:00').timestamp()
            kind = event['kind']
            extra = {'association': {'source_ip', 'source_port'},
                     'registration': {'point_code', 'routing_context'},
                     'map_invoke': {'operation', 'application_context', 'destination_alias'}}
            require(kind in extra, 'unsupported event kind')
            require(set(event) == common | extra[kind], 'missing or unexpected event fields')
            require(event['protocol'] == ('MAP' if kind == 'map_invoke' else 'M3UA'), 'protocol does not match kind')
            if kind == 'association':
                ipaddress.ip_address(event['source_ip'])
                require(integer(event['source_port'], 1, 65535), 'invalid source port')
            elif kind == 'registration':
                require(isinstance(event['point_code'], str) and re.fullmatch(r'[0-7]\.\d{1,3}\.[0-7]', event['point_code']) is not None and int(event['point_code'].split('.')[1]) <= 255, 'invalid ITU point code')
                require(integer(event['routing_context'], 0, 4294967295), 'invalid routing context')
            else:
                require(all(alias(event[k]) for k in extra[kind]), 'MAP fields must be aliases')
            key = (event['sensor_id'], event['event_id'])
            if key in seen:
                require(seen[key] == event, 'event ID reused with different content')
                report['duplicates_skipped'] += 1
                continue
            require(last_time is None or now >= last_time, 'events must be in timestamp order')
            last_time = now
            seen[key] = event
            report['events_processed'] += 1
        except (ValueError, TypeError, KeyError, OverflowError):
            # Never copy raw events, subscriber data or parser excerpts into output.
            report['data_quality'].append({'line': number, 'reason': 'invalid_or_unsupported_event'})
            continue

        def alert(rule):
            report['alerts'].append({'rule_id': rule, 'line': number})

        def blocked(rule):
            report['blocked'].append({'rule_id': rule, 'line': number, 'reason': 'policy_not_configured'})

        if kind == 'association':
            report['evaluated']['SIG-01'] += 1
            if not any((x['id'], x['ip'], x['source_port']) == (event['peer_id'], event['source_ip'], event['source_port']) for x in p['approved_peers']):
                alert('SIG-01')
        elif kind == 'registration':
            report['evaluated']['SIG-02'] += 1
            if not any((x['id'], x['point_code'], x['routing_context']) == (event['peer_id'], event['point_code'], event['routing_context']) for x in p['approved_peers']):
                alert('SIG-02')
        else:
            if not p['map_allowed_tuples']:
                blocked('MAP-01')
            else:
                report['evaluated']['MAP-01'] += 1
                fields = ('peer_id', 'direction', 'operation', 'application_context', 'destination_alias')
                if not any(all(event[k] == x[k] for k in fields) for x in p['map_allowed_tuples']):
                    alert('MAP-01')
            threshold = p['rate_limit_per_peer_operation_60s']
            if threshold is None:
                blocked('MAP-03')
            else:
                report['evaluated']['MAP-03'] += 1
                window = windows[(event['sensor_id'], event['peer_id'], event['operation'])]
                while window and window[0] <= now - 60:
                    window.popleft()
                window.append(now)
                if len(window) > threshold:
                    alert('MAP-03')
    report['alert_counts'] = dict(Counter(x['rule_id'] for x in report['alerts']))
    report['not_evaluated'] = [rule for rule, count in report['evaluated'].items() if count == 0]
    report['verdict'] = ('INCONCLUSIVE' if report['data_quality'] else
                         'ALERTS' if report['alerts'] else
                         'BLOCKED' if report['blocked'] else
                         'NO_ALERTS' if report['events_processed'] else 'NOT_TESTED')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new private JSON report; never overwritten')
    args = parser.parse_args(argv)
    try:
        events = load_bytes(args.events)
        policy = load_bytes(args.policy)
        report = analyze(events, decode(policy))
        digest = lambda b: hashlib.sha256(b).hexdigest()
        report['manifest'] = {'events_sha256': digest(events), 'policy_sha256': digest(policy),
                              'analyzer_sha256': digest(Path(__file__).read_bytes()),
                              'config_sha256': {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in sorted((ROOT / 'configs').glob('*/*.cfg'))}}
        require(args.output.parent.is_dir(), 'output parent must already exist')
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
        print(f"{report['verdict']}: {report['events_processed']} events, {len(report['alerts'])} alerts, {len(report['data_quality'])} invalid records")
        return 3 if report['data_quality'] or report['blocked'] or not report['events_processed'] else 1 if report['alerts'] else 0
    except (OSError, ValueError, TypeError, KeyError):
        print('Input/policy/output error. Check schema, paths, size limits and that output does not exist.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
