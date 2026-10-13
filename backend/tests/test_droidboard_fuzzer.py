import io
import sys
from pathlib import Path

import pytest
from flask import Flask

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import droidboard.app as board


RAW_REQUEST = 'POST http://example.test/FUZZ HTTP/1.1\nHost: example.test\n\nvalue=FUZZ'


def config_from_upload(content=None, range_expression='2-4'):
    data = {'request_raw': RAW_REQUEST, 'range': range_expression, 'max_thread': '3', 'delay': '25'}
    if content is not None:
        data['wordlist'] = (io.BytesIO(content), 'values.txt')
    with Flask(__name__).test_request_context('/fuzzer/start', method='POST', data=data):
        return board._fuzzer_config_from_form(1)


def test_uploaded_wordlist_replaces_range_and_preserves_payloads():
    config = config_from_upload(b'\xef\xbb\xbfalpha\r\nbeta\ngamma\r\n\rdelta\nalpha\n spaced \n', 'invalid')
    expected = ['alpha', 'beta', 'gamma', 'delta', 'alpha', ' spaced ']
    assert config['values'] == expected
    assert config['wordlist_name'] == 'values.txt'
    assert config['max_thread'] == 3
    assert config['delay'] == 25
    attempts = board._build_fuzzer_attempts(config)
    assert [attempt.value for attempt in attempts] == expected
    for attempt in attempts:
        assert attempt.raw_request == RAW_REQUEST.replace('FUZZ', attempt.value)
        assert '\r' not in attempt.value and '\n' not in attempt.value
    # Restart uses a copy of the stored config, without uploading the file again.
    assert board._build_fuzzer_attempts(dict(config)) == attempts


def test_numeric_range_remains_available():
    config = config_from_upload()
    assert 'values' not in config
    assert [attempt.value for attempt in board._build_fuzzer_attempts(config)] == ['2', '3', '4']


@pytest.mark.parametrize('content, message', [(b'', 'non-empty'), (b'\r\n\n\r', 'non-empty'), (b'\xff', 'UTF-8')])
def test_invalid_wordlists_are_rejected(content, message):
    with pytest.raises(ValueError, match=message):
        config_from_upload(content)


def test_live_progress_tracks_all_results_even_with_pagination_and_filter(monkeypatch):
    from types import SimpleNamespace

    job = {
        'id': 1, 'project_id': 1, 'config': {}, 'status': 'running',
        'total': 10, 'created_at': '', 'finished_at': '', 'error': '',
        'results': [{'value': 'match'}, {'value': 'other'}],
    }
    monkeypatch.setattr(board, 'FUZZ_JOBS', {1: job})
    monkeypatch.setattr(board, 'get_settings', lambda: SimpleNamespace(droidboard_page_size=1))
    app = Flask(__name__)
    app.secret_key = 'test'
    with app.test_request_context('/?fuzzer_q_1=match'):
        before = board._fuzzer_context(None, 1)
        job['results'].append({'value': 'another'})
        after = board._fuzzer_context(None, 1)
        assert before['fuzzer_jobs'][0]['completed'] == 2
        assert after['fuzzer_jobs'][0]['completed'] == 3
        assert after['fuzzer_jobs'][0]['result_total'] == 1
        assert before['fuzzer_live_version'] != after['fuzzer_live_version']
        job['status'] = 'done'
        assert board._fuzzer_context(None, 1)['fuzzer_live_version'] != after['fuzzer_live_version']


def test_fuzzer_preserves_body_whitespace_and_recalculates_length(monkeypatch):
    import httpx
    import threading
    from app.services import fuzzer

    raw = 'PATCH http://example.test/api HTTP/1.1\r\nContent-Length: 4\r\n\r\nFUZZ \n\n  '
    with Flask(__name__).test_request_context('/fuzzer/start', method='POST', data={
        'request_raw': raw, 'range': '1-2',
    }):
        config = board._fuzzer_config_from_form(1)
    assert config['request_raw'] == raw
    config['values'] = ['è', 'longer payload']
    captured = []

    def receive(request):
        captured.append(request)
        return httpx.Response(200, content=b'ok')

    def send(method, url, **kwargs):
        kwargs.pop('verify')
        with httpx.Client(transport=httpx.MockTransport(receive)) as client:
            return client.request(method, url, **kwargs)

    monkeypatch.setattr('app.services.repeater.httpx.request', send)
    for attempt in board._build_fuzzer_attempts(config):
        result = fuzzer._send_attempt(attempt, 0, threading.Event(), None)
        assert result['error'] == ''
    assert [r.content for r in captured] == [b'\xc3\xa8 \n\n  ', b'longer payload \n\n  ']
    for request in captured:
        assert request.headers['content-length'] == str(len(request.content))


def test_response_matches_saved_counted_and_rendered(monkeypatch):
    import threading
    from types import SimpleNamespace
    from flask import render_template

    with Flask(__name__).test_request_context('/fuzzer/start', method='POST', data={
        'request_raw': RAW_REQUEST, 'range': '1-1',
        'response_matches': 'error\r\nadodb\n\nERROR\n .* \n<script>',
    }):
        config = board._fuzzer_config_from_form(1)
    assert config['response_matches'] == ['error', 'adodb', '.*', '<script>']
    job = {
        'id': 1, 'project_id': 1, 'config': config, 'status': 'running',
        'total': 1, 'created_at': '', 'finished_at': '', 'error': '',
        'results': [], 'stop_event': threading.Event(),
    }
    result = {
        'response_raw': 'HTTP 200\r\nX-Error: yes\r\n\r\nERROR error AdoDB adodb .* <script>',
        'request_raw': 'error error', 'error': '', 'duration_ms': 125,
        'source': 'raw', 'name': 'FUZZ', 'value': '1', 'status_code': 200, 'size': 40,
        'url': 'http://example.test/1',
    }
    monkeypatch.setattr(board, 'FUZZ_JOBS', {1: job})
    monkeypatch.setattr(board.fuzzer, 'run_attempts', lambda *args, **kwargs: iter([result]))
    board._run_fuzzer_job(1, [])
    assert job['status'] == 'done'
    assert job['results'][0]['match_counts'] == {'error': 3, 'adodb': 2, '.*': 1, '<script>': 1}
    assert dict(job['config'])['response_matches'] == config['response_matches']

    monkeypatch.setattr(board, 'init_db', lambda: None)
    app = board.create_app()
    with app.test_request_context('/?fuzzer_sort_1=match:error&fuzzer_order_1=desc'):
        public = board._prepare_public_fuzzer_job(board._public_fuzzer_job(job), 20)
        assert public['result_sort'] == 'match:error'
        html = render_template('_fuzzer.html', project=SimpleNamespace(id=1),
            fuzzer_prefill={}, fuzzer_jobs=[public], fuzzer_live_version='', url_args=board._url_args)
    assert 'Delay (ms)' in html and '<td>125</td>' in html
    assert 'Matches: error' in html and 'Matches: adodb' in html
    assert 'Matches: &lt;script&gt;' in html
    assert '<strong class="nes-text is-error">3</strong>' in html
    assert 'colspan="12"' in html


def test_response_match_sorting_and_network_errors():
    assert board._fuzzer_match_counts({'error': 'error adodb', 'response_raw': 'error'}, ['error']) == {'error': 0}
    assert board._fuzzer_match_counts({'response_raw': 'aaaa'}, ['aa', 'absent']) == {'aa': 2, 'absent': 0}
    rows = [{'match_counts': {'error': 2}}, {'match_counts': {'error': 10}}, {}]
    assert board._sort_fuzzer_results(rows, 'match:error', 'desc') == [rows[1], rows[0], rows[2]]


def test_response_duration_excludes_configured_pause(monkeypatch):
    from app.services import fuzzer

    clock = [10.0]
    def send(*args, **kwargs):
        clock[0] += 0.125
        return 'HTTP 200\n\nok'
    class Stop:
        def is_set(self):
            return False
        def wait(self, seconds):
            clock[0] += seconds
    monkeypatch.setattr(fuzzer.time, 'perf_counter', lambda: clock[0])
    monkeypatch.setattr(fuzzer, 'send_repeater_request', send)
    attempt = board._build_fuzzer_attempts(config_from_upload())[0]
    result = fuzzer._send_attempt(attempt, 2, Stop(), None)
    assert result['duration_ms'] == 125
    assert clock[0] == 12.125
