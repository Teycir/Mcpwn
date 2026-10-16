"""tool_injection findings must carry a type and severity"""
from tests.tool_injection import classify_detections


def test_detection_types_map_to_severity():
    assert classify_detections([{'type': 'RCE'}]) == ('RCE', 'CRITICAL')
    assert classify_detections([{'type': 'OOB_DNS'}]) == ('OOB_DNS', 'CRITICAL')
    assert classify_detections([{'type': 'FILE_READ'}]) == ('FILE_READ', 'HIGH')
    assert classify_detections([{'type': 'TIMING', 'elapsed': 0.001}]) == ('TIMING', 'LOW')


def test_strongest_detection_wins():
    findings = [{'type': 'TIMING'}, {'type': 'FILE_READ'}]
    assert classify_detections(findings) == ('FILE_READ', 'HIGH')


def test_no_usable_detection_falls_back_to_medium():
    assert classify_detections([]) == ('INJECTION_ANOMALY', 'MEDIUM')
    assert classify_detections(['Timing delay: 5.00s']) == ('INJECTION_ANOMALY', 'MEDIUM')
