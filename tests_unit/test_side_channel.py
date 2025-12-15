"""Unit tests for side-channel detection"""
import unittest
from unittest.mock import Mock, patch
from tests.side_channel import SideChannelTest


class TestSideChannelDetection(unittest.TestCase):
    
    def setUp(self):
        self.pentester = Mock()
        self.profile = {
            'timing_thresholds': {'slow_query_ms': 1000},
            'size_thresholds': {'large_response_bytes': 1048576},
            'behavioral_patterns': {
                'network_indicators': ['af_inet', 'tcp://'],
                'shell_indicators': ['/bin/bash', 'subprocess.call'],
                'filesystem_root_indicators': ['/etc/passwd', '/root/']
            }
        }
        self.test = SideChannelTest(self.pentester, self.profile)
    
    def test_timing_side_channel_detection(self):
        """Test timing side-channel with consistent slow responses"""
        tool = {
            'name': 'list_directory',
            'inputSchema': {
                'properties': {
                    'path': {'type': 'string'}
                }
            }
        }
        
        # Simulate consistent slow responses (1.2s each)
        self.pentester.send.return_value = ({}, None)
        with patch('time.time', side_effect=[0, 1.2, 0, 1.2, 0, 1.2]):
            findings = self.test._test_timing_side_channel(tool)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'TIMING_SIDE_CHANNEL')
        self.assertEqual(findings[0]['severity'], 'MEDIUM')
        self.assertIn('1.200s', findings[0]['avg_time'])
    
    def test_timing_no_false_positive_with_jitter(self):
        """Test that high variance (network jitter) doesn't trigger"""
        tool = {
            'name': 'query_api',
            'inputSchema': {
                'properties': {
                    'query': {'type': 'string'}
                }
            }
        }
        
        # Simulate jittery responses (0.5s, 1.5s, 0.8s - high variance)
        self.pentester.send.return_value = ({}, None)
        with patch('time.time', side_effect=[0, 0.5, 0, 1.5, 0, 0.8]):
            findings = self.test._test_timing_side_channel(tool)
        
        # Should not flag due to high variance (stdev > avg * 0.5)
        self.assertEqual(len(findings), 0)
    
    def test_size_side_channel_detection(self):
        """Test large response detection"""
        tool = {
            'name': 'read_file',
            'inputSchema': {
                'properties': {
                    'path': {'type': 'string'}
                }
            }
        }
        
        # Simulate 2MB response
        large_response = 'x' * (2 * 1024 * 1024)
        self.pentester.send.return_value = (large_response, None)
        
        findings = self.test._test_content_and_size(tool)
        
        size_findings = [f for f in findings if f['type'] == 'SIZE_SIDE_CHANNEL']
        self.assertEqual(len(size_findings), 1)
        self.assertEqual(size_findings[0]['severity'], 'MEDIUM')
        self.assertGreater(size_findings[0]['response_size'], 1048576)
    
    def test_shell_activity_detection(self):
        """Test shell execution pattern detection"""
        tool = {
            'name': 'execute',
            'inputSchema': {
                'properties': {
                    'cmd': {'type': 'string'}
                }
            }
        }
        
        response = "Executing: subprocess.call(['ls', '-la'])"
        self.pentester.send.return_value = (response, None)
        
        findings = self.test._test_content_and_size(tool)
        
        shell_findings = [f for f in findings if f['type'] == 'SHELL_ACTIVITY_DETECTED']
        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0]['severity'], 'CRITICAL')
    
    def test_network_activity_detection(self):
        """Test network activity pattern detection"""
        tool = {
            'name': 'fetch',
            'inputSchema': {
                'properties': {
                    'url': {'type': 'string'}
                }
            }
        }
        
        response = "Opening socket: AF_INET connection to tcp://example.com:80"
        self.pentester.send.return_value = (response, None)
        
        findings = self.test._test_content_and_size(tool)
        
        net_findings = [f for f in findings if f['type'] == 'NETWORK_ACTIVITY_DETECTED']
        self.assertEqual(len(net_findings), 1)
        self.assertEqual(net_findings[0]['severity'], 'HIGH')
    
    def test_filesystem_access_detection(self):
        """Test sensitive filesystem access detection"""
        tool = {
            'name': 'read',
            'inputSchema': {
                'properties': {
                    'file': {'type': 'string'}
                }
            }
        }
        
        response = "root:x:0:0:root:/root:/bin/bash\nReading /etc/passwd"
        self.pentester.send.return_value = (response, None)
        
        findings = self.test._test_content_and_size(tool)
        
        fs_findings = [f for f in findings if f['type'] == 'ROOT_FILESYSTEM_ACCESS']
        self.assertEqual(len(fs_findings), 1)
        self.assertEqual(fs_findings[0]['severity'], 'HIGH')
    
    def test_no_false_positives_on_normal_response(self):
        """Test that normal responses don't trigger alerts"""
        tool = {
            'name': 'get_data',
            'inputSchema': {
                'properties': {
                    'id': {'type': 'string'}
                }
            }
        }
        
        response = "User data: John Doe, email: john@example.com"
        self.pentester.send.return_value = (response, None)
        
        findings = self.test._test_content_and_size(tool)
        
        self.assertEqual(len(findings), 0)
    
    def test_exception_handling(self):
        """Test that exceptions are handled gracefully"""
        tool = {
            'name': 'broken_tool',
            'inputSchema': {
                'properties': {
                    'arg': {'type': 'string'}
                }
            }
        }
        
        self.pentester.send.side_effect = TimeoutError("Connection timeout")
        
        # Should not raise, just log and continue
        findings = self.test._test_content_and_size(tool)
        self.assertEqual(len(findings), 0)
    
    def test_profile_defaults(self):
        """Test that defaults are used when profile is missing"""
        test_no_profile = SideChannelTest(self.pentester, None)
        
        self.assertEqual(test_no_profile.timing_threshold, 0.5)  # 500ms default
        self.assertEqual(test_no_profile.size_threshold, 1048576)
        self.assertEqual(test_no_profile.network_indicators, [])
        self.assertEqual(test_no_profile.shell_indicators, [])
        self.assertEqual(test_no_profile.root_indicators, [])


if __name__ == '__main__':
    unittest.main()
