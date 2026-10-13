import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import numpy as np

from app.detection import _behavior_features


class BehaviorFeatureTests(unittest.TestCase):
    def test_features_capture_recent_activity_and_source_novelty(self):
        start = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)
        events = [
            SimpleNamespace(occurred_at=start, event_type="page_view", source_ip="192.0.2.1"),
            SimpleNamespace(occurred_at=start + timedelta(minutes=1), event_type="login_failed", source_ip="192.0.2.2"),
            SimpleNamespace(occurred_at=start + timedelta(minutes=2), event_type="login_failed", source_ip="192.0.2.2"),
        ]

        features = _behavior_features(events)

        self.assertEqual(features.shape, (3, 7))
        self.assertAlmostEqual(features[1, 3], np.log1p(1))
        self.assertEqual(features[1, 5], 1)
        self.assertAlmostEqual(features[2, 4], np.log1p(1))
        self.assertEqual(features[2, 5], 0)
        self.assertAlmostEqual(features[2, 6], np.log1p(1))


if __name__ == "__main__":
    unittest.main()