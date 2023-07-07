import unittest
import tempfile
import os

import mitre_attack_navigator_layer_builder.loader as loader
import mitre_attack_navigator_layer_builder.analyzer as analyzer


RESOURCES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources"
)

OILRIG_LAYER = os.path.join(
    RESOURCES_DIR,
    "data/mitre-attack-navigator-layers/mitre-attack/G0049-enterprise-layer.json",
)


class Tests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(OILRIG_LAYER))
        self.assertTrue(os.path.getsize(OILRIG_LAYER) > 0)

    def test_read_layer(self):
        layer = loader.read_layer(OILRIG_LAYER)
        self.assertTrue(isinstance(layer, loader.Layer))

    def test_save_layer(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            layer = loader.read_layer(OILRIG_LAYER)
            loader.save_layer(layer, path)

            self.assertTrue(os.path.exists(path))
            self.assertTrue(os.path.getsize(path) > 0)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_read_write_layer(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            a = loader.read_layer(OILRIG_LAYER)
            loader.save_layer(a, path)

            self.assertTrue(os.path.exists(path))
            self.assertTrue(os.path.getsize(path) > 0)

            b = loader.read_layer(path)
            print(a)
            print(b)
            self.assertEqual(a, b)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_get_layer_summary(self):
        layer = loader.read_layer(OILRIG_LAYER)
        summary = analyzer.get_layer_summary(layer)

        self.assertEqual(summary.total_selected_techniques, 73)
        self.assertEqual(summary.total_unique_colors, 1)
        self.assertEqual(summary.total_unique_scores, 1)
