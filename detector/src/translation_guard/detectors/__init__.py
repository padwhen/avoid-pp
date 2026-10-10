"""Detector implementations behind one async interface."""

from translation_guard.detectors.base import Detector, DetectorUnavailable
from translation_guard.detectors.fake import FakeDetector

__all__ = ["Detector", "DetectorUnavailable", "FakeDetector"]
