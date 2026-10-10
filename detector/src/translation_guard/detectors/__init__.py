"""Detector implementations behind one async interface."""

from translation_guard.detectors.base import Detector, DetectorUnavailable
from translation_guard.detectors.claude import ClaudeDetector
from translation_guard.detectors.fake import FakeDetector

__all__ = ["ClaudeDetector", "Detector", "DetectorUnavailable", "FakeDetector"]
