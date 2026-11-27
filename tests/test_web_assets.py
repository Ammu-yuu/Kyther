"""Static guards for the browser bundle (no headless browser needed)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


class WebAssetTests(unittest.TestCase):
    def test_home_view_imports_every_shared_helper_it_calls(self):
        src = (_ROOT / "kyther/web/assets/js/scan.js").read_text()
        start = src.index("const {")
        end = src.index("} = K;", start)
        imported = src[start:end]
        # These are exported by core.js on window.Kyther. Calling one without
        # destructuring it throws mid-render (which is how the Home view used
        # to lose all results when a profile contained a link or avatar).
        helpers = ("esc", "safeHref", "put", "addLog", "renderStats",
                   "requestJson", "requestBlob", "setButtonBusy", "isAbort")
        for name in helpers:
            if re.search(r"(?<![.\w])" + name + r"\s*\(", src[end:]):
                self.assertRegex(imported, r"\b" + name + r"\b",
                                 f"scan.js calls {name}() without importing it")


if __name__ == "__main__":
    unittest.main()
