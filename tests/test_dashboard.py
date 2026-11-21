import os

import pytest

pytest.importorskip("streamlit")

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_dashboard_loads():
    from streamlit.testing.v1 import AppTest
    app = AppTest.from_file(os.path.join(ROOT, "app.py"))
    app.run(timeout=120)
    assert not app.exception
    assert any("Deputy Graph Audit" in (t.value or "") for t in app.title)
