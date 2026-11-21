import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_reproduce_script_passes():
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "reproduce_results.py")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0
    assert "reproduce exactly" in proc.stdout


def test_build_cases_script_runs(tmp_path):
    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "scripts", "build_cases.py")],
        capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0
    assert "290 traces" in proc.stdout


def test_notebooks_run():
    for name in ("01_demo_run.py", "02_evaluation_experiment.py"):
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "notebooks", name)],
            capture_output=True, text=True, cwd=ROOT)
        assert proc.returncode == 0, proc.stderr
