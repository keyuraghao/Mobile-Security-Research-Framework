"""Background-task plumbing for the GUI.

Engine actions can block (a MobSF scan, an nmap sweep). Running them on the Qt
main thread would freeze the UI, so every action runs on a ``QThreadPool`` via
:class:`Worker`, which emits the result or the error back to the UI thread.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import QObject, QRunnable, pyqtSignal, pyqtSlot


class WorkerSignals(QObject):
    """Signals emitted by a :class:`Worker`."""

    result = pyqtSignal(object)
    error = pyqtSignal(str)
    finished = pyqtSignal()


class Worker(QRunnable):
    """Run ``fn(*args, **kwargs)`` off the UI thread and emit the outcome."""

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @pyqtSlot()
    def run(self) -> None:  # noqa: D401 - QRunnable entry point
        try:
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:  # surfaced to the UI as an error string
            self.signals.error.emit(str(exc))
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit()
