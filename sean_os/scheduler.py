from __future__ import annotations

import json
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from .store import Actor, SeanOSStore, now


class LocalScheduler:
    """Atomically dispatches cadence work once per local calendar period."""

    def __init__(self, store: SeanOSStore, actor: Actor, timezone_name: str = "America/Toronto"):
        self.store = store
        self.actor = actor
        self.timezone = ZoneInfo(timezone_name)

    def tick(self, at: datetime | None = None) -> list[str]:
        local = (at or datetime.now(self.timezone)).astimezone(self.timezone)
        schedules = [("daily-operational-report", local.strftime("%Y-%m-%d"), "DAILY")]
        if local.weekday() == 0:
            schedules.append(("weekly-operational-report", local.strftime("%G-W%V"), "WEEKLY"))
        dispatched=[]
        for name, period, cadence in schedules:
            work_id = self._dispatch_once(name, period, cadence)
            if work_id:
                dispatched.append(work_id)
        return dispatched

    def _dispatch_once(self, schedule_name: str, period_key: str, cadence: str) -> str | None:
        self.store._authorize(self.actor, "IAC", (), "write")
        work_id=str(uuid.uuid4()); stamp=now()
        try:
            self.store.connection.execute("BEGIN IMMEDIATE")
            exists=self.store.connection.execute(
                "SELECT work_id FROM schedule_dispatches WHERE schedule_name=? AND period_key=?",
                (schedule_name, period_key),
            ).fetchone()
            if exists:
                self.store.connection.commit()
                return None
            self.store.connection.execute(
                """INSERT INTO work_queue
                   (id, task_type, owner_scope, payload, status, priority, max_attempts,
                    available_at, created_at, updated_at)
                   VALUES (?, 'GENERATE_OPERATIONAL_REPORT', 'IAC', ?, 'QUEUED', 50, 3, ?, ?, ?)""",
                (work_id, json.dumps({"cadence":cadence, "period_key":period_key}, sort_keys=True),
                 stamp, stamp, stamp),
            )
            self.store.connection.execute(
                """INSERT INTO schedule_dispatches(schedule_name, period_key, work_id, dispatched_at)
                   VALUES (?, ?, ?, ?)""", (schedule_name, period_key, work_id, stamp),
            )
            self.store.connection.commit()
        except Exception:
            self.store.connection.rollback()
            raise
        self.store.record_policy_decision(
            self.actor, work_id, True, "Scheduled work dispatched",
            {"schedule_name":schedule_name, "period_key":period_key},
        )
        return work_id
