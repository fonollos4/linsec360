import json

from database import get_db


class DeploymentRepository:
    """Persistence for asynchronous deployment jobs."""

    @staticmethod
    def create(job):
        DeploymentRepository._ensure_table()
        db = get_db()
        db.execute(
            "INSERT INTO deployment_jobs "
            "(job_id, environment, playbook, target_hosts, status, created_at, log_path) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                job["job_id"],
                job["environment"],
                job["playbook"],
                json.dumps(job["target_hosts"]),
                job["status"],
                job["created_at"],
                job["log_path"],
            ),
        )
        db.commit()
        return job

    @staticmethod
    def get_by_id(job_id):
        DeploymentRepository._ensure_table()
        row = get_db().execute(
            "SELECT * FROM deployment_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return DeploymentRepository._to_dict(row)

    @staticmethod
    def list_recent(limit=20):
        DeploymentRepository._ensure_table()
        rows = get_db().execute(
            "SELECT * FROM deployment_jobs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [DeploymentRepository._to_dict(row) for row in rows]

    @staticmethod
    def update_status(job_id, status, *, started_at=None, finished_at=None, error_message=None):
        DeploymentRepository._ensure_table()
        db = get_db()
        db.execute(
            "UPDATE deployment_jobs SET status = ?, started_at = COALESCE(?, started_at), "
            "finished_at = ?, error_message = ? WHERE job_id = ?",
            (status, started_at, finished_at, error_message, job_id),
        )
        db.commit()

    @staticmethod
    def _ensure_table():
        db = get_db()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS deployment_jobs (
                job_id TEXT PRIMARY KEY,
                environment TEXT NOT NULL,
                playbook TEXT NOT NULL,
                target_hosts TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                log_path TEXT NOT NULL,
                error_message TEXT
            )
            """
        )
        db.commit()

    @staticmethod
    def _to_dict(row):
        if row is None:
            return None
        job = dict(row)
        job["target_hosts"] = json.loads(job["target_hosts"])
        return job
