from database import get_db


class StatsRepository:
    """Repository for stats persistence and queries."""

    @staticmethod
    def get_latest():
        return get_db().execute(
            "SELECT * FROM stats ORDER BY timestamp DESC, id DESC LIMIT 1"
        ).fetchone()

    @staticmethod
    def refresh():
        db = get_db()
        total_hosts = db.execute(
            "SELECT COUNT(*) FROM hosts"
        ).fetchone()[0]
        secured_hosts = db.execute(
            "SELECT COUNT(*) FROM hosts WHERE status = 'secured'"
        ).fetchone()[0]
        # Legacy column is NOT NULL. It is retained as a placeholder but is
        # never exposed: the API reports vulnerability data as "not configured"
        # until a real Wazuh source is connected.
        vulnerabilities = 0
        db.execute(
            "INSERT INTO stats "
            "(host_count, secured_count, vulnerabilities_count) VALUES (?, ?, ?)",
            (total_hosts, secured_hosts, vulnerabilities),
        )
        db.commit()
