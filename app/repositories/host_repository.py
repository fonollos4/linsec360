from database import get_db


class HostRepository:
    """Repository for all host-related database operations."""

    @staticmethod
    def list_all():
        return get_db().execute(
            "SELECT * FROM hosts ORDER BY added_date DESC"
        ).fetchall()

    @staticmethod
    def get_by_id(host_id):
        return get_db().execute(
            "SELECT * FROM hosts WHERE id = ?",
            (host_id,),
        ).fetchone()

    @staticmethod
    def create(host_data):
        db = get_db()
        cursor = db.execute(
            "INSERT INTO hosts "
            "(name, ip, environment, security_level, groups, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                host_data["name"],
                host_data["ip"],
                host_data["environment"],
                host_data["security_level"],
                host_data["groups"],
                host_data["status"],
            ),
        )
        db.commit()
        return cursor.lastrowid

    @staticmethod
    def update_status(host_name, status):
        HostRepository.update_statuses([host_name], status)

    @staticmethod
    def update_statuses(host_names, status):
        if not host_names:
            return
        db = get_db()
        db.executemany(
            "UPDATE hosts SET status = ? WHERE name = ?",
            ((status, host_name) for host_name in host_names),
        )
        db.commit()

    @staticmethod
    def delete(host_id):
        db = get_db()
        host = HostRepository.get_by_id(host_id)
        if host is None:
            return None
        db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        db.commit()
        return dict(host)

    @staticmethod
    def get_by_environment(environment):
        return get_db().execute(
            "SELECT name FROM hosts WHERE environment = ?",
            (environment,),
        ).fetchall()

    @staticmethod
    def get_by_group(group, environment):
        return get_db().execute(
            "SELECT name FROM hosts "
            "WHERE instr(',' || COALESCE(groups, '') || ',', ',' || ? || ',') > 0 "
            "AND environment = ?",
            (group, environment),
        ).fetchall()
