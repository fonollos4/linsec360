from repositories.stats_repository import StatsRepository


class StatsService:
    """Business logic for stats reading and refresh operations."""

    @staticmethod
    def get_current_stats():
        stats = StatsRepository.get_latest()
        data = dict(stats) if stats else {}
        # Do not present a synthetic vulnerability count. The Wazuh client is
        # not implemented yet, so the value is explicitly unknown.
        data["vulnerabilities_count"] = None
        data["vulnerabilities_status"] = "not_configured"
        data["vulnerabilities_source"] = "wazuh"
        return data

    @staticmethod
    def refresh_stats():
        StatsRepository.refresh()
        return StatsService.get_current_stats()
