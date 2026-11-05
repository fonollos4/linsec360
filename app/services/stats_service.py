from repositories.stats_repository import StatsRepository


class StatsService:
    """Business logic for stats reading and refresh operations."""

    @staticmethod
    def get_current_stats():
        stats = StatsRepository.get_latest()
        return dict(stats) if stats else {}

    @staticmethod
    def refresh_stats():
        StatsRepository.refresh()
        return StatsService.get_current_stats()
