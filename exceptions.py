"""
Custom exception hierarchy for Security Investigator.

Provides specific exception types for different failure modes:
- Configuration loading
- External API calls (with status_code and service tracking)
- IP enrichment
- Report generation
- Data validation
"""


class SecurityInvestigatorError(Exception):
    """Base exception for all Security Investigator errors."""
    pass


class ConfigurationError(SecurityInvestigatorError):
    """Raised when configuration loading or validation fails."""
    pass


class APIError(SecurityInvestigatorError):
    """Raised when an external API call fails.

    Attributes:
        status_code: HTTP status code from the failed request (None if no response).
        service: Name of the external service that failed.
    """

    def __init__(self, message: str, status_code: int = None, service: str = ""):
        self.status_code = status_code
        self.service = service
        super().__init__(message)


class EnrichmentError(APIError):
    """Raised when IP enrichment fails."""
    pass


class ReportGenerationError(SecurityInvestigatorError):
    """Raised when report generation fails."""
    pass


class DataValidationError(SecurityInvestigatorError):
    """Raised when input data is invalid or missing required fields."""
    pass
