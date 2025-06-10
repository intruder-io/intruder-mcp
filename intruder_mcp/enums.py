from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime, date
from enum import Enum

class ExploitLikelihoodEnum(str, Enum):
    RARE = "rare"
    UNLIKELY = "unlikely"
    LIKELY = "likely"
    VERY_LIKELY = "very_likely"
    KNOWN = "known"
    UNKNOWN = "unknown"

class ScanStatusField(str, Enum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    CANCELLED_NO_ACTIVE_TARGETS = "cancelled_no_active_targets"
    CANCELLED_NO_VALID_TARGETS = "cancelled_no_valid_targets"
    ANALYSING_RESULTS = "analysing_results"

class ScanTypeEnum(str, Enum):
    ASSESSMENT_SCHEDULE = "assessment_schedule"
    NEW_SERVICE = "new_service"
    CLOUDBOT_NEW_TARGET = "cloudbot_new_target"
    RAPID_REMEDIATION = "rapid_remediation"
    ADVISORY = "advisory"
    CLOUD_SECURITY = "cloud_security"

class SchedulePeriodEnum(str, Enum):
    MONTHLY = "monthly"
    DAILY = "daily"
    ONE_OFF = "one_off"
    WEEKLY = "weekly"
    QUARTERLY = "quarterly"

class TypeEnum(str, Enum):
    HTTP_HEADER = "http_header"
    SESSION_COOKIE = "session_cookie"
    HTTP = "http"
    FORM = "form"
    RECORDED = "recorded"
    UNAUTHENTICATED = "unauthenticated"

class TargetStatusEnum(str, Enum):
    LIVE = "live"
    LICENSE_EXCEEDED = "license_exceeded"
    UNSCANNED = "unscanned"
    UNRESPONSIVE = "unresponsive"
    AGENT_UNINSTALLED = "agent_uninstalled"

class LicenseTypeEnum(str, Enum):
    # Ignore the swagger file here - it incorrectly defines this as an int
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"

class TargetAuthenticationGenericJSONField(BaseModel):
    name: str
    value: str

class PluginDetail(BaseModel):
    cve: Optional[List[Any]] = None
    cvss_base_score: Optional[str] = None
    cvss3_base_score: Optional[str] = None
    name: str

class Tags(BaseModel):
    name: str = Field(..., max_length=40)

class TagsRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=40)

class TargetAuthentications(BaseModel):
    id: int
    url: str
    type: TypeEnum
    name: Optional[str] = None
    logout_url: Optional[str] = None
    logged_in_indicator: Optional[str] = None
    csrf_token_field: Optional[str] = None
    login_form_url: Optional[str] = None
    login_url: Optional[str] = None
    password_field: Optional[str] = None
    realm: Optional[str] = None
    username_field: Optional[str] = None
    enabled: Optional[bool] = None
    is_ajax_spider_enabled: Optional[bool] = None
    recorded_login_file: Optional[HttpUrl] = None

class TargetAuthenticationsRequest(BaseModel):
    url: str = Field(..., min_length=1)
    type: TypeEnum
    name: Optional[str] = None
    logout_url: Optional[str] = None
    logged_in_indicator: Optional[str] = None
    csrf_token_field: Optional[str] = None
    login_form_url: Optional[str] = None
    login_url: Optional[str] = None
    password_field: Optional[str] = None
    realm: Optional[str] = None
    username_field: Optional[str] = None
    enabled: Optional[bool] = None
    is_ajax_spider_enabled: Optional[bool] = None
    recorded_login_file: Optional[bytes] = None
    additional_parameters: Optional[List[TargetAuthenticationGenericJSONField]] = None
    cookies: Optional[List[TargetAuthenticationGenericJSONField]] = None
    headers: Optional[List[TargetAuthenticationGenericJSONField]] = None
    password: Optional[str] = Field(None, min_length=1)
    username: Optional[str] = Field(None, min_length=1)

class Target(BaseModel):
    id: int
    address: str
    has_api_schemas: bool
    has_authentications: bool
    license_type: Optional[LicenseTypeEnum] = None
    tags: Optional[List[Optional[str]]] = None
    target_status: TargetStatusEnum

class TargetCreateRequest(BaseModel):
    address: str
    tags: Optional[List[str]] = Field(None, min_items=1, max_length=40)
    target_authentication: Optional[TargetAuthenticationsRequest] = None

class Scan(BaseModel):
    id: int
    status: ScanStatusField
    created_at: datetime
    target_addresses: Optional[List[str]] = None
    scan_type: ScanTypeEnum
    schedule_period: SchedulePeriodEnum
    start_time: Optional[datetime] = None
    completed_time: Optional[datetime] = None

class ScanList(BaseModel):
    id: int
    status: ScanStatusField
    created_at: datetime
    scan_type: ScanTypeEnum
    schedule_period: Optional[SchedulePeriodEnum] = None

class ScanRequest(BaseModel):
    target_addresses: Optional[List[str]] = None
    tag_names: Optional[List[str]] = Field(None, min_items=1)

class ScannerOutputList(BaseModel):
    id: int
    plugin: PluginDetail
    scanner_output: Optional[List[Any]] = None

class Issue(BaseModel):
    id: int
    severity: str
    title: str
    description: str
    remediation: str
    snoozed: bool
    snooze_reason: Optional[str] = None
    snooze_until: Optional[date] = None
    occurrences: Optional[HttpUrl] = None
    exploit_likelihood: Union[ExploitLikelihoodEnum, None]
    cvss_score: Optional[float] = None

class Occurrence(BaseModel):
    id: int
    target: str
    port: Optional[Union[str, int]] = None
    protocol: str
    extra_info: Optional[Dict[str, str]] = None
    age: str
    snoozed: bool
    snooze_reason: Optional[str] = None
    snooze_until: Optional[date] = None
    exploit_likelihood: Union[ExploitLikelihoodEnum, None]
    cvss_score: Optional[float] = None

class Licenses(BaseModel):
    total_infrastructure_licenses: int
    available_infrastructure_licenses: int
    consumed_infrastructure_licenses: int
    total_application_licenses: int
    available_application_licenses: int
    consumed_application_licenses: int

class Health(BaseModel):
    status: str = Field(..., description="API health status")
    authenticated_as: str = Field(..., format="email")

class APISchemas(BaseModel):
    id: int
    base_url: HttpUrl
    name: str
    target_authentication_id: Optional[int] = None

class APISchemasRequest(BaseModel):
    base_url: HttpUrl = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    target_authentication_id: Optional[int] = None
    file: bytes

class PatchedAPISchemasRequest(BaseModel):
    base_url: Optional[HttpUrl] = Field(None, min_length=1)
    name: Optional[str] = Field(None, min_length=1)
    target_authentication_id: Optional[int] = None
    file: Optional[bytes] = None

class PatchedTargetAuthenticationsRequest(BaseModel):
    url: Optional[str] = Field(None, min_length=1)
    type: Optional[TypeEnum] = None
    name: Optional[str] = None
    logout_url: Optional[str] = None
    logged_in_indicator: Optional[str] = None
    csrf_token_field: Optional[str] = None
    login_form_url: Optional[str] = None
    login_url: Optional[str] = None
    password_field: Optional[str] = None
    realm: Optional[str] = None
    username_field: Optional[str] = None
    enabled: Optional[bool] = None
    is_ajax_spider_enabled: Optional[bool] = None
    recorded_login_file: Optional[bytes] = None
    additional_parameters: Optional[List[TargetAuthenticationGenericJSONField]] = None
    cookies: Optional[List[TargetAuthenticationGenericJSONField]] = None
    headers: Optional[List[TargetAuthenticationGenericJSONField]] = None
    password: Optional[str] = Field(None, min_length=1)
    username: Optional[str] = Field(None, min_length=1)

# Paginated response models
class PaginatedResponse(BaseModel):
    count: int
    next: Optional[HttpUrl] = None
    previous: Optional[HttpUrl] = None

class PaginatedIssueList(PaginatedResponse):
    results: List[Issue]

class PaginatedOccurrenceList(PaginatedResponse):
    results: List[Occurrence]

class PaginatedScanListList(PaginatedResponse):
    results: List[ScanList]

class PaginatedScannerOutputListList(PaginatedResponse):
    results: List[ScannerOutputList]

class PaginatedTagsList(PaginatedResponse):
    results: List[Tags]

class PaginatedTargetAuthenticationsList(PaginatedResponse):
    results: List[TargetAuthentications]

class PaginatedTargetList(PaginatedResponse):
    results: List[Target]

class PaginatedLicensesList(PaginatedResponse):
    results: List[Licenses]

class IssueSnoozeReasonEnum(str, Enum):
    ACCEPT_RISK = "ACCEPT_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATING_CONTROLS = "MITIGATING_CONTROLS"

class OccurrencesSnoozeReasonEnum(str, Enum):
    ACCEPT_RISK = "ACCEPT_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATING_CONTROLS = "MITIGATING_CONTROLS"

class SnoozeIssueRequest(BaseModel):
    details: Optional[str] = None
    duration: Optional[int] = None
    duration_type: Optional[str] = None  # Should match DurationTypeEnum if defined
    reason: IssueSnoozeReasonEnum

class SnoozeOccurrenceRequest(BaseModel):
    details: Optional[str] = None
    duration: Optional[int] = None
    duration_type: Optional[str] = None  # Should match DurationTypeEnum if defined
    reason: OccurrencesSnoozeReasonEnum 