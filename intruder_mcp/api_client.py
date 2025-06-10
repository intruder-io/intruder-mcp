from typing import List, Optional, Dict, Any, Generator
import httpx
import os
import json
from .enums import (
    Health, Issue, Occurrence, Licenses, Scan, ScanList, ScanRequest, Target, TargetCreateRequest,
    TargetAuthentications, TargetAuthenticationsRequest, Tags, TagsRequest, APISchemas, APISchemasRequest,
    PatchedAPISchemasRequest, PatchedTargetAuthenticationsRequest, PaginatedIssueList, PaginatedOccurrenceList,
    PaginatedScanListList, PaginatedScannerOutputListList, PaginatedTagsList, PaginatedTargetAuthenticationsList,
    PaginatedTargetList, PaginatedLicensesList, ScannerOutputList, SnoozeIssueRequest, SnoozeOccurrenceRequest,
    IssueSnoozeReasonEnum, OccurrencesSnoozeReasonEnum
)

class IntruderAPI:
    def __init__(self, api_key: str):
        self.base_url = "https://api.intruder.io/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Intruder-MCP/1.0"
        }
        self.client = httpx.Client(headers=self.headers)

    def get_health(self) -> Health:
        return Health(**self.client.get(f"{self.base_url}/health/").json())

    def list_issues(self, severity: Optional[str] = None, snoozed: Optional[bool] = None, 
                   issue_ids: Optional[List[int]] = None, tag_names: Optional[List[str]] = None,
                   target_addresses: Optional[List[str]] = None, limit: Optional[int] = None,
                   offset: Optional[int] = None) -> PaginatedIssueList:
        params = {}
        if severity:
            params["severity"] = severity
        if snoozed is not None:
            params["snoozed"] = snoozed
        if issue_ids:
            params["issue_ids"] = issue_ids
        if tag_names:
            params["tag_names"] = tag_names
        if target_addresses:
            params["target_addresses"] = target_addresses
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedIssueList(**self.client.get(f"{self.base_url}/issues/", params=params).json())

    def list_issues_all(self, severity: Optional[str] = None, snoozed: Optional[bool] = None,
                       issue_ids: Optional[List[int]] = None, tag_names: Optional[List[str]] = None,
                       target_addresses: Optional[List[str]] = None) -> Generator[Issue, None, None]:
        offset = 0
        while True:
            response = self.list_issues(severity=severity, snoozed=snoozed, issue_ids=issue_ids,
                                      tag_names=tag_names, target_addresses=target_addresses,
                                      limit=100, offset=offset)
            for issue in response.results:
                yield issue
            if not response.next:
                break
            offset += len(response.results)

    def get_issue_occurrences(self, issue_id: int, snoozed: Optional[bool] = None,
                             tag_names: Optional[List[str]] = None,
                             target_addresses: Optional[List[str]] = None,
                             limit: Optional[int] = None, offset: Optional[int] = None) -> PaginatedOccurrenceList:
        params = {}
        if snoozed is not None:
            params["snoozed"] = snoozed
        if tag_names:
            params["tag_names"] = tag_names
        if target_addresses:
            params["target_addresses"] = target_addresses
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedOccurrenceList(**self.client.get(f"{self.base_url}/issues/{issue_id}/occurrences/", params=params).json())

    def get_issue_occurrences_all(self, issue_id: int, snoozed: Optional[bool] = None,
                                 tag_names: Optional[List[str]] = None,
                                 target_addresses: Optional[List[str]] = None) -> Generator[Occurrence, None, None]:
        offset = 0
        while True:
            response = self.get_issue_occurrences(issue_id, snoozed=snoozed, tag_names=tag_names,
                                                target_addresses=target_addresses, limit=100, offset=offset)
            for occurrence in response.results:
                yield occurrence
            if not response.next:
                break
            offset += len(response.results)

    def get_scanner_output(self, issue_id: int, occurrence_id: int,
                          limit: Optional[int] = None, offset: Optional[int] = None) -> PaginatedScannerOutputListList:
        params = {}
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedScannerOutputListList(**self.client.get(f"{self.base_url}/issues/{issue_id}/occurrences/{occurrence_id}/scanner_output/", params=params).json())

    def get_scanner_output_all(self, issue_id: int, occurrence_id: int) -> Generator[ScannerOutputList, None, None]:
        offset = 0
        while True:
            response = self.get_scanner_output(issue_id, occurrence_id, limit=100, offset=offset)
            for output in response.results:
                yield output
            if not response.next:
                break
            offset += len(response.results)

    def list_licenses(self, limit: Optional[int] = None, offset: Optional[int] = None) -> PaginatedLicensesList:
        params = {}
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedLicensesList(**self.client.get(f"{self.base_url}/licenses/", params=params).json())

    def list_licenses_all(self) -> Generator[Licenses, None, None]:
        offset = 0
        while True:
            response = self.list_licenses(limit=100, offset=offset)
            for license in response.results:
                yield license
            if not response.next:
                break
            offset += len(response.results)

    def list_scans(self, scan_type: Optional[str] = None, schedule_period: Optional[str] = None,
                  status: Optional[str] = None, limit: Optional[int] = None,
                  offset: Optional[int] = None) -> PaginatedScanListList:
        params = {}
        if scan_type:
            params["scan_type"] = scan_type
        if schedule_period:
            params["schedule_period"] = schedule_period
        if status:
            params["status"] = status
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedScanListList(**self.client.get(f"{self.base_url}/scans/", params=params).json())

    def list_scans_all(self, scan_type: Optional[str] = None, schedule_period: Optional[str] = None,
                      status: Optional[str] = None) -> Generator[ScanList, None, None]:
        offset = 0
        while True:
            response = self.list_scans(scan_type=scan_type, schedule_period=schedule_period,
                                     status=status, limit=100, offset=offset)
            for scan in response.results:
                yield scan
            if not response.next:
                break
            offset += len(response.results)

    def list_targets(self, address: Optional[str] = None, target_status: Optional[str] = None,
                    limit: Optional[int] = None, offset: Optional[int] = None) -> PaginatedTargetList:
        params = {}
        if address:
            params["address"] = address
        if target_status:
            params["target_status"] = target_status
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedTargetList(**self.client.get(f"{self.base_url}/targets/", params=params).json())

    def list_targets_all(self, address: Optional[str] = None, target_status: Optional[str] = None) -> Generator[Target, None, None]:
        offset = 0
        while True:
            response = self.list_targets(address=address, target_status=target_status,
                                       limit=100, offset=offset)
            for target in response.results:
                yield target
            if not response.next:
                break
            offset += len(response.results)

    def create_scan(self, target_addresses: Optional[List[str]] = None,
                   tag_names: Optional[List[str]] = None) -> Scan:
        data = ScanRequest(target_addresses=target_addresses, tag_names=tag_names)
        return Scan(**self.client.post(f"{self.base_url}/scans/", json=data.dict(exclude_none=True)).json())

    def get_scan(self, scan_id: int) -> Scan:
        return Scan(**self.client.get(f"{self.base_url}/scans/{scan_id}/").json())

    def cancel_scan(self, scan_id: int) -> str:
        return self.client.post(f"{self.base_url}/scans/{scan_id}/cancel/").text

    def create_target(self, address: str, tags: Optional[List[str]] = None) -> Target:
        data = TargetCreateRequest(address=address, tags=tags)
        return Target(**self.client.post(f"{self.base_url}/targets/", json=data.dict(exclude_none=True)).json())

    def delete_target(self, target_id: str) -> None:
        self.client.delete(f"{self.base_url}/targets/{target_id}/")

    def bulk_create_targets(self, targets: List[Dict[str, str]]) -> List[Target]:
        # Get list of existing target addresses
        existing_targets = list(self.list_targets_all())
        existing_addresses = {target.address for target in existing_targets}
        
        # Filter out targets that already exist
        new_targets = [target for target in targets if target['address'] not in existing_addresses]
        
        if not new_targets:
            return [target for target in existing_targets if target.address in {t['address'] for t in targets}]
            
        response = self.client.post(f"{self.base_url}/targets/bulk/", json=new_targets)
        created_targets = [Target(**target) for target in response.json()]
        
        # Combine newly created targets with existing ones
        return created_targets + [target for target in existing_targets if target.address in {t['address'] for t in targets}]

    def list_target_api_schemas(self, target_id: int, limit: Optional[int] = None, 
                              offset: Optional[int] = None) -> PaginatedTagsList:
        params = {}
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedTagsList(**self.client.get(f"{self.base_url}/targets/{target_id}/api_schemas/", params=params).json())

    def list_target_api_schemas_all(self, target_id: int) -> Generator[Tags, None, None]:
        offset = 0
        while True:
            response = self.list_target_api_schemas(target_id, limit=100, offset=offset)
            for schema in response.results:
                yield schema
            if not response.next:
                break
            offset += len(response.results)

    def create_target_api_schema(self, target_id: int, base_url: str, name: str, 
                               file: bytes, target_authentication_id: Optional[int] = None) -> APISchemas:
        data = APISchemasRequest(base_url=base_url, name=name, target_authentication_id=target_authentication_id, file=file)
        return APISchemas(**self.client.post(f"{self.base_url}/targets/{target_id}/api_schemas/", 
                              files={"file": file}, data=data.dict(exclude_none=True)).json())

    def update_target_api_schema(self, target_id: int, schema_id: int, 
                               base_url: Optional[str] = None, name: Optional[str] = None,
                               file: Optional[bytes] = None, 
                               target_authentication_id: Optional[int] = None) -> APISchemas:
        data = PatchedAPISchemasRequest(base_url=base_url, name=name, target_authentication_id=target_authentication_id, file=file)
        files = {"file": file} if file else None
        return APISchemas(**self.client.patch(f"{self.base_url}/targets/{target_id}/api_schemas/{schema_id}/", 
                               files=files, data=data.dict(exclude_none=True)).json())

    def delete_target_api_schema(self, target_id: int, schema_id: int) -> None:
        self.client.delete(f"{self.base_url}/targets/{target_id}/api_schemas/{schema_id}/")

    def list_target_authentications(self, target_id: int, limit: Optional[int] = None, 
                                  offset: Optional[int] = None) -> PaginatedTargetAuthenticationsList:
        params = {}
        if limit:
            params["limit"] = limit
        if offset:
            params["offset"] = offset
        return PaginatedTargetAuthenticationsList(**self.client.get(f"{self.base_url}/targets/{target_id}/authentications/", params=params).json())

    def list_target_authentications_all(self, target_id: int) -> Generator[TargetAuthentications, None, None]:
        offset = 0
        while True:
            response = self.list_target_authentications(target_id, limit=100, offset=offset)
            for auth in response.results:
                yield auth
            if not response.next:
                break
            offset += len(response.results)

    def create_target_authentication(self, target_id: int, auth_type: str, url: str, 
                                   **kwargs: Any) -> TargetAuthentications:
        data = TargetAuthenticationsRequest(type=auth_type, url=url, **kwargs)
        return TargetAuthentications(**self.client.post(f"{self.base_url}/targets/{target_id}/authentications/", json=data.dict(exclude_none=True)).json())

    def update_target_authentication(self, target_id: int, auth_id: int, **kwargs: Any) -> TargetAuthentications:
        data = PatchedTargetAuthenticationsRequest(**kwargs)
        return TargetAuthentications(**self.client.patch(f"{self.base_url}/targets/{target_id}/authentications/{auth_id}/", 
                               json=data.dict(exclude_none=True)).json())

    def delete_target_authentication(self, target_id: int, auth_id: int) -> None:
        self.client.delete(f"{self.base_url}/targets/{target_id}/authentications/{auth_id}/")

    def create_target_tag(self, target_id: int, name: str) -> Tags:
        data = TagsRequest(name=name)
        return Tags(**self.client.post(f"{self.base_url}/targets/{target_id}/tags/", json=data.dict()).json())

    def delete_target_tag(self, target_id: int, tag_name: str) -> None:
        self.client.delete(f"{self.base_url}/targets/{target_id}/tags/{tag_name}/")

    def snooze_issue(self, issue_id: int, reason: IssueSnoozeReasonEnum, details: Optional[str] = None, duration: Optional[int] = None, duration_type: Optional[str] = None) -> dict:
        data = SnoozeIssueRequest(details=details, duration=duration, duration_type=duration_type, reason=reason)
        return self.client.post(f"{self.base_url}/issues/{issue_id}/snooze/", json=data.dict(exclude_none=True)).json()

    def snooze_occurrence(self, issue_id: int, occurrence_id: int, reason: OccurrencesSnoozeReasonEnum, details: Optional[str] = None, duration: Optional[int] = None, duration_type: Optional[str] = None) -> dict:
        data = SnoozeOccurrenceRequest(details=details, duration=duration, duration_type=duration_type, reason=reason)
        return self.client.post(f"{self.base_url}/issues/{issue_id}/occurrences/{occurrence_id}/snooze/", json=data.dict(exclude_none=True)).json() 