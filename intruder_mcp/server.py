import base64
import os
import sys
from datetime import datetime, timedelta, timezone
from importlib.resources import files
from typing import Any, Optional, List, Dict
from mcp.server.fastmcp import FastMCP
from mcp.types import Icon
from intruder_mcp.api_client import IntruderAPI
from intruder_mcp.enums import ScanFrequencyEnum, NetworkService, Target


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# The attack surface API rejects date-times without an offset, so dates and naive times are taken as UTC.
def _parse_iso8601_utc(value: str) -> datetime:
    parsed = _parse_iso8601(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _format_date(value: datetime) -> str:
    return value.date().isoformat()


def _format_target(target: Target) -> str:
    line = f"{target.id} - {target.address}"
    if target.ip_address and target.ip_address != target.address:
        line += f" [{target.ip_address}]"
    line += f" ({target.target_status.value})"
    if target.hostnames and target.hostnames != [target.address]:
        line += f", hostnames: {', '.join(target.hostnames)}"
    return line


def _format_network_service(service: NetworkService) -> str:
    parts = [f"{service.port}/{service.protocol}", service.name or "unknown service"]
    if service.product:
        parts.append(f"product: {service.product}")
    if service.version:
        parts.append(f"version: {service.version}")
    if service.extra_info:
        parts.append(f"info: {service.extra_info}")
    if service.http_title:
        parts.append(f'title: "{service.http_title}"')
    if service.ssl_cert_expiry_date:
        parts.append(f"TLS expires: {_format_date(service.ssl_cert_expiry_date)}")
    if service.waf_provider:
        parts.append(f"WAF: {service.waf_provider}")
    if service.first_observed_at:
        parts.append(f"first seen: {_format_date(service.first_observed_at)}")
    if service.last_observed_at:
        parts.append(f"last seen: {_format_date(service.last_observed_at)}")
    return " | ".join(parts)


# Embedded as data URIs so clients can show the icon offline and without fetching from GitHub.
# PNG first: clients must support it, whereas SVG support is optional.
def _icon(filename: str, mime_type: str, size: str) -> Icon:
    data = base64.b64encode(files("intruder_mcp").joinpath("assets", filename).read_bytes()).decode()
    return Icon(src=f"data:{mime_type};base64,{data}", mimeType=mime_type, sizes=[size])


def main():
    api_key = os.environ.get("INTRUDER_API_KEY")
    if not api_key:
        print("Error: INTRUDER_API_KEY environment variable not set", file=sys.stderr)
        sys.exit(1)

    api = IntruderAPI(api_key)
    mcp = FastMCP("intruder", website_url="https://www.intruder.io", icons=[
        _icon("icon.png", "image/png", "512x512"),
        _icon("icon.svg", "image/svg+xml", "any"),
    ])
    PAGE_SIZE = 100

    @mcp.tool()
    async def get_user() -> str:
        """Get the current user of the Intruder API that we are authenticated as"""
        health = api.get_health()
        return health.authenticated_as

    @mcp.tool()
    async def get_status() -> str:
        """Get the status of the Intruder API"""
        health = api.get_health()
        return health.status

    @mcp.tool()
    async def list_targets() -> str:
        """
        List all targets in the Intruder account with their IDs, IP address and hostnames (when scanned) and status (one of 'live', 'license_exceeded', 'unscanned', 'unresponsive', 'agent_uninstalled').
        """

        targets = api.list_targets_all()
        formatted = [_format_target(target) for target in targets]
        return "\n".join(formatted)

    @mcp.tool()
    async def list_network_services(target_ids: Optional[List[int]] = None,
                                    tag_names: Optional[List[str]] = None,
                                    ports: Optional[List[int]] = None,
                                    protocols: Optional[List[str]] = None,
                                    names: Optional[List[str]] = None,
                                    ssl_cert_expired: bool = False,
                                    ssl_cert_expiring_within_days: Optional[int] = None,
                                    ssl_cert_expiry_after: Optional[str] = None,
                                    ssl_cert_expiry_before: Optional[str] = None,
                                    search: Optional[str] = None,
                                    offset: int = 0) -> str:
        """
        List the external attack surface: the network services (open ports) detected on targets by network scans,
        including product, version, web page title, TLS certificate expiry, web application firewall, and when each
        service was first and last seen. Use it to find where a product, service or port is exposed.
        Services are grouped under their target ID; use list_targets to get each target's address, IP address and
        hostnames, and to find target IDs to filter by.
        Returns up to 100 services per call, ordered by target address, port and protocol.
        If there are more, call again with the offset given.

        Args:
            target_ids: Filter by a list of target IDs (as returned by list_targets)
            tag_names: Filter by a list of tag names
            ports: Filter by a list of ports
            protocols: Filter by a list of protocols ('tcp', 'udp')
            names: Filter by a list of service names (exact match, e.g. 'https', 'ssh')
            ssl_cert_expired: Only services whose TLS certificate has already expired. Set together with
                ssl_cert_expiring_within_days to get certificates that have expired or will expire within that many days.
            ssl_cert_expiring_within_days: Only services whose TLS certificate has not yet expired but will within this
                many days (e.g. 30 for certificates expiring in the next month)
            ssl_cert_expiry_after: Only services whose TLS certificate expires at or after this time (ISO 8601 date or
                date-time, e.g. 2026-01-15 or 2026-01-15T00:00:00Z; UTC if no offset is given). Cannot be combined with
                ssl_cert_expired or ssl_cert_expiring_within_days.
            ssl_cert_expiry_before: Only services whose TLS certificate expires at or before this time (same format as
                ssl_cert_expiry_after). Combine with ssl_cert_expiry_after for a specific window. Cannot be combined
                with ssl_cert_expired or ssl_cert_expiring_within_days.
            search: Case-insensitive partial match on service name or product (e.g. 'nginx', 'ssh')
            offset: Number of services to skip, for paging through results
        """
        if ssl_cert_expired or ssl_cert_expiring_within_days is not None:
            if ssl_cert_expiry_after or ssl_cert_expiry_before:
                raise ValueError("Use either ssl_cert_expired/ssl_cert_expiring_within_days or "
                                 "ssl_cert_expiry_after/ssl_cert_expiry_before, not both")
            if ssl_cert_expiring_within_days is not None and ssl_cert_expiring_within_days < 1:
                raise ValueError("ssl_cert_expiring_within_days must be at least 1")
            now = datetime.now(timezone.utc)
            expiry_after = None if ssl_cert_expired else now
            expiry_before = now + timedelta(days=ssl_cert_expiring_within_days) if ssl_cert_expiring_within_days else now
        else:
            expiry_after = _parse_iso8601_utc(ssl_cert_expiry_after) if ssl_cert_expiry_after else None
            expiry_before = _parse_iso8601_utc(ssl_cert_expiry_before) if ssl_cert_expiry_before else None

        page = api.list_network_services(
            target_ids=target_ids,
            tag_names=tag_names,
            ports=ports,
            protocols=protocols,
            names=names,
            ssl_cert_expiry_after=expiry_after,
            ssl_cert_expiry_before=expiry_before,
            search=search,
            limit=PAGE_SIZE,
            offset=offset,
        )
        if not page.results:
            return "No network services found"

        end = offset + len(page.results)
        header = f"Services {offset + 1}-{end} of {page.count}"
        if page.next:
            header += f" (call again with offset={end} for more)"
        lines = [header]
        previous_target_id = None
        for service in page.results:
            if service.target_id != previous_target_id:
                lines.append(f"Target {service.target_id}")
                previous_target_id = service.target_id
            lines.append(f"  {_format_network_service(service)}")
        return "\n".join(lines)

    @mcp.tool()
    async def list_issues(target_addresses: Optional[List[str]] = None,
                         tag_names: Optional[List[str]] = None,
                         snoozed: Optional[bool] = None,
                         severity: Optional[str] = None) -> str:
        """
        List issues in the Intruder account with optional filters.

        Args:
            target_addresses: Filter by a list of target addresses
            tag_names: Filter by a list of tag names
            snoozed: Filter by snoozed status (true or false)
            severity: Filter by severity level (one of 'critical', 'high', 'medium', 'low')
        """
        issues = api.list_issues_all(
            target_addresses=target_addresses,
            tag_names=tag_names,
            snoozed=snoozed,
            severity=severity
        )
        formatted = [f"{issue.id} - {issue.title} ({issue.severity})" for issue in issues]
        return "\n".join(formatted)

    @mcp.tool()
    async def list_scans(status: Optional[str] = None, scan_type: Optional[str] = None) -> str:
        """
        List scans in the Intruder account with optional filters.

        Args:
            status: Filter by scan status (in_progress, completed, cancelled, cancelled_no_active_targets,
                   cancelled_no_valid_targets, analysing_results)
            scan_type: Filter by scan type (assessment_schedule, new_service, cloudbot_new_target,
                     rapid_remediation, advisory, cloud_security, container_image)
        
        The scan_type parameters mean:
            - assessment_schedule: Scans that run on a regular schedule
            - new_service: Scans that are triggered when a new service is exposed on a target
            - cloudbot_new_target: Scans that are triggered when CloudBot discovers a new target in a connected cloud account
            - rapid_remediation: Scans that a user can trigger to test if a specific issue has been remediated
            - advisory: An issue created by the Intruder security team based on their manual work
            - cloud_security: Scans of cloud accounts, checking the configuration of the resources in the cloud account
            - container_image: Scans of container images for vulnerabilities
        """
        scans = api.list_scans_all(status=status, scan_type=scan_type)
        formatted = [f"{scan.id} - {scan.scan_type} ({scan.status})" for scan in scans]
        return "\n".join(formatted)

    @mcp.tool()
    async def list_tags(target_address: Optional[str] = None) -> str:
        """
        List all tags in the Intruder account. Tags are applied to targets.

        Args:
            target_address: Only list tags applied to targets matching this address
        """
        if target_address:
            targets = api.list_targets_all(address=target_address)
            tags = {tag for target in targets for tag in target.tags or []}
        else:
            # A tag name can exist once per cloud integration, so the endpoint may repeat names
            tags = {tag.name for tag in api.list_tags_all()}
        return "\n".join(sorted(tags))

    @mcp.tool()
    async def list_occurrences(issue_id: int,
                             target_addresses: Optional[List[str]] = None,
                             tag_names: Optional[List[str]] = None,
                             snoozed: Optional[bool] = None) -> str:
        """
        List all occurrences for a specific issue with optional filters.

        Args:
            issue_id: The ID of the issue to list occurrences for
            target_addresses: Filter by a list of target addresses
            tag_names: Filter by a list of tag names
            snoozed: Filter by snoozed status (true or false)
        """
        occurrences = api.get_issue_occurrences_all(
            issue_id=issue_id,
            target_addresses=target_addresses,
            tag_names=tag_names,
            snoozed=snoozed
        )
        formatted = [f"{occ.id} - {occ.target}:{occ.port}/{occ.protocol}" for occ in occurrences]
        return "\n".join(formatted)

    @mcp.tool()
    async def get_scanner_output(issue_id: int, occurrence_id: int) -> str:
        """
        Get scanner output for a specific occurrence of an issue.

        Args:
            issue_id: The ID of the issue
            occurrence_id: The ID of the occurrence
        """
        outputs = api.get_scanner_output_all(issue_id=issue_id, occurrence_id=occurrence_id)
        formatted = []
        for output in outputs:
            plugin_info = f"Plugin: {output.plugin.name}"
            if output.plugin.cve:
                plugin_info += f" (CVEs: {', '.join(output.plugin.cve)})"
            formatted.append(plugin_info)
            formatted.append("Output:")
            formatted.extend(str(line) for line in output.scanner_output)
            formatted.append("")
        return "\n".join(formatted)

    @mcp.tool()
    async def create_scan(target_addresses: Optional[List[str]] = None, tag_names: Optional[List[str]] = None) -> str:
        """
        Create a new scan.

        Args:
            target_addresses: List of target addresses to scan
            tag_names: List of tag names to scan targets with these tags
        """
        scan = api.create_scan(target_addresses=target_addresses, tag_names=tag_names)
        return f"Created scan {scan.id} ({scan.scan_type})"

    @mcp.tool()
    async def get_scan(scan_id: int) -> str:
        """
        Get details of a specific scan.

        Args:
            scan_id: The ID of the scan to get
        """
        scan = api.get_scan(scan_id)
        details = [
            f"Scan {scan.id} ({scan.scan_type})",
            f"Status: {scan.status}",
            f"Schedule: {scan.schedule_period}",
            f"Created: {scan.created_at}",
            f"Type: {scan.scan_type}"
        ]
        if scan.start_time:
            details.append(f"Started: {scan.start_time}")
        if scan.completed_time:
            details.append(f"Completed: {scan.completed_time}")
        if scan.target_addresses:
            details.append("\nTargets:")
            details.extend(f"- {addr}" for addr in scan.target_addresses)

        return "\n".join(details)

    @mcp.tool()
    async def cancel_scan(scan_id: int) -> str:
        """
        Cancel a running scan.

        Args:
            scan_id: The ID of the scan to cancel
        """
        result = api.cancel_scan(scan_id)
        return f"Cancelled scan {scan_id}: {result}"

    @mcp.tool()
    async def delete_target(target_id: str) -> str:
        """
        Delete a target.

        Args:
            target_id: The ID of the target to delete
        """
        api.delete_target(target_id)
        return f"Deleted target {target_id}"

    @mcp.tool()
    async def create_targets(addresses: List[str]) -> str:
        """
        Create one or more targets.

        Args:
            addresses: List of target addresses to create
                    Example: ['example.com'] for a single target
                    Example: ['example.com', 'test.com'] for multiple targets
        """
        targets = [{'address': addr} for addr in addresses]
        result = api.bulk_create_targets(targets)
        return f"Created {len(addresses)} targets"

    @mcp.tool()
    async def create_target_tag(target_id: int, name: str) -> str:
        """
        Add a tag to a target.

        Args:
            target_id: The ID of the target to add the tag to
            name: The name of the tag to add (max 40 characters)
        """
        tag = api.create_target_tag(target_id=target_id, name=name)
        return f"Added tag '{tag.name}' to target {target_id}"

    @mcp.tool()
    async def delete_target_tag(target_id: int, tag_name: str) -> str:
        """
        Remove a tag from a target.

        Args:
            target_id: The ID of the target to remove the tag from
            tag_name: The name of the tag to remove
        """
        api.delete_target_tag(target_id=target_id, tag_name=tag_name)
        return f"Removed tag '{tag_name}' from target {target_id}"

    @mcp.tool()
    async def list_licenses() -> str:
        """
        List license information for the Intruder account. Shows usage and limits for infrastructure and application licenses. When a license is used, it is tied to the target that used it for 30 days.
        """
        licenses = api.list_licenses_all()
        formatted = []
        for license in licenses:
            formatted.append("Infrastructure Licenses:")
            formatted.append(f"  Total: {license.total_infrastructure_licenses}")
            formatted.append(f"  Available: {license.available_infrastructure_licenses}")
            formatted.append(f"  Consumed: {license.consumed_infrastructure_licenses}")
            formatted.append("")
            formatted.append("Application Licenses:")
            formatted.append(f"  Total: {license.total_application_licenses}")
            formatted.append(f"  Available: {license.available_application_licenses}")
            formatted.append(f"  Consumed: {license.consumed_application_licenses}")
            formatted.append("")
        return "\n".join(formatted)

    @mcp.tool()
    async def snooze_occurrence(issue_id: int, occurrence_id: int, reason: str, details: Optional[str] = None, duration: Optional[int] = None, duration_type: Optional[str] = None) -> str:
        """
        Snooze a specific occurrence of an issue.

        To snooze a whole issue, list its occurrences with list_occurrences and snooze each one.

        Args:
            issue_id: The ID of the issue
            occurrence_id: The ID of the occurrence to snooze
            reason: Reason for snoozing (required, must be one of ACCEPT_RISK, FALSE_POSITIVE, MITIGATING_CONTROLS)
            details: Optional free-text details for the snooze
            duration: Optional number of duration_type units to snooze for (ignored when duration_type is 'forever')
            duration_type: Optional duration type, one of 'forever', 'day', 'week', 'month'

        The reasons mean:
            - ACCEPT_RISK - Risk accepted for this specific occurrence
            - FALSE_POSITIVE - False positive - occurrence has been verified as not exploitable
            - MITIGATING_CONTROLS - Mitigating controls are in place for this occurrence
        """
        result = api.snooze_occurrence(issue_id, occurrence_id, reason=reason, details=details, duration=duration, duration_type=duration_type)
        return result.get("detail", str(result))

    @mcp.tool()
    async def list_scan_schedules() -> str:
        """
        List all scan schedules in the Intruder account, including the full record for each.
        """
        response = api.list_scan_schedules()
        if not response.results:
            return "No scan schedules found."
        blocks = []
        for s in response.results:
            block = [
                f"{s.id} - {s.name}",
                f"  schedule_period: {s.schedule_period}",
                f"  status: {s.status}",
                f"  first_scan_time: {s.first_scan_time}",
                f"  next_scan_date: {s.next_scan_date}",
                f"  throttled: {s.throttled}",
                f"  web_ports_only: {s.web_ports_only}",
                f"  upload_to_drata: {s.upload_to_drata}",
                f"  upload_to_vanta: {s.upload_to_vanta}",
                f"  latest_scan_id: {s.latest_scan_id}",
                f"  latest_scan_status: {s.latest_scan_status}",
                f"  last_scan_start_time: {s.last_scan_start_time}",
                f"  last_scan_end_time: {s.last_scan_end_time}",
                f"  targets: {', '.join(map(str, s.targets)) if s.targets else '(none)'}",
                f"  target_tags: {', '.join(s.target_tags) if s.target_tags else '(none)'}",
            ]
            blocks.append("\n".join(block))
        return "\n\n".join(blocks)

    def _format_schedule_result(action: str, schedule_id: Optional[int], result: dict) -> str:
        notice = result.get("notice", "OK")
        return f"{action} scan schedule {schedule_id}: {notice}"

    @mcp.tool()
    async def create_scan_schedule(
        name: str,
        first_scan_time: str,
        scan_frequency: ScanFrequencyEnum,
        target_ids: Optional[List[int]] = None,
        tag_names: Optional[List[str]] = None,
        throttled: Optional[bool] = None,
        web_ports_only: Optional[bool] = None,
        upload_to_drata: Optional[bool] = None,
        upload_to_vanta: Optional[bool] = None,
    ) -> str:
        """
        Create a recurring scan schedule.

        Args:
            name: Name of the schedule
            first_scan_time: ISO 8601 timestamp of the first scan. Must be in the future and on the hour
                (e.g. '2026-05-01T03:00:00Z', not '2026-05-01T03:12:34Z')
            scan_frequency: One of 'daily', 'weekly', 'monthly', 'quarterly'
            target_ids: List of target IDs to include in the schedule
            tag_names: List of target tag names to include in the schedule
            throttled: Whether to throttle the scan
            web_ports_only: Only scan standard web ports
            upload_to_drata: Upload scan results to Drata
            upload_to_vanta: Upload scan results to Vanta
        """
        parsed_first_scan_time = _parse_iso8601(first_scan_time)
        result = api.create_scan_schedule(
            name=name,
            first_scan_time=parsed_first_scan_time,
            scan_frequency=scan_frequency,
            tags=tag_names,
            targets=target_ids,
            throttled=throttled,
            web_ports_only=web_ports_only,
            upload_to_drata=upload_to_drata,
            upload_to_vanta=upload_to_vanta,
        )
        return _format_schedule_result("Created", result.get("id"), result)

    @mcp.tool()
    async def update_scan_schedule(
        schedule_id: int,
        name: Optional[str] = None,
        first_scan_time: Optional[str] = None,
        scan_frequency: Optional[ScanFrequencyEnum] = None,
        target_ids: Optional[List[int]] = None,
        tag_names: Optional[List[str]] = None,
        throttled: Optional[bool] = None,
        web_ports_only: Optional[bool] = None,
        upload_to_drata: Optional[bool] = None,
        upload_to_vanta: Optional[bool] = None,
    ) -> str:
        """
        Update an existing scan schedule. Only the provided fields are changed.

        Args:
            schedule_id: The ID of the scan schedule to update
            name: Rename the schedule
            first_scan_time: ISO 8601 timestamp, in the future and on the hour
            scan_frequency: One of 'daily', 'weekly', 'monthly', 'quarterly'
            target_ids: Replace the set of target IDs included in the schedule
            tag_names: Replace the set of target tag names included in the schedule
            throttled: Whether to throttle the scan
            web_ports_only: Only scan standard web ports
            upload_to_drata: Upload scan results to Drata
            upload_to_vanta: Upload scan results to Vanta
        """
        parsed_first_scan_time = _parse_iso8601(first_scan_time) if first_scan_time is not None else None
        result = api.update_scan_schedule(
            schedule_id=schedule_id,
            name=name,
            first_scan_time=parsed_first_scan_time,
            scan_frequency=scan_frequency,
            tags=tag_names,
            targets=target_ids,
            throttled=throttled,
            web_ports_only=web_ports_only,
            upload_to_drata=upload_to_drata,
            upload_to_vanta=upload_to_vanta,
        )
        return _format_schedule_result("Updated", schedule_id, result)

    @mcp.tool()
    async def delete_scan_schedule(schedule_id: int) -> str:
        """
        Delete a scan schedule.

        Args:
            schedule_id: The ID of the scan schedule to delete
        """
        api.delete_scan_schedule(schedule_id)
        return f"Deleted scan schedule {schedule_id}"

    @mcp.tool()
    async def list_ai_pentests() -> str:
        """
        List all AI pentests in the Intruder account with their IDs, the URL of the application being tested and status (one of 'pending', 'started', 'completed', 'cancelled', 'aborted', 'cancellation_pending').
        """
        ai_pentests = api.list_ai_pentests_all()
        formatted = [f"{ai_pentest.id} - {ai_pentest.url} ({ai_pentest.status})" for ai_pentest in ai_pentests]
        return "\n".join(formatted) or "No AI pentests found."

    @mcp.tool()
    async def get_ai_pentest(ai_pentest_id: str) -> str:
        """
        Get details of a specific AI pentest.

        Args:
            ai_pentest_id: The ID of the AI pentest to get
        """
        ai_pentest = api.get_ai_pentest(ai_pentest_id)
        details = [
            f"AI pentest {ai_pentest.id}",
            f"URL: {ai_pentest.url}",
            f"Application: {ai_pentest.application_name or '(none)'}",
            f"Environment: {ai_pentest.environment or '(none)'}",
            f"Status: {ai_pentest.status}",
            f"Created: {ai_pentest.created_at}",
        ]
        if ai_pentest.completed_at:
            details.append(f"Completed: {ai_pentest.completed_at}")
        if ai_pentest.canceled_at:
            details.append(f"Cancelled: {ai_pentest.canceled_at}")
        if ai_pentest.retest_status:
            details.append(f"Latest retest: {ai_pentest.retest_status}")
        if ai_pentest.release_test_status:
            details.append(f"Latest release test: {ai_pentest.release_test_status}")
        return "\n".join(details)

    @mcp.tool()
    async def list_ai_pentest_findings(ai_pentest_id: str, statuses: Optional[List[str]] = None) -> str:
        """
        List findings of an AI pentest, most severe first, including the full write-up for each.

        Args:
            ai_pentest_id: The ID of the AI pentest to list findings for
            statuses: Filter by finding statuses (any of 'open', 'fixed'). Defaults to open findings only.
        """
        findings = api.list_ai_pentest_findings_all(ai_pentest_id, statuses=statuses)
        blocks = []
        for finding in findings:
            block = [
                f"{finding.id} - {finding.title}",
                f"  severity: {finding.severity}",
                f"  status: {finding.status}",
                f"  impact: {finding.impact}",
                f"  likelihood: {finding.likelihood}",
            ]
            if finding.location:
                lines = ", ".join(finding.location.lines or [])
                block.append(f"  location: {finding.location.file or '(unknown file)'}{f' (lines {lines})' if lines else ''}")
            block.extend([
                f"  overview: {finding.overview}",
                f"  evidence: {finding.evidence}",
                f"  technical_details: {finding.technical_details}",
                f"  remediation: {finding.remediation}",
            ])
            if finding.retest_summary:
                block.append(f"  retest_summary: {finding.retest_summary}")
            blocks.append("\n".join(block))
        return "\n\n".join(blocks) or "No findings found."

    @mcp.tool()
    async def start_ai_pentest_release_test(ai_pentest_id: str) -> str:
        """
        Start a release test of an AI pentest, using its existing configuration.
        Only call this when the user asks to start one. It fails if a test is already running,
        or if the full test has no results or recorded commits yet.
        Check its progress with get_ai_pentest_run.

        Args:
            ai_pentest_id: The ID of the AI pentest to release test
        """
        run = api.start_ai_pentest_release_test(ai_pentest_id)
        return f"Started release test {run.id} ({run.status})"

    @mcp.tool()
    async def start_ai_pentest_retest(ai_pentest_id: str, finding_ids: List[str]) -> str:
        """
        Start a retest of findings from an AI pentest to check whether they've been fixed, using its existing
        configuration. Only call this when the user asks to start one. Get finding IDs from list_ai_pentest_findings.
        Findings that aren't open are skipped. It fails if none of them are open, or if a test is already running.
        Check its progress with get_ai_pentest_run.

        Args:
            ai_pentest_id: The ID of the AI pentest to retest
            finding_ids: The IDs of the findings to retest
        """
        run = api.start_ai_pentest_retest(ai_pentest_id, finding_ids)
        return f"Started retest {run.id} ({run.status})"

    def format_detail_value(value) -> str:
        return ", ".join(str(item) for item in value) if isinstance(value, list) else str(value)

    def format_ai_pentest_run(run) -> str:
        lines = [f"{run.id} - {run.type} ({run.status}), started {run.created_at}"]
        for error in run.preflight_errors:
            detail = ", ".join(
                f"{key}: {format_detail_value(value)}" for key, value in error.detail.items() if value is not None
            )
            lines.append(f"  preflight error: {error.code}" + (f" ({detail})" if detail else ""))
        return "\n".join(lines)

    @mcp.tool()
    async def list_ai_pentest_runs(ai_pentest_id: str) -> str:
        """
        List the runs of an AI pentest (its full test, retests and release tests), newest first, with their
        status (one of 'in_progress', 'completed', 'failed', 'cancelled') and preflight errors explaining a failure.
        A failed run's preflight errors can appear a few seconds after it fails, so fetch it again with
        get_ai_pentest_run if it has none. If it still has none after a minute, there won't be any.
        A restarted full test shows when its first attempt started.

        Args:
            ai_pentest_id: The ID of the AI pentest to list runs for
        """
        runs = api.list_ai_pentest_runs_all(ai_pentest_id)
        return "\n".join(format_ai_pentest_run(run) for run in runs) or "No runs found."

    @mcp.tool()
    async def get_ai_pentest_run(ai_pentest_id: str, run_id: str) -> str:
        """
        Get a run of an AI pentest with its status (one of 'in_progress', 'completed', 'failed', 'cancelled') and
        preflight errors explaining a failure. A failed run's preflight errors can appear a few seconds after it
        fails, so fetch it again if it has none. If it still has none after a minute, there won't be any.
        A restarted full test shows when its first attempt started.

        Args:
            ai_pentest_id: The ID of the AI pentest
            run_id: The ID of the run to get
        """
        return format_ai_pentest_run(api.get_ai_pentest_run(ai_pentest_id, run_id))

    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
