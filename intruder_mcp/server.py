import os
from typing import Any, Optional, List, Dict
from mcp.server.fastmcp import FastMCP
from intruder_mcp.api_client import IntruderAPI


def main():
    api_key = os.environ.get("INTRUDER_API_KEY")
    if not api_key:
        raise ValueError("INTRUDER_API_KEY environment variable not set")

    api = IntruderAPI(api_key)
    mcp = FastMCP("intruder")
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
        List all targets in the Intruder account and their associated IDs.
        """

        targets = api.list_targets_all()
        formatted = [f"{target.id} - {target.address} ({target.target_status})" for target in targets]
        return "\n".join(formatted)

    @mcp.tool()
    async def list_issues(target_addresses: Optional[List[str]] = None,
                         tag_names: Optional[List[str]] = None,
                         snoozed: Optional[bool] = None,
                         severity: Optional[str] = None) -> str:
        """
        List issues in the Intruder account with optional filters.

        Args:
            target_addresses: Filter by target addresses
            tag_names: Filter by tag names
            snoozed: Filter by snoozed status
            severity: Filter by severity level
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
                     rapid_remediation, advisory, cloud_security)
        """
        scans = api.list_scans_all(status=status, scan_type=scan_type)
        formatted = [f"{scan.id} - {scan.scan_type} ({scan.status})" for scan in scans]
        return "\n".join(formatted)

    @mcp.tool()
    async def list_tags(target_address: Optional[str] = None) -> str:
        """
        List all tags in the Intruder account with optional filters.

        Args:
            target_address: Filter tags by target address
        """
        targets = api.list_targets_all(address=target_address)
        tags = set()
        for target in targets:
            if target.tags:
                tags.update(target.tags)
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
            target_addresses: Filter by target addresses
            tag_names: Filter by tag names
            snoozed: Filter by snoozed status
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
            f"Created: {scan.created_at}"
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
        List license information for the Intruder account.
        Shows usage and limits for infrastructure and application licenses.
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

    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
