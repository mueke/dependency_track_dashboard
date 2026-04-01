import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import os
import re

logger = logging.getLogger(__name__)

VULNERABILITY_FILTER_PROJECT_VERSION_REGEX = os.getenv('VULNERABILITY_FILTER_PROJECT_VERSION_REGEX', '')
LICENSE_FILTER_PROJECT_VERSION_REGEX = os.getenv('LICENSE_FILTER_PROJECT_VERSION_REGEX', '')

class Project(BaseModel):
    uuid: str
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []
    active: bool = True
    last_bom_import: Optional[datetime] = None


class Vulnerability(BaseModel):
    uuid: str
    vuln_id: str
    severity: str
    source: str
    published: Optional[datetime] = None
    analyzed: Optional[datetime] = None


class License(BaseModel):
    license_id: str
    name: str
    text: Optional[str] = None


class DependencyTrackClient:
    def __init__(self, base_url: str, api_key: str, api_token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.api_token = api_token
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'de-AT,de-DE;q=0.9,de;q=0.8,en-US;q=0.7,en;q=0.6',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Pragma': 'no-cache',
            'Referer': self.base_url.replace('-api', ''),
            'Origin': self.base_url.replace('-api', ''),
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-site'
        }
        if api_token:
            self.headers['Authorization'] = f'Bearer {api_token}'
        if api_key:
            self.headers['X-API-Key'] = api_key

        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Validate token by making a test request
        # try:
        #     resp = self._make_request("GET", "/api/v1/user/self")
        #     logger.debug(f"Token validation response: {resp}")
        #     logger.info("API token validated successfully")
        # except Exception as e:
        #     logger.error(f"API token validation failed: {e}")
        #     raise ValueError("Invalid API key or token") from e

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        logger.debug(f"Making {method} request to {url}")
        response = self.session.request(method, url, **kwargs)
        logger.debug(f"Response status: {response.status_code}, Response content: {response.text}")
        response.raise_for_status()
        return response.json() if response.content else {}

    def get_projects(self, tag_filter: Optional[str] = None) -> List[Project]:
        """Get all projects, optionally filtered by tag"""
        logger.debug(f"Fetching projects with tag filter: {tag_filter}")
        endpoint = "/api/v1/project"
        projects_data = self._make_request("GET", endpoint)
        logger.info(f"Fetched {len(projects_data)} projects from API")
        projects = []
        for project_data in projects_data:
            # Handle tags - they might be list of dicts with 'name'
            raw_tags = project_data.get('tags', [])
            if isinstance(raw_tags, list) and raw_tags and isinstance(raw_tags[0], dict):
                tags = [tag.get('name', '') for tag in raw_tags if isinstance(tag, dict)]
            else:
                tags = raw_tags if isinstance(raw_tags, list) else []
            
            project = Project(
                uuid=project_data['uuid'],
                name=project_data['name'],
                version=project_data.get('version') or None,
                description=project_data.get('description'),
                tags=tags,
                active=project_data.get('active', True),
                last_bom_import=project_data['lastBomImport'] if project_data.get('lastBomImport') else None
            )
            
            # Filter by tag if specified
            if tag_filter is None or tag_filter in project.tags:
                projects.append(project)
        
        logger.debug(f"Filtered to {len(projects)} projects after tag filtering")
        return projects

    def get_project_vulnerabilities(self, project_uuid: str, project_version: str = None) -> List[Vulnerability]:
        """Get vulnerabilities for a specific project"""
        if VULNERABILITY_FILTER_PROJECT_VERSION_REGEX and project_version:
            if not re.search(VULNERABILITY_FILTER_PROJECT_VERSION_REGEX, project_version or ''):
                logger.debug(f"Skipping vulnerabilities for project {project_uuid} due to version filter")
                return []
        
        logger.debug(f"Fetching vulnerabilities for project {project_uuid}")
        endpoint = f"/api/v1/vulnerability/project/{project_uuid}"
        vulns_data = self._make_request("GET", endpoint)
        
        vulnerabilities = []
        for vuln_data in vulns_data:
            vulnerability = Vulnerability(
                uuid=vuln_data['uuid'],
                vuln_id=vuln_data['vulnId'],
                severity=vuln_data.get('severity', 'UNKNOWN'),
                source=vuln_data.get('source', 'UNKNOWN'),
                published=datetime.fromisoformat(vuln_data['published'].replace('Z', '+00:00')) if vuln_data.get('published') else None,
                analyzed=datetime.fromisoformat(vuln_data['analyzed'].replace('Z', '+00:00')) if vuln_data.get('analyzed') else None
            )
            vulnerabilities.append(vulnerability)
        
        
        logger.debug(f"Found {len(vulnerabilities)} vulnerabilities for project {project_uuid}")
        return vulnerabilities

    def get_project_licenses(self, project_uuid: str, project_version: str = None) -> List[License]:
        """Get license information for a specific project"""
        if LICENSE_FILTER_PROJECT_VERSION_REGEX and project_version:
            if not re.search(LICENSE_FILTER_PROJECT_VERSION_REGEX, project_version or ''):
                logger.debug(f"Skipping licenses for project {project_uuid} due to version filter")
                return []
        
        logger.debug(f"Fetching licenses for project {project_uuid}")
        try:
            endpoint = f"/api/v1/license/project/{project_uuid}"
            licenses_data = self._make_request("GET", endpoint)
            
            licenses = []
            for license_data in licenses_data:
                license_obj = License(
                    license_id=license_data['licenseId'],
                    name=license_data['name'],
                    text=license_data.get('text')
                )
                licenses.append(license_obj)
            
            logger.debug(f"Found {len(licenses)} licenses for project {project_uuid}")
            return licenses
        except Exception as e:
            logger.warning(f"Failed to fetch licenses for project {project_uuid}: {e}")
            return []

    def get_new_vulnerabilities_last_week(self, project_uuid: str) -> List[Vulnerability]:
        """Get vulnerabilities added in the last week for a project"""
        logger.debug(f"Fetching new vulnerabilities for project {project_uuid} in the last week")
        all_vulns = self.get_project_vulnerabilities(project_uuid)
        one_week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        
        new_vulns = []
        for vuln in all_vulns:
            # Check if vulnerability was published or analyzed in the last week
            if vuln.published and vuln.published > one_week_ago:
                new_vulns.append(vuln)
            elif vuln.analyzed and vuln.analyzed > one_week_ago:
                new_vulns.append(vuln)
        
        logger.debug(f"Found {len(new_vulns)} new vulnerabilities in the last week for project {project_uuid}")
        return new_vulns

    def get_project_metrics(self, project_uuid: str, project_version: str = None) -> Dict[str, Any]:
        """Get comprehensive metrics for a project"""
        logger.debug(f"Calculating metrics for project {project_uuid}")
        vulnerabilities = self.get_project_vulnerabilities(project_uuid, project_version)
        licenses = self.get_project_licenses(project_uuid, project_version)
        new_vulns = self.get_new_vulnerabilities_last_week(project_uuid)
        
        # Calculate severity distribution
        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        # Calculate license risk
        license_risk = {
            'permissive': 0,
            'copyleft': 0,
            'commercial': 0,
            'unknown': 0
        }
        
        for license_obj in licenses:
            license_name = license_obj.name.lower()
            if any(perm in license_name for perm in ['mit', 'apache', 'bsd']):
                license_risk['permissive'] += 1
            elif any(copyleft in license_name for copyleft in ['gpl', 'lgpl', 'agpl']):
                license_risk['copyleft'] += 1
            elif 'commercial' in license_name:
                license_risk['commercial'] += 1
            else:
                license_risk['unknown'] += 1
        
        metrics = {
            'total_vulnerabilities': len(vulnerabilities),
            'new_vulnerabilities_week': len(new_vulns),
            'severity_distribution': severity_counts,
            'total_licenses': len(licenses),
            'license_risk_distribution': license_risk,
            'critical_vulns': severity_counts.get('CRITICAL', 0),
            'high_vulns': severity_counts.get('HIGH', 0),
            'medium_vulns': severity_counts.get('MEDIUM', 0),
            'low_vulns': severity_counts.get('LOW', 0)
        }
        logger.debug(f"Metrics for project {project_uuid}: {metrics}")
        return metrics
