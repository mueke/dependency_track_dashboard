import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from pydantic import BaseModel


class Project(BaseModel):
    uuid: str
    name: str
    version: str
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
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'X-Api-Key': api_key,
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base_url}{endpoint}"
        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else {}

    def get_projects(self, tag_filter: Optional[str] = None) -> List[Project]:
        """Get all projects, optionally filtered by tag"""
        endpoint = "/api/v1/project"
        projects_data = self._make_request("GET", endpoint)
        
        projects = []
        for project_data in projects_data:
            project = Project(
                uuid=project_data['uuid'],
                name=project_data['name'],
                version=project_data.get('version', ''),
                description=project_data.get('description'),
                tags=project_data.get('tags', []),
                active=project_data.get('active', True),
                last_bom_import=datetime.fromisoformat(project_data['lastBomImport'].replace('Z', '+00:00')) if project_data.get('lastBomImport') else None
            )
            
            # Filter by tag if specified
            if tag_filter is None or tag_filter in project.tags:
                projects.append(project)
        
        return projects

    def get_project_vulnerabilities(self, project_uuid: str) -> List[Vulnerability]:
        """Get vulnerabilities for a specific project"""
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
        
        return vulnerabilities

    def get_project_licenses(self, project_uuid: str) -> List[License]:
        """Get license information for a specific project"""
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
        
        return licenses

    def get_new_vulnerabilities_last_week(self, project_uuid: str) -> List[Vulnerability]:
        """Get vulnerabilities added in the last week for a project"""
        all_vulns = self.get_project_vulnerabilities(project_uuid)
        one_week_ago = datetime.now() - timedelta(days=7)
        
        new_vulns = []
        for vuln in all_vulns:
            # Check if vulnerability was published or analyzed in the last week
            if vuln.published and vuln.published > one_week_ago:
                new_vulns.append(vuln)
            elif vuln.analyzed and vuln.analyzed > one_week_ago:
                new_vulns.append(vuln)
        
        return new_vulns

    def get_project_metrics(self, project_uuid: str) -> Dict[str, Any]:
        """Get comprehensive metrics for a project"""
        vulnerabilities = self.get_project_vulnerabilities(project_uuid)
        licenses = self.get_project_licenses(project_uuid)
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
        
        return {
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
