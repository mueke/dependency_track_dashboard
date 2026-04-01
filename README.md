# Dependency-Track Dashboard

A comprehensive dashboard built with Dash for monitoring Dependency-Track projects, vulnerabilities, and license compliance.

## Features

- **Project Filtering**: Filter projects by specific tags
- **Vulnerability Tracking**: Monitor vulnerabilities across all projects
- **New Vulnerability Detection**: Identifies vulnerabilities added in the last week
- **License Analysis**: Track license risk distribution (permissive, copyleft, commercial)
- **Visual Analytics**: Interactive charts for severity and license distributions
- **Real-time Updates**: Auto-refresh every 5 minutes

## Prerequisites

- Python 3.8+
- Dependency-Track server running
- API key for Dependency-Track

## Installation

1. Install `uv` (if not already installed):
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Create the virtual environment and install dependencies:
```bash
uv sync
```

3. Set environment variables:
```bash
export DT_BASE_URL="http://your-dependency-track-server:8080"
export DT_API_KEY="your-api-key"
export TAG_FILTER="your-tag-filter"  # Optional, defaults to "cc"
```

4. Run the dashboard:
```bash
uv run app.py
```

The dashboard will be available at `http://localhost:8050`

## Configuration

The dashboard reads configuration from environment variables:

- `DT_BASE_URL`: Base URL of your Dependency-Track server (default: `http://localhost:8080`)
- `DT_API_KEY`: Your Dependency-Track API key (required)
- `TAG_FILTER`: Tag to filter projects by (default: `cc`)

## Docker Compose

Start Dependency-Track (API server + PostgreSQL) and the dashboard together:

```bash
docker compose up -d
```

Services:

- Dependency-Track API: `http://localhost:8080`
- Dashboard: `http://localhost:8050`

The dashboard reads `DT_API_KEY` and `TAG_FILTER` via environment variables in `docker-compose.yml`:

- `DT_API_KEY` defaults to empty (`""`) if not set
- `TAG_FILTER` defaults to `cc`

You can set them before starting compose, for example:

```bash
export DT_API_KEY="your-api-key"
export TAG_FILTER="cc"
docker compose up -d
```

## Dashboard Components

### Summary Cards
- **Total Projects**: Number of projects matching the tag filter
- **Critical Vulnerabilities**: Total critical vulnerabilities across all projects
- **New This Week**: Vulnerabilities added in the last 7 days
- **License Issues**: Count of copyleft and commercial licenses

### Charts
- **Vulnerability Severity Distribution**: Bar chart showing breakdown by severity levels
- **License Risk Distribution**: Pie chart showing license risk categories

### Projects Table
Detailed view of all projects including:
- Project name and version
- Tags
- Vulnerability counts by severity
- New vulnerabilities this week
- License issues
- Last BOM import date

## API Endpoints Used

The dashboard uses the following Dependency-Track API endpoints:
- `/api/v1/project` - Get all projects
- `/api/v1/vulnerability/project/{uuid}` - Get project vulnerabilities
- `/api/v1/license/project/{uuid}` - Get project licenses

## Security Notes

- Ensure your Dependency-Track API key has read-only permissions
- Consider using HTTPS for your Dependency-Track server
- The dashboard runs on all interfaces (0.0.0.0) by default - consider firewall rules

## Troubleshooting

1. **Connection Issues**: Verify DT_BASE_URL and API key are correct
2. **No Data**: Check that projects have the specified tag
3. **Permission Errors**: Ensure API key has sufficient permissions

## Development

To extend the dashboard:
1. Add new metrics in `dt_client.py`
2. Update the layout in `app.py`
3. Add new callbacks for additional visualizations
