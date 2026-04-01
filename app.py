import dash
from dash import dcc, html, Input, Output, callback, State, dash_table
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Any
import os
import logging
from dt_client import DependencyTrackClient, Project, Vulnerability

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Dash app
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])

# Configuration - read from environment variables
DT_BASE_URL = os.getenv('DT_BASE_URL', 'http://localhost:8080')
DT_API_KEY = os.getenv('DT_API_KEY', '')
DT_API_TOKEN = os.getenv('DT_API_TOKEN', '')
TAG_FILTER = os.getenv('TAG_FILTER', 'cc')

# Initialize Dependency-Track client
dt_client = DependencyTrackClient(DT_BASE_URL, DT_API_KEY, DT_API_TOKEN)

# App layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("Dependency-Track Dashboard", className="text-center mb-4"),
            html.Hr()
        ])
    ]),
    
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Configuration", className="card-title"),
                    html.P(f"Dependency-Track Server: {DT_BASE_URL}"),
                    dbc.Label("Tag Filter", html_for="tag-filter-input"),
                    dbc.Input(id="tag-filter-input", type="text", value=TAG_FILTER, placeholder="Enter tag filter"),
                    dbc.Button("Refresh Data", id="refresh-btn", color="primary", className="mt-2")
                ])
            ])
        ], width=12, className="mb-4")
    ]),
    
    # Summary cards
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Total Projects", className="card-title"),
                    html.H2(id="total-projects", children="0")
                ])
            ], color="primary", outline=True)
        ], width=3),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Critical Vulnerabilities", className="card-title"),
                    html.H2(id="critical-vulns", children="0", className="text-danger")
                ])
            ], color="danger", outline=True)
        ], width=3),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("New This Week", className="card-title"),
                    html.H2(id="new-vulns-week", children="0", className="text-warning")
                ])
            ], color="warning", outline=True)
        ], width=3),
        
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("License Issues", className="card-title"),
                    html.H2(id="license-issues", children="0", className="text-info")
                ])
            ], color="info", outline=True)
        ], width=3),
    ], className="mb-4"),
    
    # Charts toggle button
    dbc.Row([
        dbc.Col([
            dbc.Button("Show Charts", id="toggle-charts-btn", color="secondary", className="mb-2")
        ], width=12)
    ]),
    
    # Charts section
    dbc.Collapse(
        id="charts-collapse",
        is_open=False,
        children=[
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Vulnerability Severity Distribution", className="card-title"),
                            dcc.Graph(id="severity-chart")
                        ])
                    ])
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("License Risk Distribution", className="card-title"),
                            dcc.Graph(id="license-chart")
                        ])
                    ])
                ], width=6),
            ], className="mb-4")
        ]
    ),
    
    # Projects table
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Projects Overview", className="card-title"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Rows per page", html_for="page-size-select"),
                            dbc.Select(
                                id="page-size-select",
                                options=[
                                    {"label": "10", "value": 10},
                                    {"label": "20", "value": 20},
                                    {"label": "50", "value": 50},
                                    {"label": "100", "value": 100}
                                ],
                                value=20
                            )
                        ], width=3)
                    ], className="mb-3"),
                    html.Div(id="projects-table")
                ])
            ])
        ], width=12)
    ]),
    
    # Store for data
    dcc.Store(id="projects-data"),
    dcc.Store(id="metrics-data"),
    
    # Interval for auto-refresh
    dcc.Interval(
        id="interval-component",
        interval=5*60*1000,  # 5 minutes
        n_intervals=0
    ),
    
    # Error toast
    dbc.Toast(
        id="error-toast",
        header="Error",
        is_open=False,
        dismissable=True,
        duration=4000,
        style={"position": "fixed", "top": 10, "right": 10, "width": 350}
    )
    
], fluid=True)

@callback(
    [Output("projects-data", "data"),
     Output("metrics-data", "data"),
     Output("error-toast", "is_open"),
     Output("error-toast", "children")],
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals"),
     Input("tag-filter-input", "value")]
)
def update_data(n_clicks, n_intervals, tag_filter):
    try:
        # Get projects with tag filter
        effective_tag_filter = (tag_filter or TAG_FILTER).strip() or TAG_FILTER
        projects = dt_client.get_projects(effective_tag_filter)
        logger.info(f"Fetched {len(projects)} projects with tag filter '{effective_tag_filter}'")
        # Get metrics for each project
        all_metrics = []
        for project in projects:
            try:
                metrics = dt_client.get_project_metrics(project.uuid, project.version)
                metrics['project_name'] = project.name
                metrics['project_version'] = project.version or ''
                metrics['project_tags'] = project.tags
                all_metrics.append(metrics)
            except Exception as e:
                logger.warning(f"Failed to get metrics for project {project.name}: {e}")
                # Add default metrics
                all_metrics.append({
                    'total_vulnerabilities': 0,
                    'new_vulnerabilities_week': 0,
                    'severity_distribution': {},
                    'total_licenses': 0,
                    'license_risk_distribution': {},
                    'critical_vulns': 0,
                    'high_vulns': 0,
                    'medium_vulns': 0,
                    'low_vulns': 0,
                    'project_name': project.name,
                    'project_version': project.version or '',
                    'project_tags': project.tags
                })
        
        # Convert to serializable format
        projects_data = [
            {
                'uuid': p.uuid,
                'name': p.name,
                'version': p.version or '',
                'description': p.description,
                'tags': p.tags,
                'active': p.active,
                'last_bom_import': p.last_bom_import.isoformat() if p.last_bom_import else None
            }
            for p in projects
        ]
        
        return projects_data, all_metrics, False, ""
        
    except Exception as e:
        logger.error(f"Error updating data: {e}")
        return [], [], True, str(e)

@callback(
    [Output("total-projects", "children"),
     Output("critical-vulns", "children"),
     Output("new-vulns-week", "children"),
     Output("license-issues", "children")],
    [Input("metrics-data", "data")]
)
def update_summary_cards(metrics_data):
    if not metrics_data:
        return "0", "0", "0", "0"
    
    total_projects = len(metrics_data)
    critical_vulns = sum(m.get('critical_vulns', 0) for m in metrics_data)
    new_vulns_week = sum(m.get('new_vulnerabilities_week', 0) for m in metrics_data)
    license_issues = sum(m.get('license_risk_distribution', {}).get('copyleft', 0) + 
                        m.get('license_risk_distribution', {}).get('commercial', 0) for m in metrics_data)
    
    return str(total_projects), str(critical_vulns), str(new_vulns_week), str(license_issues)

@callback(
    Output("severity-chart", "figure"),
    [Input("metrics-data", "data")]
)
def update_severity_chart(metrics_data):
    if not metrics_data:
        return go.Figure()
    
    # Aggregate severity data across all projects
    severity_totals = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    for metrics in metrics_data:
        severity_dist = metrics.get('severity_distribution', {})
        for severity, count in severity_dist.items():
            if severity in severity_totals:
                severity_totals[severity] += count
    
    df = pd.DataFrame(list(severity_totals.items()), columns=['Severity', 'Count'])
    
    # Create color mapping
    color_map = {
        'CRITICAL': '#dc3545',
        'HIGH': '#fd7e14',
        'MEDIUM': '#ffc107',
        'LOW': '#28a745'
    }
    
    fig = px.bar(df, x='Severity', y='Count', 
                 color='Severity', color_discrete_map=color_map,
                 title="Vulnerability Severity Distribution")
    
    fig.update_layout(showlegend=False)
    return fig

@callback(
    Output("license-chart", "figure"),
    [Input("metrics-data", "data")]
)
def update_license_chart(metrics_data):
    if not metrics_data:
        return go.Figure()
    
    # Aggregate license data across all projects
    license_totals = {
        'permissive': 0,
        'copyleft': 0,
        'commercial': 0,
        'unknown': 0
    }
    
    for metrics in metrics_data:
        license_dist = metrics.get('license_risk_distribution', {})
        for risk_type, count in license_dist.items():
            license_totals[risk_type] += count
    
    df = pd.DataFrame(list(license_totals.items()), columns=['Risk Type', 'Count'])
    
    # Create color mapping
    color_map = {
        'permissive': '#28a745',
        'copyleft': '#ffc107',
        'commercial': '#dc3545',
        'unknown': '#6c757d'
    }
    
    fig = px.pie(df, values='Count', names='Risk Type',
                 color='Risk Type', color_discrete_map=color_map,
                 title="License Risk Distribution")
    
    return fig

@callback(
    [Output("charts-collapse", "is_open"),
     Output("toggle-charts-btn", "children")],
    Input("toggle-charts-btn", "n_clicks"),
    State("charts-collapse", "is_open")
)
def toggle_charts(n_clicks, is_open):
    if n_clicks:
        new_open = not is_open
        button_text = "Hide Charts" if new_open else "Show Charts"
        return new_open, button_text
    return is_open, "Show Charts"

@callback(
    Output("projects-table", "children"),
    [Input("projects-data", "data"),
     Input("metrics-data", "data"),
     Input("page-size-select", "value")]
)
def update_projects_table(projects_data, metrics_data, page_size):
    if not projects_data or not metrics_data:
        return html.P("No data available")
    
    # Combine project data with metrics
    table_data = []
    for i, project in enumerate(projects_data):
        if i < len(metrics_data):
            metrics = metrics_data[i]
            table_data.append({
                'Project': project['name'],
                'Version': project['version'],
                'Tags': ', '.join(project['tags']),
                'Total Vulns': metrics.get('total_vulnerabilities', 0),
                'Critical': metrics.get('critical_vulns', 0),
                'High': metrics.get('high_vulns', 0),
                'New This Week': metrics.get('new_vulnerabilities_week', 0),
                'License Issues': metrics.get('license_risk_distribution', {}).get('copyleft', 0) + 
                                metrics.get('license_risk_distribution', {}).get('commercial', 0),
                'Last BOM Import': project['last_bom_import'][:10] if project['last_bom_import'] else 'Never'
            })
    
    df = pd.DataFrame(table_data)
    
    return dash_table.DataTable(
        data=df.to_dict('records'),
        columns=[{'name': col, 'id': col} for col in df.columns],
        style_cell={'textAlign': 'left', 'padding': '10px'},
        style_table={'overflowX': 'auto'},
        style_data_conditional=[
            {
                'if': {'filter_query': '{Critical} > 0'},
                'backgroundColor': '#ffebee',
                'color': 'black',
            },
            {
                'if': {'filter_query': '{New This Week} > 0'},
                'backgroundColor': '#fff3e0',
                'color': 'black',
            }
        ],
        page_size=page_size,
        sort_action='native',
        filter_action='native'
    )

if __name__ == "__main__":
    app.run_server(debug=True, host="0.0.0.0", port=8050)
