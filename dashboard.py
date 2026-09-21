#!/usr/bin/env python3
"""
Advanced IDS Dashboard
Real-time visualization of network alerts with:
- Live alerts table
- Top suspicious IPs chart
- Port distribution chart
- Blocked IPs counter
- Auto-refresh every 5 seconds
"""

import pandas as pd
from dash import Dash, dash_table, dcc, html, callback
import dash_bootstrap_components as dbc
from dash.dependencies import Output, Input
import plotly.express as px
import plotly.graph_objects as go
import time
import os

ALERT_CSV = "alerts.csv"

def get_alerts():
    """Load alerts from CSV file"""
    try:
        if os.path.exists(ALERT_CSV):
            df = pd.read_csv(ALERT_CSV)
            return df
    except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError) as error:
        print(f"Error reading alerts: {error}")
    return pd.DataFrame(columns=[
    "timestamp",
    "src_ip",
    "dst_port",
    "attack_type",
    "severity",
    "location",
    "blocked",
    "attempt_count"
])

def create_top_ips_chart(df):
    """Create bar chart of top suspicious IPs"""
    if df.empty or 'src_ip' not in df.columns:
        return go.Figure().add_annotation(text="No data available")
    
    top_ips = df['src_ip'].value_counts().head(10)
    fig = px.bar(
        x=top_ips.values,
        y=top_ips.index,
        orientation='h',
        title="Top 10 Suspicious IPs",
        labels={'x': 'Number of Attempts', 'y': 'IP Address'},
        color=top_ips.values,
        color_continuous_scale='Reds'
    )
    fig.update_layout(height=400, showlegend=False)
    return fig

def create_port_distribution_chart(df):
    """Create pie chart of targeted ports"""
    if df.empty or 'dst_port' not in df.columns:
        return go.Figure().add_annotation(text="No data available")
    
    port_counts = df['dst_port'].value_counts()
    fig = px.pie(
        values=port_counts.values,
        names=port_counts.index,
        title="Targeted Ports Distribution"
    )
    fig.update_layout(height=400)
    return fig

def create_alerts_timeline(df):
    """Create line chart of alerts over time"""
    if df.empty or 'timestamp' not in df.columns:
        return go.Figure().add_annotation(text="No data available")
    
    try:
        timestamps = pd.to_datetime(df['timestamp'], errors='raise')
        alerts_per_minute = df.groupby(timestamps.dt.floor('1min')).size()
        
        fig = px.line(
            x=alerts_per_minute.index,
            y=alerts_per_minute.values,
            title="Alerts Over Time",
            labels={'x': 'Time', 'y': 'Number of Alerts'},
            markers=True
        )
        fig.update_layout(height=400)
        return fig
    except (AttributeError, TypeError, ValueError) as error:
        print(f"Error creating timeline: {error}")
        return go.Figure().add_annotation(text="Error processing timeline")

def create_location_chart(df):
    """Create bar chart of alerts by location"""

    if df.empty or "location" not in df.columns:
        return go.Figure().add_annotation(text="No data available")

    location_counts = df["location"].value_counts().head(10)

    fig = px.bar(
        x=location_counts.index,
        y=location_counts.values,
        title="Top 10 Locations",
        labels={
            "x": "Location",
            "y": "Alerts"
        },
        color=location_counts.values,
        color_continuous_scale="Blues"
    )

    fig.update_layout(
        height=400,
        xaxis_tickangle=-45
    )

    return fig

def create_attack_type_chart(df):
    """Create pie chart of detected attack types"""

    if df.empty or "attack_type" not in df.columns:
        return go.Figure().add_annotation(text="No data available")

    attack_counts = df["attack_type"].value_counts()

    fig = px.pie(
        values=attack_counts.values,
        names=attack_counts.index,
        title="Attack Type Distribution"
    )

    fig.update_layout(height=400)

    return fig

def create_severity_chart(df):
    """Create severity bar chart"""

    if df.empty or "severity" not in df.columns:
        return go.Figure().add_annotation(text="No data available")

    severity_counts = (
        df["severity"]
        .value_counts()
        .reindex(
            ["Low","Medium","High","Critical"],
            fill_value=0
        )
    )

    fig = px.bar(
        x=severity_counts.index,
        y=severity_counts.values,
        title="Attack Severity",
        labels={
            "x":"Severity",
            "y":"Alerts"
        },
        color=severity_counts.index
    )

    fig.update_layout(height=400)

    return fig

# Initialize Dash app
app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

# App layout
app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.H1("Advanced IDS Dashboard", className="text-center mb-4 mt-4")
        ])
    ]),
    
    # Statistics Row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Total Alerts", className="card-title"),
                    html.H2(id="total-alerts", children="0")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Blocked IPs", className="card-title"),
                    html.H2(id="blocked-ips", children="0")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Unique Sources", className="card-title"),
                    html.H2(id="unique-sources", children="0")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Last Updated", className="card-title"),
                    html.P(id="last-update", children="--:--:--")
                ])
            ])
        ], width=3)
    ], className="mb-4"),
    
    # Charts Row 1
    dbc.Row([
        dbc.Col([
            dcc.Graph(id='top-ips-graph')
        ], width=6),
        dbc.Col([
            dcc.Graph(id='port-distribution-graph')
        ], width=6)
    ], className="mb-4"),
    
    # Charts Row 2

dbc.Row([
    dbc.Col([
        dcc.Graph(id="alerts-timeline-graph")
    ], width=6),

    dbc.Col([
        dcc.Graph(id="location-graph")
    ], width=6)
], className="mb-4"),

# Charts Row 3
dbc.Row([
    dbc.Col([
        dcc.Graph(id="attack-type-graph")
    ], width=6),

    dbc.Col([
        dcc.Graph(id="severity-graph")
    ], width=6)
], className="mb-4"),
    
    # Alerts Table
    dbc.Row([
        dbc.Col([
            html.H3("Recent Alerts"),
            dash_table.DataTable(
                id='alerts-table',
                columns=[
                    {"name": "Timestamp", "id": "timestamp"},
                    {"name": "Source IP", "id": "src_ip"},
                    {"name": "Port", "id": "dst_port"},
                    {"name": "Attack Type", "id": "attack_type"},
                    {"name": "Severity", "id": "severity"},
                    {"name": "Location", "id": "location"},
                    {"name": "Blocked", "id": "blocked"},
                    {"name": "Attempts", "id": "attempt_count"}
                ],
                data=get_alerts().to_dict('records'),
                style_table={'overflowX': 'auto', 'height': '400px', 'overflowY': 'auto'},
                style_cell={
                    'textAlign': 'left',
                    'padding': '10px',
                    'backgroundColor': '#1e1e1e',
                    'color': 'white',
                    'border': '1px solid #444'
                },
                style_header={
                    'backgroundColor': '#2d2d2d',
                    'fontWeight': 'bold',
                    'border': '1px solid #555'
                },
             style_data_conditional=[
    {
        'if': {'column_id': 'blocked', 'filter_query': '{blocked} = True'},
        'backgroundColor': '#8B0000',
        'color': 'white'
    },
    {
        'if': {'column_id': 'blocked', 'filter_query': '{blocked} = False'},
        'backgroundColor': '#1a5f1a',
        'color': 'white'
    },

    {
        'if': {'filter_query': '{severity} = "Critical"'},
        'backgroundColor': '#8B0000',
        'color': 'white'
    },
    {
        'if': {'filter_query': '{severity} = "High"'},
        'backgroundColor': '#d35400',
        'color': 'white'
    },
    {
        'if': {'filter_query': '{severity} = "Medium"'},
        'backgroundColor': '#f39c12',
        'color': 'black'
    },
    {
        'if': {'filter_query': '{severity} = "Low"'},
        'backgroundColor': '#27ae60',
        'color': 'white'
    }
],
                page_size=15,
                sort_action="native",
                filter_action="native"
            )
        ], width=12)
    ], className="mb-4"),
    
    # Auto-refresh interval
    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
    
], fluid=True, style={'backgroundColor': '#121212', 'color': 'white', 'minHeight': '100vh'})

# Callbacks for real-time updates
@app.callback(
    [
        Output('alerts-table', 'data'),
        Output('top-ips-graph', 'figure'),
        Output('port-distribution-graph', 'figure'),
        Output('alerts-timeline-graph', 'figure'),
        Output('location-graph', 'figure'),
        Output('attack-type-graph', 'figure'),
        Output('severity-graph', 'figure'),
        Output('total-alerts', 'children'),
        Output('blocked-ips', 'children'),
        Output('unique-sources', 'children'),
        Output('last-update', 'children')
    ],
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n):
    """Update all dashboard elements"""
    df = get_alerts()

    # Calculate statistics
    total_alerts = len(df)
    blocked_ips = df['blocked'].sum() if 'blocked' in df.columns and not df.empty else 0
    unique_sources = df['src_ip'].nunique() if 'src_ip' in df.columns and not df.empty else 0

    # Create charts
    top_ips_fig = create_top_ips_chart(df)
    port_fig = create_port_distribution_chart(df)
    timeline_fig = create_alerts_timeline(df)
    location_fig = create_location_chart(df)
    attack_fig = create_attack_type_chart(df)
    severity_fig = create_severity_chart(df)

    # Current time
    current_time = time.strftime('%H:%M:%S')

    return (
        df.to_dict('records'),
        top_ips_fig,
        port_fig,
        timeline_fig,
        location_fig,
        attack_fig,
        severity_fig,
        str(total_alerts),
        str(int(blocked_ips)),
        str(unique_sources),
        current_time
    )

if __name__ == '__main__':
    print("Starting Advanced IDS Dashboard...")
    print("Open http://127.0.0.1:8050/ in your browser")
    app.run_server(debug=True, host='127.0.0.1', port=8050)
