"""
app.py
------
The main Streamlit dashboard for Mini SIEM.
APPROVED NO-SIDEBAR PRODUCTION LAYOUT.

Key Features & Layout Structure:
1. Header Layout: Title on the left; Database connection status, UTC time, and Refresh button aligned at the right edge.
2. Alert Queue Layout: Severity and Status filters neatly aligned on the right of the Active Security Alerts header row without crowding the section title.
3. Spacing & Hierarchy: Consistent vertical breathing room (24px–32px) between header, overview, search, charts, alert queue, and event stream.
4. Button Action Rules:
   - NEW: Both Acknowledge and Resolve are active (can resolve directly).
   - ACKNOWLEDGED: Acknowledge disabled, Resolve remains active.
   - RESOLVED: Both Acknowledge and Resolve disabled.
5. Restrained Dark SOC Aesthetic: Preserved dark color tokens, sharp 1px borders, no glows/animations/gradients.
"""

import html as html_escape
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timezone

import db_reader as db

st.set_page_config(
    page_title="Mini SIEM | Security Monitoring Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# =====================================================================
# DESIGN TOKENS
# =====================================================================
COLORS = {
    "bg": "#080B12",
    "sidebar": "#0D1320",
    "surface": "#111827",
    "elevated": "#151D2C",
    "border": "#273247",
    "border_light": "#1C2638",
    "text": "#F3F4F6",
    "text_dim": "#9CA3AF",  # WCAG AA compliant (> 4.5:1 contrast)
    "accent": "#8B5CF6",
    "accent_soft": "#A78BFA",
}

SEVERITY_COLORS = {
    "CRITICAL": "#EF4444",
    "HIGH": "#F97316",
    "MEDIUM": "#F59E0B",
    "LOW": "#64748B",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

STATUS_COLORS = {
    "NEW": "#38BDF8",
    "ACKNOWLEDGED": "#F59E0B",
    "RESOLVED": "#22C55E",
}
STATUS_ORDER = ["NEW", "ACKNOWLEDGED", "RESOLVED"]


def esc(value) -> str:
    """HTML-escape any DB-sourced value before it goes into raw markdown."""
    if value is None:
        return ""
    return html_escape.escape(str(value))


def parse_iso_timestamp(ts_str: str) -> datetime:
    """Safely parse an ISO timestamp string into a timezone-aware UTC datetime."""
    if not ts_str:
        return datetime.now(timezone.utc)
    ts_str = str(ts_str).strip()
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def time_ago(iso_ts: str) -> str:
    dt = parse_iso_timestamp(iso_ts)
    now = datetime.now(timezone.utc)
    seconds = max(0, (now - dt).total_seconds())
    if seconds < 60:
        return f"{int(seconds)}S AGO"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)} MIN AGO"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)} HR AGO"
    days = int(hours / 24)
    return f"{days} DAY{'S' if days != 1 else ''} AGO"


def readable_timestamp(iso_ts: str) -> str:
    dt = parse_iso_timestamp(iso_ts)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def truncate(text: str, length: int) -> str:
    text = str(text)
    return text if len(text) <= length else text[: length - 1] + "…"


def clean_html(fragment: str) -> str:
    """Collapse multi-line HTML string into a single clean line."""
    return "".join(line.strip() for line in fragment.strip().splitlines())


# =====================================================================
# GLOBAL CSS — REVISED TRIAL STYLES
# =====================================================================
st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* Hide Streamlit Chrome & Headers */
    header[data-testid="stHeader"] {{
        display: none !important;
    }}
    footer {{
        display: none !important;
    }}
    #MainMenu {{
        visibility: hidden;
    }}
    div[data-testid="stDecoration"] {{
        display: none !important;
    }}

    /* Global App Container */
    .stApp {{
        background: {COLORS['bg']};
        font-family: 'Inter', -apple-system, sans-serif;
        color: {COLORS['text']};
    }}
    .block-container {{
        max-width: 1400px;
        padding-top: 24px;
        padding-bottom: 56px;
        padding-left: 28px;
        padding-right: 28px;
    }}

    /* Headings & Typography Hierarchy */
    h1, h2, h3, h4 {{
        font-family: 'Inter', sans-serif !important;
        color: {COLORS['text']} !important;
    }}
    .section-title {{
        font-size: 19px;
        font-weight: 750;
        letter-spacing: -0.01em;
        color: {COLORS['text']};
        margin: 0;
        display: flex;
        align-items: center;
        gap: 10px;
    }}
    .section-count {{
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: {COLORS['text_dim']};
        background: {COLORS['surface']};
        border: 1px solid {COLORS['border']};
        border-radius: 999px;
        padding: 3px 9px;
        white-space: nowrap;
    }}
    .section-sub {{
        font-size: 12.5px;
        color: {COLORS['text_dim']};
        margin: 2px 0 0 0;
    }}

    /* Top App Header Strip */
    .header-bar {{
        padding-bottom: 12px;
        margin-bottom: 20px;
        border-bottom: 1px solid {COLORS['border']};
    }}
    .header-tag {{
        font-size: 10.5px;
        font-weight: 700;
        letter-spacing: 0.08em;
        color: {COLORS['text_dim']};
        text-transform: uppercase;
    }}
    .header-title {{
        font-size: 22px;
        font-weight: 800;
        color: {COLORS['text']};
        letter-spacing: -0.01em;
        margin: 2px 0 0 0;
    }}
    .header-meta-box {{
        text-align: right;
    }}
    .header-status {{
        font-size: 11.5px;
        font-weight: 600;
        color: {COLORS['text']};
        display: flex;
        align-items: center;
        gap: 6px;
        justify-content: flex-end;
    }}
    .status-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
    }}
    .header-refreshed {{
        font-size: 11px;
        color: {COLORS['text_dim']};
        margin-top: 2px;
        font-family: 'JetBrains Mono', monospace;
    }}

    /* Popover Menu Controls */
    div[data-testid="stPopover"] button {{
        background-color: {COLORS['surface']} !important;
        border: 1px solid {COLORS['border']} !important;
        color: {COLORS['text']} !important;
        font-size: 12px !important;
        font-weight: 500 !important;
        border-radius: 5px !important;
        text-align: left !important;
        padding: 5px 12px !important;
        min-height: 36px !important;
        box-shadow: none !important;
    }}
    div[data-testid="stPopover"] button:hover {{
        border-color: {COLORS['accent']} !important;
        color: {COLORS['accent_soft']} !important;
    }}

    div[data-testid="stPopoverBody"] {{
        background-color: {COLORS['surface']} !important;
        border: 1px solid {COLORS['border']} !important;
        border-radius: 6px !important;
        padding: 14px !important;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6) !important;
    }}
    .popover-header {{
        font-size: 11px;
        font-weight: 700;
        color: {COLORS['text_dim']};
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 10px;
    }}

    /* Security Overview Strip Module */
    .overview-strip-card {{
        background: {COLORS['surface']};
        border: 1px solid {COLORS['border']};
        border-radius: 6px;
        padding: 16px 20px;
        margin-bottom: 24px;
    }}
    .overview-strip-header {{
        font-size: 11px;
        font-weight: 700;
        color: {COLORS['text_dim']};
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 12px;
    }}
    .overview-grid {{
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 16px;
    }}
    .overview-cell {{
        flex: 1 1 110px;
        min-width: 100px;
        padding: 2px 12px 2px 0;
        border-right: 1px solid {COLORS['border_light']};
    }}
    .overview-cell:last-child {{
        border-right: none;
    }}
    .overview-label {{
        font-size: 11px;
        font-weight: 600;
        color: {COLORS['text_dim']};
        letter-spacing: 0.05em;
        text-transform: uppercase;
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 4px;
    }}
    .overview-val {{
        font-size: 24px;
        font-weight: 700;
        line-height: 1;
        color: {COLORS['text']};
    }}

    /* Chart Headings */
    .chart-card-title {{
        font-size: 11.5px;
        font-weight: 700;
        color: {COLORS['text_dim']};
        letter-spacing: 0.06em;
        text-transform: uppercase;
        margin-bottom: 2px;
    }}
    .chart-card-sub {{
        font-size: 11px;
        color: {COLORS['text_dim']};
        margin-bottom: 10px;
    }}

    /* Alert Cards */
    .alert-header-line {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 6px;
    }}
    .alert-sev-tag {{
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.05em;
        display: flex;
        align-items: center;
        gap: 6px;
    }}
    .alert-status-badge {{
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.04em;
    }}
    .detection-badge {{
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.05em;
        padding: 2px 6px;
        border-radius: 3px;
        background: rgba(139, 92, 246, 0.15);
        color: {COLORS['accent_soft']};
        border: 1px solid rgba(139, 92, 246, 0.3);
        margin-left: 8px;
    }}
    .alert-type-title {{
        font-size: 14.5px;
        font-weight: 700;
        color: {COLORS['text']};
        font-family: 'JetBrains Mono', monospace;
        margin-bottom: 6px;
    }}
    .alert-evidence-text {{
        font-size: 12.5px;
        color: {COLORS['text_dim']};
        margin-bottom: 10px;
        line-height: 1.4;
    }}
    .alert-stats-grid {{
        display: flex;
        flex-wrap: wrap;
        gap: 24px;
        padding-top: 8px;
        border-top: 1px solid {COLORS['border_light']};
    }}
    .alert-stat-label {{
        font-size: 10.5px;
        color: {COLORS['text_dim']};
        letter-spacing: 0.05em;
        text-transform: uppercase;
        margin-bottom: 2px;
    }}
    .alert-stat-val {{
        font-size: 12.5px;
        font-weight: 600;
        color: {COLORS['text']};
        font-family: 'JetBrains Mono', monospace;
    }}

    /* Detail Expander Custom Styling */
    div[data-testid="stExpander"] {{
        border: none !important;
        background: transparent !important;
        margin-top: 6px;
    }}
    div[data-testid="stExpander"] summary {{
        padding: 4px 0 !important;
        min-height: unset !important;
    }}
    div[data-testid="stExpander"] summary p {{
        font-size: 11.5px !important;
        font-weight: 600 !important;
        color: {COLORS['accent_soft']} !important;
        letter-spacing: 0.03em;
    }}

    .detail-row {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 5px 0;
        border-bottom: 1px solid {COLORS['border_light']};
    }}
    .detail-row-label {{
        color: {COLORS['text_dim']};
        font-size: 11px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }}
    .detail-row-val {{
        color: {COLORS['text']};
        font-size: 12px;
        font-weight: 500;
    }}
    .detail-row-val.mono {{
        font-family: 'JetBrains Mono', monospace;
    }}

    .evidence-box {{
        background: {COLORS['elevated']};
        border-left: 3px solid {COLORS['accent']};
        padding: 10px 14px;
        border-radius: 4px;
        font-size: 12px;
        color: {COLORS['text']};
        line-height: 1.45;
        margin: 6px 0 10px 0;
    }}

    /* Supporting Events Table */
    .supporting-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 11.5px;
        margin: 6px 0 12px 0;
    }}
    .supporting-table thead th {{
        text-align: left;
        font-size: 10.5px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        color: {COLORS['text_dim']};
        font-weight: 700;
        padding: 6px 10px;
        background: {COLORS['surface']};
        border-bottom: 1px solid {COLORS['border']};
    }}
    .supporting-table tbody td {{
        padding: 6px 10px;
        border-bottom: 1px solid {COLORS['border_light']};
        color: {COLORS['text']};
        white-space: nowrap;
    }}

    /* Dark Console Action Buttons */
    div[data-testid="stButton"] button {{
        background-color: {COLORS['elevated']} !important;
        color: {COLORS['text']} !important;
        border: 1px solid {COLORS['border']} !important;
        border-radius: 5px !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        padding: 5px 12px !important;
        transition: all 0.15s ease !important;
    }}
    div[data-testid="stButton"] button:hover:not(:disabled) {{
        border-color: {COLORS['accent']} !important;
        color: {COLORS['accent_soft']} !important;
        background-color: #1A2338 !important;
    }}
    div[data-testid="stButton"] button:disabled {{
        opacity: 0.4 !important;
        cursor: not-allowed !important;
    }}

    /* Event Stream Log Table */
    .event-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 12px;
        margin-top: 8px;
    }}
    .event-table thead th {{
        text-align: left;
        font-size: 10.5px;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: {COLORS['text_dim']};
        font-weight: 700;
        padding: 8px 12px;
        background: {COLORS['surface']};
        border-bottom: 1px solid {COLORS['border']};
    }}
    .event-table tbody td {{
        padding: 8px 12px;
        border-bottom: 1px solid {COLORS['border_light']};
        color: {COLORS['text']};
        white-space: nowrap;
    }}
    .event-table tbody tr:hover {{
        background: {COLORS['elevated']};
    }}
    .event-mono {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 11.5px;
        color: {COLORS['text_dim']};
    }}
    .event-mono.bold {{
        font-weight: 600;
        color: {COLORS['text']};
    }}
    .service-badge {{
        display: inline-block;
        font-size: 9.5px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        padding: 2px 6px;
        border-radius: 3px;
        background: {COLORS['elevated']};
        border: 1px solid {COLORS['border']};
        color: {COLORS['text_dim']};
    }}
    .event-msg-cell {{
        max-width: 320px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        color: {COLORS['text_dim']};
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# =====================================================================
# DATA INITIALIZATION & DB CHECK
# =====================================================================
current_db_path = db.get_db_path()
try:
    summary = db.get_alert_summary()
    db_connected = True
except FileNotFoundError as e:
    db_connected = False
    db_error = str(e)
except Exception as e:
    db_connected = False
    db_error = f"Database error: {e}"

all_alerts = db.get_all_alerts() if db_connected else []
all_events = db.get_all_events() if db_connected else []


# Initialize Session State for Filters
if "filter_severities" not in st.session_state:
    st.session_state["filter_severities"] = list(SEVERITY_ORDER)

if "filter_statuses" not in st.session_state:
    st.session_state["filter_statuses"] = list(STATUS_ORDER)


def set_filter_selection(state_key: str, widget_prefix: str, choices: list[str]) -> None:
    """Keep stored filter and Streamlit's checkbox widget state in sync."""
    st.session_state[state_key] = list(choices)
    for choice in SEVERITY_ORDER if state_key == "filter_severities" else STATUS_ORDER:
        st.session_state[f"{widget_prefix}{choice}"] = choice in choices


def format_filter_label(selected_items: list, all_items: list, prefix: str) -> str:
    if len(selected_items) == len(all_items):
        return f"{prefix}: All"
    if len(selected_items) == 0:
        return f"{prefix}: None"
    if len(selected_items) == 1:
        return f"{prefix}: {selected_items[0].title()}"
    if len(selected_items) == 2:
        return f"{prefix}: {selected_items[0].title()}, {selected_items[1].title()}"
    return f"{prefix}: {len(selected_items)} selected"


# =====================================================================
# REVISED TOP HEADER — TITLE LEFT, REFRESH + STATUS AT RIGHT EDGE
# =====================================================================
head_col1, head_col2 = st.columns([2.5, 2], vertical_alignment="center")

with head_col1:
    st.markdown(
        clean_html(f"""
        <div class="header-bar" style="border-bottom:none;padding-bottom:0;margin-bottom:0;">
            <div>
                <div class="header-tag">SECURITY MONITORING CONSOLE</div>
                <div class="header-title">Mini SIEM</div>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

with head_col2:
    status_col, refresh_col = st.columns([1.8, 1], vertical_alignment="center")
    with status_col:
        status_dot_c = "#22C55E" if db_connected else SEVERITY_COLORS["CRITICAL"]
        db_status_txt = "DATABASE CONNECTED" if db_connected else "DATABASE OFFLINE"
        now_ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        st.markdown(
            clean_html(f"""
            <div class="header-meta-box">
                <div class="header-status">
                    <span class="status-dot" style="background:{status_dot_c};"></span>
                    {db_status_txt}
                </div>
                <div class="header-refreshed" title="{esc(current_db_path)}">DATA: {esc(current_db_path.name)}</div>
                <div class="header-refreshed">{now_ts} UTC</div>
            </div>
            """),
            unsafe_allow_html=True,
        )
    with refresh_col:
        if st.button("↻  Refresh", key="header_refresh", use_container_width=True):
            st.rerun()

if not db_connected:
    st.warning(
        f"**Database Not Accessible**: {esc(db_error)}\n\n"
        f"**Target DB Path**: `{esc(current_db_path)}`\n\n"
        f"To seed disposable test data safely without modifying production database, run:\n"
        f"```bash\n"
        f"python3 dashboard/seed_test_data.py\n"
        f"SIEM_DB_PATH=\"data/siem_demo.db\" python3 -m streamlit run dashboard/app.py\n"
        f"```"
    )
    st.stop()

st.markdown('<div class="sidebar-divider" style="margin-top:4px;margin-bottom:24px;"></div>', unsafe_allow_html=True)


# =====================================================================
# SECURITY OVERVIEW — KPI STRIP MODULE
# =====================================================================
sev_counts = summary["severity_counts"]

cells_data = [
    ("TOTAL ALERTS", summary["total_alerts"], None, COLORS["text"]),
    ("NEW", summary["new_count"], STATUS_COLORS["NEW"], STATUS_COLORS["NEW"]),
    ("CRITICAL", sev_counts["CRITICAL"], SEVERITY_COLORS["CRITICAL"], SEVERITY_COLORS["CRITICAL"]),
    ("HIGH", sev_counts["HIGH"], SEVERITY_COLORS["HIGH"], SEVERITY_COLORS["HIGH"]),
    ("MEDIUM", sev_counts["MEDIUM"], SEVERITY_COLORS["MEDIUM"], SEVERITY_COLORS["MEDIUM"]),
    ("LOW", sev_counts["LOW"], SEVERITY_COLORS["LOW"], SEVERITY_COLORS["LOW"]),
]

cells_html = ""
for label, val, dot_color, num_color in cells_data:
    dot_html = f'<span class="status-dot" style="background:{dot_color};"></span>' if dot_color else ""
    cells_html += clean_html(f"""
    <div class="overview-cell">
        <div class="overview-label">{dot_html}{label}</div>
        <div class="overview-val" style="color:{num_color};">{val}</div>
    </div>
    """)

st.markdown(
    clean_html(f"""
    <div class="overview-strip-card">
        <div class="overview-strip-header">Security Overview</div>
        <div class="overview-grid">
            {cells_html}
        </div>
    </div>
    """),
    unsafe_allow_html=True,
)


# =====================================================================
# SEARCH & INVESTIGATION FILTER (Scope: Active Alerts & Event Stream)
# =====================================================================
search_query = st.text_input(
    "Source IP / Keyword Investigation Search",
    value="",
    placeholder="Filter alerts and event stream by Source IP (e.g. 10.0.0.5) or message keyword...",
    key="global_search_input",
    help="Filters both the Active Security Alerts queue and the Event Stream log table by matching Source IP, evidence, or raw log message text.",
).strip()

st.markdown('<div style="height:20px;"></div>', unsafe_allow_html=True)


# =====================================================================
# MAIN ANALYTICS — BAR CHART & THREAT DONUT
# =====================================================================
chart_col1, chart_col2 = st.columns([1.75, 1])

with chart_col1, st.container(border=True):
    if all_alerts:
        df_time = pd.DataFrame(all_alerts)
        df_time["dt"] = df_time["timestamp"].apply(parse_iso_timestamp)
        time_span = (df_time["dt"].max() - df_time["dt"].min()).total_seconds()

        # Adaptively group by hour for short periods (< 24h) or date for multi-day spans
        if time_span < 86400:
            df_time["time_group"] = df_time["dt"].apply(lambda t: t.strftime("%H:00 UTC"))
            chart_sub = "Alert volume grouped by hour (UTC)"
            x_title = "Hour (UTC)"
        else:
            df_time["time_group"] = df_time["dt"].apply(lambda t: t.strftime("%Y-%m-%d"))
            chart_sub = "Alert volume grouped by date"
            x_title = "Date"

        daily = df_time.groupby("time_group").size().reset_index(name="count")

        st.markdown(
            clean_html(f"""
            <div class="chart-card-title">Alert Activity</div>
            <div class="chart-card-sub">{chart_sub}</div>
            """),
            unsafe_allow_html=True,
        )

        fig_bar = go.Figure(
            data=[
                go.Bar(
                    x=daily["time_group"].astype(str),
                    y=daily["count"],
                    marker=dict(color=COLORS["accent"], cornerradius=3),
                    hovertemplate="%{x}<br><b>%{y} alerts</b><extra></extra>",
                )
            ]
        )
        fig_bar.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=10, r=10, t=5, b=25),
            height=220,
            font=dict(family="Inter, sans-serif"),
            bargap=0.5,
            xaxis=dict(
                type="category",
                showgrid=False,
                tickfont=dict(size=11, color=COLORS["text_dim"]),
                linecolor=COLORS["border"],
                title=dict(text=x_title, font=dict(size=10, color=COLORS["text_dim"])),
            ),
            yaxis=dict(
                showgrid=True,
                gridcolor=COLORS["border_light"],
                tickfont=dict(size=11, color=COLORS["text_dim"]),
                title=dict(text="Alerts", font=dict(size=10, color=COLORS["text_dim"])),
                dtick=1,
                zeroline=False,
                rangemode="tozero",
            ),
            hoverlabel=dict(bgcolor=COLORS["elevated"], font_size=12, font_family="Inter"),
        )
        st.plotly_chart(fig_bar, use_container_width=True, theme=None, config={"displayModeBar": False})
    else:
        st.markdown(
            clean_html(f"""
            <div class="chart-card-title">Alert Activity</div>
            <div class="chart-card-sub">Alert volume</div>
            <div style="color:{COLORS['text_dim']};font-size:12px;margin-top:20px;">No alert activity recorded in database.</div>
            """),
            unsafe_allow_html=True,
        )

with chart_col2, st.container(border=True):
    st.markdown(
        clean_html(f"""
        <div class="chart-card-title">Threat Distribution</div>
        <div class="chart-card-sub">Alert breakdown by severity</div>
        """),
        unsafe_allow_html=True,
    )
    active_labels = [s for s in SEVERITY_ORDER if sev_counts[s] > 0]
    active_values = [sev_counts[s] for s in active_labels]

    if active_values:
        fig_donut = go.Figure(
            data=[
                go.Pie(
                    labels=[f"{s.title()} ({sev_counts[s]})" for s in active_labels],
                    values=active_values,
                    hole=0.72,
                    marker=dict(
                        colors=[SEVERITY_COLORS[s] for s in active_labels],
                        line=dict(color=COLORS["surface"], width=2),
                    ),
                    textinfo="none",
                    sort=False,
                    hovertemplate="%{label}<extra></extra>",
                )
            ]
        )
        fig_donut.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="top",
                y=-0.1,
                xanchor="center",
                x=0.5,
                font=dict(size=10.5, color=COLORS["text_dim"]),
            ),
            margin=dict(l=10, r=10, t=5, b=25),
            height=220,
            annotations=[
                dict(
                    text=f"<b>{summary['total_alerts']}</b><br><span style='font-size:9px;color:{COLORS['text_dim']}'>TOTAL</span>",
                    x=0.5,
                    y=0.5,
                    font=dict(size=19, color=COLORS["text"], family="Inter"),
                    showarrow=False,
                )
            ],
            hoverlabel=dict(bgcolor=COLORS["elevated"], font_size=12, font_family="Inter"),
        )
        st.plotly_chart(fig_donut, use_container_width=True, theme=None, config={"displayModeBar": False})
    else:
        st.markdown(f'<span style="color:{COLORS["text_dim"]};font-size:12px;">No severity data available.</span>', unsafe_allow_html=True)

st.markdown('<div style="height:28px;"></div>', unsafe_allow_html=True)


# =====================================================================
# ACTIVE SECURITY ALERTS QUEUE (Uncrowded Heading & Filter Layout)
# =====================================================================
filtered_alerts = [
    a for a in all_alerts
    if a["severity"] in st.session_state["filter_severities"]
    and a["status"] in st.session_state["filter_statuses"]
]

if search_query:
    q = search_query.lower()
    filtered_alerts = [
        a for a in filtered_alerts
        if q in a["source_ip"].lower()
        or q in a.get("evidence", "").lower()
        or q in a.get("alert_type", "").lower()
    ]

# UNCROWDED ALERTS HEADER ROW — HEADING ON LEFT, FILTERS ON RIGHT
alerts_header_left, alerts_header_right = st.columns([3, 2], vertical_alignment="center")

with alerts_header_left:
    st.markdown(
        clean_html(f"""
        <div>
            <div class="section-title">
                <span>Active Security Alerts</span>
                <span class="section-count">{len(filtered_alerts)} alerts shown</span>
            </div>
            <div class="section-sub">Review detections and take direct status triage actions</div>
        </div>
        """),
        unsafe_allow_html=True,
    )

with alerts_header_right:
    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        sev_btn_label = format_filter_label(st.session_state["filter_severities"], SEVERITY_ORDER, "Severity")
        with st.popover(sev_btn_label, use_container_width=True):
            st.markdown('<div class="popover-header">Filter Severity</div>', unsafe_allow_html=True)
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Select All", key="top_sev_all_btn", use_container_width=True):
                    set_filter_selection("filter_severities", "chk_sev_", SEVERITY_ORDER)
                    st.rerun()
            with col_b:
                if st.button("Clear", key="top_sev_clear_btn", use_container_width=True):
                    set_filter_selection("filter_severities", "chk_sev_", [])
                    st.rerun()

            st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)
            updated_sevs = []
            for sev in SEVERITY_ORDER:
                is_chk = sev in st.session_state["filter_severities"]
                chk = st.checkbox(f"● {sev.title()}", value=is_chk, key=f"chk_sev_{sev}")
                if chk:
                    updated_sevs.append(sev)

            if updated_sevs != st.session_state["filter_severities"]:
                st.session_state["filter_severities"] = updated_sevs
                st.rerun()

    with filter_col2:
        status_btn_label = format_filter_label(st.session_state["filter_statuses"], STATUS_ORDER, "Status")
        with st.popover(status_btn_label, use_container_width=True):
            st.markdown('<div class="popover-header">Filter Status</div>', unsafe_allow_html=True)
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Select All", key="top_stat_all_btn", use_container_width=True):
                    set_filter_selection("filter_statuses", "chk_stat_", STATUS_ORDER)
                    st.rerun()
            with col_b:
                if st.button("Clear", key="top_stat_clear_btn", use_container_width=True):
                    set_filter_selection("filter_statuses", "chk_stat_", [])
                    st.rerun()

            st.markdown('<div style="height:6px;"></div>', unsafe_allow_html=True)
            updated_stats = []
            for stat in STATUS_ORDER:
                is_chk = stat in st.session_state["filter_statuses"]
                chk = st.checkbox(f"● {stat.title()}", value=is_chk, key=f"chk_stat_{stat}")
                if chk:
                    updated_stats.append(stat)

            if updated_stats != st.session_state["filter_statuses"]:
                st.session_state["filter_statuses"] = updated_stats
                st.rerun()

st.markdown('<div style="height:14px;"></div>', unsafe_allow_html=True)

if not filtered_alerts:
    st.info("No security alerts match the selected filters or search query.")
else:
    for idx, alert in enumerate(filtered_alerts):
        sev = alert["severity"]
        sev_color = SEVERITY_COLORS.get(sev, COLORS["text_dim"])
        status_color = STATUS_COLORS.get(alert["status"], COLORS["text_dim"])
        det_source = alert.get("detection_source", "RULE")
        det_badge_html = f'<span class="detection-badge">{esc(det_source)}</span>' if det_source else ""

        # ALERT STATUS ACTION RULES:
        # NEW: Acknowledge=Active, Resolve=Active (can resolve directly)
        # ACKNOWLEDGED: Acknowledge=Disabled, Resolve=Active
        # RESOLVED: Acknowledge=Disabled, Resolve=Disabled
        ack_disabled = (alert["status"] != "NEW")
        resolve_disabled = (alert["status"] == "RESOLVED")

        with st.container(border=True):
            card_col1, card_col2 = st.columns([3.8, 1.2], vertical_alignment="top")

            with card_col1:
                st.markdown(
                    clean_html(f"""
                    <div class="alert-header-line">
                        <div class="alert-sev-tag" style="color:{sev_color};">
                            <span class="status-dot" style="background:{sev_color};"></span>
                            {esc(sev)}{det_badge_html}
                        </div>
                        <div class="alert-status-badge" style="color:{status_color};">
                            &#9679; {esc(alert['status'])}
                        </div>
                    </div>
                    <div class="alert-type-title">{esc(alert['alert_type'])}</div>
                    <div class="alert-evidence-text">{esc(alert['evidence'])}</div>
                    <div class="alert-stats-grid">
                        <div>
                            <div class="alert-stat-label">Source IP</div>
                            <div class="alert-stat-val">{esc(alert['source_ip'])}</div>
                        </div>
                        <div>
                            <div class="alert-stat-label">Events</div>
                            <div class="alert-stat-val">{alert['event_count']}</div>
                        </div>
                        <div>
                            <div class="alert-stat-label">Detected</div>
                            <div class="alert-stat-val">{time_ago(alert['timestamp'])}</div>
                        </div>
                    </div>
                    """),
                    unsafe_allow_html=True,
                )

            with card_col2:
                st.markdown('<div style="font-size:10.5px;font-weight:700;color:#9CA3AF;letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px;">Triage Actions</div>', unsafe_allow_html=True)
                if st.button(
                    "Acknowledge",
                    key=f"card_ack_{alert['alert_id']}",
                    disabled=ack_disabled,
                    use_container_width=True,
                ):
                    db.update_alert_status(alert["alert_id"], "ACKNOWLEDGED")
                    st.rerun()

                st.markdown('<div style="height:4px;"></div>', unsafe_allow_html=True)
                if st.button(
                    "Resolve",
                    key=f"card_resolve_{alert['alert_id']}",
                    disabled=resolve_disabled,
                    use_container_width=True,
                ):
                    db.update_alert_status(alert["alert_id"], "RESOLVED")
                    st.rerun()

            with st.expander("›  VIEW EVIDENCE LOG & SUPPORTING EVENTS"):
                detail_rows = [
                    ("Alert Type", esc(alert["alert_type"]), True),
                    ("Severity", esc(sev), False),
                    ("Source IP", esc(alert["source_ip"]), True),
                    ("Event Count", str(alert["event_count"]), True),
                    ("Detected Time", readable_timestamp(alert["timestamp"]), True),
                    ("Detection Source", esc(det_source), True),
                ]
                rows_html = "".join(
                    clean_html(f"""
                    <div class="detail-row">
                        <span class="detail-row-label">{label}</span>
                        <span class="detail-row-val{' mono' if is_mono else ''}">{val}</span>
                    </div>
                    """)
                    for label, val, is_mono in detail_rows
                )
                st.markdown(rows_html, unsafe_allow_html=True)

                st.markdown('<div class="detail-row-label" style="margin-top:10px;">Evidence Log Summary</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="evidence-box">{esc(alert["evidence"])}</div>', unsafe_allow_html=True)

                # LINKED SUPPORTING EVENTS VIA alert_events
                st.markdown('<div class="detail-row-label" style="margin-top:10px;margin-bottom:6px;">Supporting Events (Evidence Traceability)</div>', unsafe_allow_html=True)
                linked_events = db.get_alert_events(alert["alert_id"])
                if linked_events:
                    evt_rows_html = ""
                    for le in linked_events:
                        dest_info = esc(le.get("destination_ip"))
                        if le.get("destination_port"):
                            dest_info += f":{le['destination_port']}"
                        if not dest_info:
                            dest_info = "—"
                        evt_rows_html += clean_html(f"""
                        <tr>
                            <td class="event-mono">{esc(readable_timestamp(le['timestamp']))}</td>
                            <td class="event-mono bold">{esc(le['event_type'])}</td>
                            <td><span class="service-badge">{esc(le['service'])}</span></td>
                            <td class="event-mono">{esc(le['source_ip'])}</td>
                            <td class="event-mono">{dest_info}</td>
                            <td class="event-msg-cell" title="{esc(le['message'])}">{esc(truncate(le['message'], 60))}</td>
                        </tr>
                        """)

                    st.markdown(
                        clean_html(f"""
                        <table class="supporting-table">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Event Type</th>
                                    <th>Service</th>
                                    <th>Source</th>
                                    <th>Destination</th>
                                    <th>Message</th>
                                </tr>
                            </thead>
                            <tbody>
                                {evt_rows_html}
                            </tbody>
                        </table>
                        """),
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div style="font-size:12px;color:{COLORS["text_dim"]};margin-bottom:8px;">'
                        f'No linked event evidence records found in <code>alert_events</code> table for Alert #{alert["alert_id"]}.'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

st.markdown('<div style="height:32px;"></div>', unsafe_allow_html=True)


# =====================================================================
# EVENT STREAM LOG VIEWER (With Localized Table Filters)
# =====================================================================
st.markdown(
    clean_html(f"""
    <div>
        <div class="section-title">
            <span>Event Stream</span>
            <span class="section-count">{len(all_events)} total events</span>
        </div>
        <div class="section-sub">Raw security events received by the SIEM</div>
    </div>
    """),
    unsafe_allow_html=True,
)

st.markdown('<div style="height:12px;"></div>', unsafe_allow_html=True)

with st.container(border=True):
    if not all_events:
        st.info("No events recorded in database.")
    else:
        events_df = pd.DataFrame(all_events)

        svc_opts = ["All Services"] + sorted(events_df["service"].dropna().unique().tolist())
        typ_opts = ["All Event Types"] + sorted(events_df["event_type"].dropna().unique().tolist())

        ctrl_c1, ctrl_c2, ctrl_c3, ctrl_c4 = st.columns([1.5, 1.5, 1, 1], vertical_alignment="bottom")

        with ctrl_c1:
            sel_service = st.selectbox("Service", svc_opts, key="table_service_filter")
        with ctrl_c2:
            sel_type = st.selectbox("Event Type", typ_opts, key="table_type_filter")
        with ctrl_c3:
            page_size = st.selectbox("Rows per page", [10, 25, 50], index=0, key="evt_page_size")

        filtered_df = events_df.copy()
        if sel_service != "All Services":
            filtered_df = filtered_df[filtered_df["service"] == sel_service]
        if sel_type != "All Event Types":
            filtered_df = filtered_df[filtered_df["event_type"] == sel_type]
        if search_query:
            sq = search_query.lower()
            filtered_df = filtered_df[
                filtered_df["source_ip"].str.lower().str.contains(sq, na=False)
                | filtered_df["message"].str.lower().str.contains(sq, na=False)
                | filtered_df["event_type"].str.lower().str.contains(sq, na=False)
                | filtered_df["service"].str.lower().str.contains(sq, na=False)
            ]

        total_rows = len(filtered_df)
        total_pages = max(1, -(-total_rows // page_size))

        with ctrl_c4:
            page_num = st.number_input(
                "Page",
                min_value=1,
                max_value=total_pages,
                value=min(1, total_pages),
                step=1,
                key="evt_page_num",
            )
            page_num = min(page_num, total_pages)

        start_idx = (page_num - 1) * page_size
        end_idx = start_idx + page_size
        page_df = filtered_df.iloc[start_idx:end_idx]

        if page_df.empty:
            st.info("No events match the selected service, event type, or search query.")
        else:
            rows_html = ""
            for _, row in page_df.iterrows():
                dest_str = esc(row.get("destination_ip")) if row.get("destination_ip") else "—"
                if row.get("destination_port"):
                    dest_str += f":{row['destination_port']}"

                rows_html += clean_html(f"""
                <tr>
                    <td class="event-mono">{esc(readable_timestamp(row['timestamp']))}</td>
                    <td class="event-mono bold">{esc(row['event_type'])}</td>
                    <td><span class="service-badge">{esc(row['service'])}</span></td>
                    <td class="event-mono">{esc(row['source_ip'])}</td>
                    <td class="event-mono">{dest_str}</td>
                    <td class="event-msg-cell" title="{esc(row['message'])}">{esc(truncate(row['message'], 65))}</td>
                </tr>
                """)

            table_html = clean_html(f"""
            <table class="event-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Service</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
            """)
            st.markdown(table_html, unsafe_allow_html=True)

            st.markdown(
                clean_html(f"""
                <div style="font-size:11px;color:{COLORS['text_dim']};margin-top:10px;">
                    Showing {start_idx + 1}-{min(end_idx, total_rows)} of {total_rows} matching events &middot; Page {page_num} of {total_pages}
                </div>
                """),
                unsafe_allow_html=True,
            )
