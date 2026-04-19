import streamlit as st
import os
import pandas as pd
import json
from pathlib import Path
from datetime import datetime

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(
    page_title="Retail Digital Forensics System",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# CONSTANTS
# ============================================================================
PROJECT_DIR = Path(__file__).parent
RETAIL_FILES_DIR = PROJECT_DIR / "retail_files"
BASELINE_FILE = PROJECT_DIR / "baseline.csv"
EVIDENCE_FILE = PROJECT_DIR / "evidence_report.csv"
CUSTOMERS_FILE = RETAIL_FILES_DIR / "customers.csv"
PRODUCTS_FILE = RETAIL_FILES_DIR / "products.json"

WORKING_HOURS_START = 10  # 10 AM
WORKING_HOURS_END = 22    # 10 PM

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================
if "baseline_data" not in st.session_state:
    st.session_state.baseline_data = None
if "current_scan" not in st.session_state:
    st.session_state.current_scan = None
if "edit_customer_index" not in st.session_state:
    st.session_state.edit_customer_index = None
if "edit_product_index" not in st.session_state:
    st.session_state.edit_product_index = None

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def ensure_retail_files_dir():
    """Ensure retail_files directory exists."""
    RETAIL_FILES_DIR.mkdir(parents=True, exist_ok=True)

def get_file_metadata(file_path):
    """Get metadata for a single file."""
    try:
        stat = file_path.stat()
        created_time = datetime.fromtimestamp(stat.st_ctime)
        modified_time = datetime.fromtimestamp(stat.st_mtime)
        
        return {
            "File Name": file_path.name,
            "Path": str(file_path),
            "Size (Bytes)": stat.st_size,
            "Created Time": created_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Modified Time": modified_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Created Timestamp": stat.st_ctime,
            "Modified Timestamp": stat.st_mtime
        }
    except Exception as e:
        return None

def scan_retail_files():
    """Scan all files in retail_files folder."""
    ensure_retail_files_dir()
    
    files_data = []
    
    try:
        if not RETAIL_FILES_DIR.exists():
            return pd.DataFrame()
        
        for file_path in sorted(RETAIL_FILES_DIR.glob("*")):
            if file_path.is_file():
                metadata = get_file_metadata(file_path)
                if metadata:
                    files_data.append(metadata)
        
        if files_data:
            return pd.DataFrame(files_data)
        return pd.DataFrame()
    
    except Exception as e:
        st.error(f"Error scanning folder: {str(e)}")
        return pd.DataFrame()

def load_baseline():
    """Load baseline data from baseline.csv - handles empty files safely."""
    try:
        if not BASELINE_FILE.exists():
            return None
        
        df = pd.read_csv(BASELINE_FILE)
        
        # Check if dataframe is empty
        if df.empty:
            return None
        
        return df
    except Exception as e:
        return None

def save_baseline(scan_df):
    """Save current scan as baseline."""
    try:
        if scan_df is None or scan_df.empty:
            st.error("❌ Cannot save empty scan as baseline")
            return False
        
        scan_df.to_csv(BASELINE_FILE, index=False)
        st.session_state.baseline_data = scan_df.copy()
        return True
    except Exception as e:
        st.error(f"Error saving baseline: {str(e)}")
        return False

def is_after_hours(timestamp):
    """Check if timestamp is outside working hours (10 AM - 10 PM)."""
    try:
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour
        return hour < WORKING_HOURS_START or hour >= WORKING_HOURS_END
    except:
        return False

def compare_with_baseline(current_scan, baseline):
    """Compare current scan with baseline to detect changes."""
    # SAFE CHECK: Use 'is None' instead of 'or' which causes ambiguous truth value error
    if baseline is None:
        return current_scan.assign(Status="New Scan", **{"Risk Level": "Low"})
    
    if baseline.empty:
        return current_scan.assign(Status="New Scan", **{"Risk Level": "Low"})
    
    current_files = set(current_scan["File Name"].values)
    baseline_files = set(baseline["File Name"].values)
    
    results = []
    
    for _, row in current_scan.iterrows():
        file_name = row["File Name"]
        status = "Normal"
        risk_level = "Low"
        
        if file_name not in baseline_files:
            # New file detected
            status = "New File"
            risk_level = "Medium"
        else:
            # File exists in baseline - check for modifications
            baseline_row = baseline[baseline["File Name"] == file_name].iloc[0]
            
            if row["Modified Time"] != baseline_row["Modified Time"]:
                # File has been modified
                if is_after_hours(row["Modified Timestamp"]):
                    status = "Tampered (After Hours)"
                    risk_level = "High"
                else:
                    status = "Modified"
                    risk_level = "Medium"
        
        row_dict = row.to_dict()
        row_dict["Status"] = status
        row_dict["Risk Level"] = risk_level
        results.append(row_dict)
    
    # Check for deleted files
    for deleted_file in baseline_files - current_files:
        baseline_row = baseline[baseline["File Name"] == deleted_file].iloc[0]
        results.append({
            "File Name": deleted_file,
            "Path": baseline_row["Path"],
            "Size (Bytes)": baseline_row.get("Size (Bytes)", 0),
            "Created Time": baseline_row["Created Time"],
            "Modified Time": baseline_row["Modified Time"],
            "Created Timestamp": baseline_row.get("Created Timestamp", 0),
            "Modified Timestamp": baseline_row.get("Modified Timestamp", 0),
            "Status": "Deleted File",
            "Risk Level": "High"
        })
    
    return pd.DataFrame(results)

def save_evidence_report(analysis_df):
    """Save evidence report to CSV."""
    try:
        if analysis_df is None or analysis_df.empty:
            return False
        
        report_df = analysis_df[[
            "File Name", "Path", "Created Time", "Modified Time", "Status", "Risk Level"
        ]].copy()
        report_df["Report Generated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_df.to_csv(EVIDENCE_FILE, index=False)
        return True
    except Exception:
        return False

def get_alerts(analysis_df):
    """Extract suspicious activities."""
    try:
        if analysis_df is None or analysis_df.empty:
            return pd.DataFrame()
        
        suspicious = analysis_df[
            (analysis_df["Status"] != "Normal") & 
            (analysis_df["Status"] != "New Scan")
        ].copy()
        
        # Safe sort - return empty if no columns
        if suspicious.empty:
            return suspicious
        
        return suspicious.sort_values("Risk Level", ascending=False)
    except Exception:
        return pd.DataFrame()

def add_customer(name, email):
    """Add customer to customers.csv in retail_files."""
    try:
        ensure_retail_files_dir()
        
        if CUSTOMERS_FILE.exists():
            try:
                df = pd.read_csv(CUSTOMERS_FILE)
                # Handle empty CSV
                if df.empty:
                    df = pd.DataFrame(columns=["Name", "Email", "Date Added"])
            except:
                df = pd.DataFrame(columns=["Name", "Email", "Date Added"])
        else:
            df = pd.DataFrame(columns=["Name", "Email", "Date Added"])
        
        new_customer = {
            "Name": name,
            "Email": email,
            "Date Added": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        df = pd.concat([df, pd.DataFrame([new_customer])], ignore_index=True)
        df.to_csv(CUSTOMERS_FILE, index=False)
        return True
    except Exception as e:
        st.error(f"Error adding customer: {str(e)}")
        return False

def update_product_price(product_name, new_price):
    """Update product price in products.json - FIXED to handle file properly."""
    try:
        ensure_retail_files_dir()
        
        # Initialize as empty dict if file doesn't exist
        products = {}
        
        if PRODUCTS_FILE.exists():
            try:
                with open(PRODUCTS_FILE, 'r') as f:
                    content = f.read().strip()
                    if content:  # Only load if file has content
                        products = json.load(open(PRODUCTS_FILE, 'r'))
                    else:
                        products = {}
            except (json.JSONDecodeError, ValueError):
                # File exists but is corrupted or empty - reset
                products = {}
        
        # Ensure products is a dictionary
        if not isinstance(products, dict):
            products = {}
        
        # Update or create product entry
        products[product_name] = {
            "Price": float(new_price),
            "Last Updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Write back to file
        with open(PRODUCTS_FILE, 'w') as f:
            json.dump(products, f, indent=2)
        
        return True
    except Exception as e:
        st.error(f"Error updating product: {str(e)}")
        return False

def prepare_tampering_timeline(analysis_df):
    """
    Prepare tampering timeline data from analysis dataframe.
    Groups tampering events by time for visualization.
    """
    try:
        if analysis_df is None or analysis_df.empty:
            return None
        
        # Create a copy to avoid modifying original
        timeline_df = analysis_df.copy()
        
        # Safely convert Modified Time to datetime
        timeline_df["Modified"] = pd.to_datetime(
            timeline_df["Modified Time"], 
            format="%Y-%m-%d %H:%M:%S",
            errors="coerce"
        )
        
        # Drop rows with invalid datetime
        timeline_df = timeline_df.dropna(subset=["Modified"])
        
        # Filter only changes (exclude Normal status)
        changes_df = timeline_df[timeline_df["Status"] != "Normal"].copy()
        
        if changes_df.empty:
            return None
        
        # Group by time (hour:minute format)
        timeline_grouped = changes_df.groupby(
            changes_df["Modified"].dt.strftime("%H:%M")
        ).size()
        
        # Convert to dataframe
        timeline_data = timeline_grouped.reset_index()
        timeline_data.columns = ["Time", "Change Count"]
        timeline_data = timeline_data.set_index("Time")
        
        return timeline_data
    
    except Exception as e:
        return None

def create_baseline_comparison(current_scan, baseline):
    """
    Create detailed comparison between baseline and current scan.
    Matches files by Path to detect modifications, new, and deleted files.
    """
    if baseline is None or baseline.empty:
        return None
    
    if current_scan is None or current_scan.empty:
        return None
    
    # Get file paths from both scans
    baseline_files = {}
    for _, row in baseline.iterrows():
        baseline_files[row["Path"]] = {
            "File Name": row["File Name"],
            "Modified Time": row["Modified Time"]
        }
    
    current_files = {}
    for _, row in current_scan.iterrows():
        current_files[row["Path"]] = {
            "File Name": row["File Name"],
            "Modified Time": row["Modified Time"]
        }
    
    results = []
    
    # Process files that exist in current scan
    for path, current_data in current_files.items():
        file_name = current_data["File Name"]
        current_modified = current_data["Modified Time"]
        
        if path in baseline_files:
            # File exists in both - check if modified
            baseline_modified = baseline_files[path]["Modified Time"]
            
            if current_modified == baseline_modified:
                change_type = "🟢 Unchanged"
            else:
                change_type = "🟠 Modified"
        else:
            # New file
            baseline_modified = "N/A"
            change_type = "🔵 New"
        
        results.append({
            "File Name": file_name,
            "Path": path,
            "Baseline Modified": baseline_modified,
            "Current Modified": current_modified,
            "Change Type": change_type
        })
    
    # Process deleted files (exist in baseline but not in current)
    for path, baseline_data in baseline_files.items():
        if path not in current_files:
            results.append({
                "File Name": baseline_data["File Name"],
                "Path": path,
                "Baseline Modified": baseline_data["Modified Time"],
                "Current Modified": "N/A",
                "Change Type": "🔴 Deleted"
            })
    
    if not results:
        return None
    
    return pd.DataFrame(results)

def load_customers_data():
    """Load customer data from retail_files/customers.csv"""
    try:
        if CUSTOMERS_FILE.exists():
            df = pd.read_csv(CUSTOMERS_FILE)
            if not df.empty:
                return df
    except Exception:
        pass
    return pd.DataFrame(columns=["Name", "Email", "Date Added"])

def load_products_data():
    """Load product data from retail_files/products.json"""
    try:
        if PRODUCTS_FILE.exists():
            with open(PRODUCTS_FILE, 'r') as f:
                content = f.read().strip()
                if content:
                    products = json.load(open(PRODUCTS_FILE, 'r'))
                    if isinstance(products, dict):
                        return pd.DataFrame([
                            {"Product Name": name, "Price": data.get("Price", 0), "Last Updated": data.get("Last Updated", "")}
                            for name, data in products.items()
                        ])
    except Exception:
        pass
    return pd.DataFrame(columns=["Product Name", "Price", "Last Updated"])

def delete_customer(index, df):
    """Delete customer from dataframe and save to file"""
    try:
        df.drop(index, inplace=True)
        df.reset_index(drop=True, inplace=True)
        df.to_csv(CUSTOMERS_FILE, index=False)
        return True
    except Exception:
        return False

def delete_product(product_name):
    """Delete product from products.json"""
    try:
        if PRODUCTS_FILE.exists():
            with open(PRODUCTS_FILE, 'r') as f:
                products = json.load(f)
            if product_name in products:
                del products[product_name]
                with open(PRODUCTS_FILE, 'w') as f:
                    json.dump(products, f, indent=2)
                return True
    except Exception:
        pass
    return False

# ============================================================================
# STREAMLIT APP LAYOUT
# ============================================================================

st.title("🔍 Retail Digital Forensics System")
st.markdown("### Monitor and Detect File Tampering in Retail Environment")
st.markdown("---")

# ============================================================================
# SECTION 1: SCAN & BASELINE CONTROLS
# ============================================================================

st.header("📊 File Integrity Scanning")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("🔄 Scan Retail Files", use_container_width=True):
        st.session_state.current_scan = scan_retail_files()
        st.success("✅ Scan completed!")

with col2:
    if st.button("📌 Set Baseline", use_container_width=True):
        if st.session_state.current_scan is None or (isinstance(st.session_state.current_scan, pd.DataFrame) and st.session_state.current_scan.empty):
            st.error("❌ No scan data. Please scan first!")
        else:
            if save_baseline(st.session_state.current_scan):
                st.success("✅ Baseline saved!")

with col3:
    if st.button("📥 Load Baseline", use_container_width=True):
        baseline = load_baseline()
        if baseline is not None:
            st.session_state.baseline_data = baseline
            st.success("✅ Baseline loaded!")
        else:
            st.info("ℹ️ No baseline exists yet")

st.markdown("---")

# ============================================================================
# SECTION 2: FILE INTEGRITY TABLE
# ============================================================================

st.header("📋 File Integrity Analysis")

if st.session_state.current_scan is None or (isinstance(st.session_state.current_scan, pd.DataFrame) and st.session_state.current_scan.empty):
    st.info("👉 Click 'Scan Retail Files' to start the analysis")
else:
    # Perform comparison with baseline if available - SAFE CHECK
    baseline = st.session_state.baseline_data
    if baseline is None:
        baseline = load_baseline()
    
    analysis_df = compare_with_baseline(st.session_state.current_scan, baseline)
    
    st.session_state.current_scan = analysis_df
    
    # Save evidence report
    save_evidence_report(analysis_df)
    
    # Display file integrity table with color coding using custom function
    display_df = analysis_df[[
        "File Name", "Size (Bytes)", "Created Time", "Modified Time", "Status", "Risk Level"
    ]].copy()
    
    st.subheader(f"✅ Total Files Found: {len(display_df)}")
    
    # Create color-coded display using Streamlit's native features
    for idx, row in display_df.iterrows():
        risk = row["Risk Level"]
        status = row["Status"]
        
        if risk == "High":
            color_code = "🔴"
        elif risk == "Medium":
            color_code = "🟡"
        else:
            color_code = "🟢"
        
        # Add color indicator to display
        display_df.at[idx, "Status"] = f"{color_code} {status}"
    
    # Display dataframe without problematic styling
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    
    # Summary metrics
    st.markdown("---")
    st.subheader("📈 Summary Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Files", len(display_df))
    
    with col2:
        normal_count = len(analysis_df[analysis_df["Status"] == "Normal"])
        st.metric("Normal Files", normal_count)
    
    with col3:
        suspicious_count = len(analysis_df[analysis_df["Risk Level"] == "High"])
        st.metric("🔴 High Risk Files", suspicious_count)
    
    with col4:
        total_size = analysis_df["Size (Bytes)"].sum()
        size_str = f"{total_size / 1024:.2f} KB" if total_size < 1024*1024 else f"{total_size / (1024*1024):.2f} MB"
        st.metric("Total Size", size_str)
    
    # ========================================================================
    # SECTION 3: BASELINE VS CURRENT ANALYSIS
    # ========================================================================
    
    st.markdown("---")
    st.header("📊 Baseline vs Current Analysis")
    
    baseline = st.session_state.baseline_data
    if baseline is None:
        baseline = load_baseline()
    
    if baseline is None or baseline.empty:
        st.info("ℹ️ Set a baseline first to compare with current scan. Click '📌 Set Baseline' above.")
    else:
        # Create comparison dataframe
        comparison_df = create_baseline_comparison(st.session_state.current_scan, baseline)
        
        if comparison_df is not None and not comparison_df.empty:
            # Extract change type counts (remove emoji for counting)
            def get_clean_change_type(change_str):
                if "Unchanged" in change_str:
                    return "Unchanged"
                elif "Modified" in change_str:
                    return "Modified"
                elif "New" in change_str:
                    return "New"
                elif "Deleted" in change_str:
                    return "Deleted"
                return "Unknown"
            
            change_counts = comparison_df["Change Type"].apply(get_clean_change_type).value_counts().to_dict()
            
            # Display summary cards
            st.subheader("📈 Comparison Summary")
            col1, col2, col3, col4, col5 = st.columns(5)
            
            with col1:
                st.metric("Total Files", len(comparison_df))
            
            with col2:
                unchanged = change_counts.get("Unchanged", 0)
                st.metric("🟢 Unchanged", unchanged)
            
            with col3:
                modified = change_counts.get("Modified", 0)
                st.metric("🟠 Modified", modified)
            
            with col4:
                new = change_counts.get("New", 0)
                st.metric("🔵 New", new)
            
            with col5:
                deleted = change_counts.get("Deleted", 0)
                st.metric("🔴 Deleted", deleted)
            
            # Display timeline chart
            if not all(count == 0 for count in change_counts.values()):
                st.subheader("📉 Change Distribution")
                chart_data = pd.DataFrame({
                    "Change Type": list(change_counts.keys()),
                    "Count": list(change_counts.values())
                })
                st.bar_chart(chart_data.set_index("Change Type"))
            
            # Display detailed comparison table
            st.markdown("---")
            st.subheader("📋 Detailed Comparison Table")
            
            # Create display dataframe
            display_comparison = comparison_df[[
                "File Name", "Path", "Baseline Modified", "Current Modified", "Change Type"
            ]].copy()
            
            # Shorten path display for readability
            display_comparison["Path"] = display_comparison["Path"].apply(
                lambda x: x.split("\\")[-1] if "\\" in x else x.split("/")[-1]
            )
            
            st.dataframe(display_comparison, use_container_width=True, hide_index=True)
            
            # Download comparison report
            st.markdown("---")
            st.subheader("📥 Download Comparison Report")
            
            comparison_csv = comparison_df.to_csv(index=False)
            st.download_button(
                label="📄 Download Baseline vs Current Comparison (CSV)",
                data=comparison_csv,
                file_name=f"baseline_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
    
    # ========================================================================
    # SECTION 4: ALERTS
    # ========================================================================
    
    st.markdown("---")
    st.header("⚠️ Security Alerts")
    
    alerts = get_alerts(analysis_df)
    
    if alerts.empty:
        st.success("✅ No suspicious activity detected!")
    else:
        st.warning(f"🚨 {len(alerts)} Suspicious File(s) Detected!")
        
        alert_display = alerts[[
            "File Name", "Status", "Risk Level", "Modified Time"
        ]].copy()
        
        # Add color indicators
        for idx, row in alert_display.iterrows():
            risk = row["Risk Level"]
            status = row["Status"]
            
            if risk == "High":
                color_code = "🔴"
            else:
                color_code = "🟡"
            
            alert_display.at[idx, "Status"] = f"{color_code} {status}"
        
        st.dataframe(alert_display, use_container_width=True, hide_index=True)
        
        # Alert details
        st.subheader("📝 Alert Details")
        for idx, alert in alerts.iterrows():
            with st.expander(f"🔴 {alert['File Name']} - {alert['Status']}"):
                st.write(f"**Path:** {alert['Path']}")
                st.write(f"**Status:** {alert['Status']}")
                st.write(f"**Risk Level:** {alert['Risk Level']}")
                st.write(f"**Modified Time:** {alert['Modified Time']}")
                st.write(f"**Size:** {alert['Size (Bytes)']} bytes")
    
    # ========================================================================
    # SECTION 4.5: TAMPERING TIMELINE GRAPH
    # ========================================================================
    
    st.markdown("---")
    st.header("📈 Tampering Timeline")
    
    timeline_data = prepare_tampering_timeline(analysis_df)
    
    if timeline_data is None or timeline_data.empty:
        st.info("ℹ️ No tampering activity detected. Timeline is empty.")
    else:
        # Display both line and bar charts for comprehensive view
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Timeline - Line Chart")
            st.line_chart(timeline_data)
        
        with col2:
            st.subheader("📊 Timeline - Bar Chart")
            st.bar_chart(timeline_data)
        
        # Summary statistics for timeline
        st.subheader("📋 Timeline Statistics")
        timeline_col1, timeline_col2, timeline_col3 = st.columns(3)
        
        with timeline_col1:
            total_events = int(timeline_data["Change Count"].sum())
            st.metric("Total Tampering Events", total_events)
        
        with timeline_col2:
            peak_time = timeline_data["Change Count"].idxmax()
            peak_count = int(timeline_data["Change Count"].max())
            st.metric(f"Peak Activity Time ({peak_time})", peak_count)
        
        with timeline_col3:
            avg_events = float(timeline_data["Change Count"].mean())
            st.metric("Average Events per Time", f"{avg_events:.1f}")
    
    # ========================================================================
    # SECTION 5: EVIDENCE REPORT DOWNLOAD
    # ========================================================================
    
    st.markdown("---")
    st.subheader("📥 Download Evidence Report")
    
    evidence_df = analysis_df[[
        "File Name", "Path", "Created Time", "Modified Time", "Status", "Risk Level"
    ]].copy()
    
    csv_data = evidence_df.to_csv(index=False)
    st.download_button(
        label="📄 Download Evidence Report (CSV)",
        data=csv_data,
        file_name=f"forensics_evidence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True
    )

st.markdown("---")

# ============================================================================
# SECTION 6: RETAIL DATA PANEL (EDIT & DELETE)
# ============================================================================

st.header("🛒 Retail Data Panel")
st.markdown("*View, Edit, and Delete Real Retail Data*")

tab_cust, tab_prod = st.tabs(["👥 Customers", "💰 Products"])

# CUSTOMERS TAB
with tab_cust:
    st.subheader("📋 Customer List")
    customers_df = load_customers_data()
    
    if customers_df.empty:
        st.info("📌 No customers found. Add customers via 'Retail Simulation Panel' below.")
    else:
        # Display each customer with edit/delete buttons
        for idx, row in customers_df.iterrows():
            col1, col2, col3, col4, col5 = st.columns([2.5, 2.5, 0.8, 0.8, 0.4])
            
            with col1:
                st.write(f"**{row['Name']}**")
            with col2:
                st.write(f"📧 {row['Email']}")
            with col3:
                if st.button("✏️ Edit", key=f"edit_cust_{idx}", use_container_width=True):
                    st.session_state.edit_customer_index = idx
                    st.rerun()
            with col4:
                if st.button("🗑️ Delete", key=f"delete_cust_{idx}", use_container_width=True):
                    if delete_customer(idx, customers_df):
                        st.warning(f"❌ Customer '{row['Name']}' deleted → Potential tampering detected!")
                        st.info("💡 Run a forensic scan to detect this change.")
                        st.rerun()
                    else:
                        st.error("Failed to delete customer")
            with col5:
                st.write("")
        
        # Edit form for customer
        if st.session_state.edit_customer_index is not None:
            idx = st.session_state.edit_customer_index
            if idx < len(customers_df):
                edit_row = customers_df.loc[idx]
                
                st.markdown("---")
                st.subheader(f"✏️ Edit Customer: {edit_row['Name']}")
                
                edit_col1, edit_col2 = st.columns(2)
                
                with edit_col1:
                    new_name = st.text_input("Name", value=edit_row["Name"], key="edit_cust_name")
                
                with edit_col2:
                    new_email = st.text_input("Email", value=edit_row["Email"], key="edit_cust_email")
                
                btn_col1, btn_col2 = st.columns(2)
                
                with btn_col1:
                    if st.button("💾 Save Changes", key="save_cust_edit", use_container_width=True):
                        customers_df.at[idx, "Name"] = new_name
                        customers_df.at[idx, "Email"] = new_email
                        customers_df.to_csv(CUSTOMERS_FILE, index=False)
                        st.session_state.edit_customer_index = None
                        st.error("⚠️ Customer data modified → Potential tampering detected!")
                        st.info("💡 Run a forensic scan to detect this change.")
                        st.rerun()
                
                with btn_col2:
                    if st.button("❌ Cancel", key="cancel_cust_edit", use_container_width=True):
                        st.session_state.edit_customer_index = None
                        st.rerun()

# PRODUCTS TAB
with tab_prod:
    st.subheader("📋 Product List")
    products_df = load_products_data()
    
    if products_df.empty:
        st.info("📌 No products found. Add products via 'Retail Simulation Panel' below.")
    else:
        # Display each product with edit/delete buttons
        for idx, row in products_df.iterrows():
            col1, col2, col3, col4, col5 = st.columns([2.5, 1.5, 0.8, 0.8, 0.4])
            
            with col1:
                st.write(f"**{row['Product Name']}**")
            with col2:
                st.write(f"💵 ${row['Price']:.2f}")
            with col3:
                if st.button("✏️ Edit", key=f"edit_prod_{idx}", use_container_width=True):
                    st.session_state.edit_product_index = idx
                    st.rerun()
            with col4:
                if st.button("🗑️ Delete", key=f"delete_prod_{idx}", use_container_width=True):
                    if delete_product(row["Product Name"]):
                        st.warning(f"❌ Product '{row['Product Name']}' deleted → Potential tampering detected!")
                        st.info("💡 Run a forensic scan to detect this change.")
                        st.rerun()
                    else:
                        st.error("Failed to delete product")
            with col5:
                st.write("")
        
        # Edit form for product
        if st.session_state.edit_product_index is not None:
            idx = st.session_state.edit_product_index
            if idx < len(products_df):
                edit_row = products_df.loc[idx]
                
                st.markdown("---")
                st.subheader(f"✏️ Edit Product: {edit_row['Product Name']}")
                
                edit_col1, edit_col2 = st.columns(2)
                
                with edit_col1:
                    new_product_name = st.text_input("Product Name", value=edit_row["Product Name"], key="edit_prod_name")
                
                with edit_col2:
                    new_price = st.number_input("Price ($)", value=float(edit_row["Price"]), step=0.01, key="edit_prod_price")
                
                btn_col1, btn_col2 = st.columns(2)
                
                with btn_col1:
                    if st.button("💾 Save Changes", key="save_prod_edit", use_container_width=True):
                        try:
                            # Load current products
                            with open(PRODUCTS_FILE, 'r') as f:
                                products = json.load(f)
                            
                            # Remove old entry if name changed
                            old_name = edit_row["Product Name"]
                            if old_name != new_product_name and old_name in products:
                                del products[old_name]
                            
                            # Add new entry
                            products[new_product_name] = {
                                "Price": float(new_price),
                                "Last Updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                            
                            # Write back to file
                            with open(PRODUCTS_FILE, 'w') as f:
                                json.dump(products, f, indent=2)
                            
                            st.session_state.edit_product_index = None
                            st.error("⚠️ Product data modified → Potential tampering detected!")
                            st.info("💡 Run a forensic scan to detect this change.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error updating product: {str(e)}")
                
                with btn_col2:
                    if st.button("❌ Cancel", key="cancel_prod_edit", use_container_width=True):
                        st.session_state.edit_product_index = None
                        st.rerun()

st.markdown("---")

# ============================================================================
# SECTION 7: RETAIL SIMULATION PANEL
# ============================================================================

st.header("🏪 Retail Simulation Panel")
st.markdown("*Simulate retail operations to test tampering detection*")

tab1, tab2 = st.tabs(["👥 Add Customer", "💰 Update Product Price"])

with tab1:
    st.subheader("Add New Customer")
    col1, col2 = st.columns(2)
    
    with col1:
        customer_name = st.text_input("Customer Name", placeholder="John Doe", key="cust_name")
    
    with col2:
        customer_email = st.text_input("Customer Email", placeholder="john@example.com", key="cust_email")
    
    if st.button("✅ Add Customer", use_container_width=True, key="btn_add_cust"):
        if customer_name and customer_email:
            if add_customer(customer_name, customer_email):
                st.success(f"✅ Customer '{customer_name}' added successfully!")
                st.info("💡 The customers.csv file has been modified. Scan again to detect the change!")
            else:
                st.error("❌ Failed to add customer")
        else:
            st.warning("⚠️ Please fill in all fields")

with tab2:
    st.subheader("Update Product Price")
    col1, col2 = st.columns(2)
    
    with col1:
        product_name = st.text_input("Product Name", placeholder="Laptop", key="prod_name")
    
    with col2:
        product_price = st.number_input("New Price ($)", min_value=0.0, step=0.01, key="prod_price")
    
    if st.button("💾 Update Product", use_container_width=True, key="btn_upd_prod"):
        if product_name:
            if update_product_price(product_name, product_price):
                st.success(f"✅ Product '{product_name}' price updated to ${product_price}!")
                st.info("💡 The products.json file has been modified. Scan again to detect the change!")
            else:
                st.error("❌ Failed to update product")
        else:
            st.warning("⚠️ Please enter a product name")

st.markdown("---")

# ============================================================================
# SECTION 8: SYSTEM STATUS
# ============================================================================

st.header("🔧 System Status")

col1, col2, col3 = st.columns(3)

with col1:
    if RETAIL_FILES_DIR.exists():
        file_count = len(list(RETAIL_FILES_DIR.glob("*")))
        st.metric("Files in retail_files", file_count)
    else:
        st.metric("Files in retail_files", 0)

with col2:
    if BASELINE_FILE.exists():
        st.metric("Baseline Status", "✅ Exists")
    else:
        st.metric("Baseline Status", "❌ Not Set")

with col3:
    if EVIDENCE_FILE.exists():
        st.metric("Evidence Report", "✅ Generated")
    else:
        st.metric("Evidence Report", "❌ Not Generated")

st.markdown("---")

# Footer
st.caption(
    "🔍 Retail Digital Forensics System v1.0 | "
    f"Working Hours: {WORKING_HOURS_START}:00 AM - {WORKING_HOURS_END}:00 PM | "
    f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)
