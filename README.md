# Cyber Threat Intelligence System - HackNex 2026

## 🎯 What This Does
Detects multi-stage cyberattacks by analyzing security logs and correlating events across users, devices, and IP addresses.

### Example Attack Detected:
1. **Stage 1:** User logs in from unusual IP (103.45.67.89 from China)
2. **Stage 2:** Accesses sensitive financial files (never accessed before)
3. **Stage 3:** Copies files to USB device (data theft)

**Result:** 🚨 ATTACK DETECTED - Risk 95%

---

## 🚀 How to Use

### Step 1: Install Python Libraries
```bash
pip install pandas streamlit networkx
```

### Step 2: Run the Web Dashboard
```bash
python -m streamlit run app.py
```

### Step 3: Upload Logs
- Opens in browser automatically (http://localhost:8501)
- Click "Choose CSV file" in sidebar
- Upload `sample_logs.csv`
- Click "Analyze for Attacks"

---

## 📁 Files Included

- **app.py** - Web dashboard (Streamlit)
- **detect_attacks.py** - Attack detection logic
- **sample_logs.csv** - Example security logs with attack scenario

---

## 🛠️ Technologies Used
- Python 3.9+
- Pandas (data analysis)
- Streamlit (web interface)
- NetworkX (graph analysis)

---

## 📊 How It Works

### Attack Detection Logic:
1. Reads security logs (CSV format)
2. Groups events by user
3. Looks for attack patterns:
   - Unusual login (from new IP, high risk)
   - Access to sensitive resources
   - Data exfiltration (copy to USB)
4. If all 3 stages found → ATTACK DETECTED
5. Displays timeline with evidence + recommendations

### What Gets Flagged:
- ✅ Login from unusual location
- ✅ Access to files user never touched
- ✅ Copy to external storage
- ✅ Complete attack chain with timeline

---

## 💡 Example Output

**Input:** CSV with security log events

**Output:**
