from flask import Flask, jsonify, request
import mysql.connector
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Database Connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Niranju+6",
        database="cve_db"
    )

# Function to format dates as "DD MMM YYYY"
def format_date(raw_date):
    if raw_date:
        return raw_date.strftime("%d %b %Y")
    return None

# Function to format CVE response
def format_cve_columns(cve):
    if cve:
        cve['source_identifier'] = cve.get('source_identifier')
        cve['vuln_status'] = cve.get('vuln_status')
    return cve

# Route: Get All CVEs with Filters, Sorting, and Pagination
@app.route('/cves', methods=['GET'])
def get_cves():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    query = "SELECT * FROM cve_data WHERE 1=1"
    params = []

    # Filtering
    cve_id = request.args.get('cve_id')
    if cve_id:
        query += " AND id = %s"
        params.append(cve_id)

    min_score = request.args.get('min_score')
    if min_score:
        query += " AND base_score >= %s"
        params.append(float(min_score))

    max_score = request.args.get('max_score')
    if max_score:
        query += " AND base_score <= %s"
        params.append(float(max_score))

    year = request.args.get('year')
    if year:
        query += " AND published_date LIKE %s"
        params.append(year + "%")

    search = request.args.get('search')
    if search:
        query += " AND (description LIKE %s OR id LIKE %s)"
        params.append('%' + search + '%')
        params.append('%' + search + '%')

    vuln_status = request.args.get('status')
    if vuln_status:
        query += " AND vuln_status = %s"
        params.append(vuln_status)

    source_identifier = request.args.get('source_identifier')
    if source_identifier:
        query += " AND source_identifier = %s"
        params.append(source_identifier)

    # Sorting
    sort_by = request.args.get('sort_by', 'published_date')
    sort_order = request.args.get('sort_order', 'ASC')
    query += f" ORDER BY {sort_by} {sort_order}"

    # Pagination
    limit = int(request.args.get('limit', 10))
    offset = int(request.args.get('offset', 0))
    query += " LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    cursor.execute(query, params)
    cves = cursor.fetchall()

    # Get total record count
    cursor.execute("SELECT COUNT(*) AS total FROM cve_data WHERE 1=1")
    total_records = cursor.fetchone()['total']

    # Format data
    for cve in cves:
        cve['published_date'] = format_date(cve['published_date'])
        cve['last_modified_date'] = format_date(cve['last_modified_date'])
        cve = format_cve_columns(cve)

    conn.close()

    return jsonify({
        'total_records': total_records,
        'current_page': offset // limit + 1,
        'total_pages': (total_records // limit) + (1 if total_records % limit != 0 else 0),
        'page_range': f'{(offset // limit) * limit + 1} to {min((offset // limit + 1) * limit, total_records)}',
        'cves': cves
    })

# Route: Get a Single CVE by ID with Additional Details
@app.route('/cve/<string:cve_id>', methods=['GET'])
def get_cve_page(cve_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Query the database for the CVE details by ID
    cursor.execute("SELECT * FROM cve_data WHERE id = %s", (cve_id,))
    cve = cursor.fetchone()

    conn.close()

    if cve:
        # Format the dates and columns before returning
        cve['published_date'] = format_date(cve['published_date'])
        cve['last_modified_date'] = format_date(cve['last_modified_date'])
        
        cve = format_cve_columns(cve)  # Ensure columns are correctly included
        
        # Adding necessary CVE metrics
        cve['access_vector'] = cve.get('access_vector')
        cve['severity']=cve.get('severity')
        cve['access_complexity'] = cve.get('access_complexity')
        cve['authentication'] = cve.get('authentication')
        cve['confidentiality_impact'] = cve.get('confidentiality_impact')
        cve['integrity_impact'] = cve.get('integrity_impact')
        cve['availability_impact'] = cve.get('availability_impact')
        cve['exploitability_score'] = cve.get('exploitability_score')
        cve['impact_score'] = cve.get('impact_score')
        
        return jsonify(cve)
    else:
        return jsonify({"error": "CVE not found"}), 404



if __name__ == '__main__':
    app.run(debug=True)
