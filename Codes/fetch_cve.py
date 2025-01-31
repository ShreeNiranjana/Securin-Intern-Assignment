import requests
import mysql.connector

# Step 1: Connect to MySQL Database
db = mysql.connector.connect(
    host="localhost",
    user="root",  # Change to your MySQL username
    password="Niranju+6",  # Change to your MySQL password
    database="cve_db"
)
cursor = db.cursor()

# Step 2: Fetch CVE data from NVD API with Pagination
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
start_index = 0
results_per_page = 2000
all_data = []

while True:
    api_url = f"{url}?startIndex={start_index}&resultsPerPage={results_per_page}"
    response = requests.get(api_url)
    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        break  # No more data available

    all_data.extend(vulnerabilities)
    start_index += results_per_page

    if len(all_data) >= 2000:
        break  # Stop after fetching 2000 records

# Step 3: Insert Data into MySQL
insert_query = """
    INSERT INTO cve_data 
    (id, description, base_score, published_date, last_modified_date, source_identifier, vuln_status, 
     severity, vector_string, access_vector, access_complexity, authentication, confidentiality_impact, 
     integrity_impact, availability_impact, exploitability_score, impact_score)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE 
        description = VALUES(description), 
        base_score = VALUES(base_score),
        published_date = VALUES(published_date),
        last_modified_date = VALUES(last_modified_date),
        source_identifier = VALUES(source_identifier),
        vuln_status = VALUES(vuln_status),
        severity = VALUES(severity),
        vector_string = VALUES(vector_string),
        access_vector = VALUES(access_vector),
        access_complexity = VALUES(access_complexity),
        authentication = VALUES(authentication),
        confidentiality_impact = VALUES(confidentiality_impact),
        integrity_impact = VALUES(integrity_impact),
        availability_impact = VALUES(availability_impact),
        exploitability_score = VALUES(exploitability_score),
        impact_score = VALUES(impact_score)
"""

for item in all_data:
    cve = item["cve"]
    cve_id = cve["id"]
    description = cve.get("descriptions", [{}])[0].get("value", "")

    # Extracting source identifier and vulnerability status
    source_identifier = cve.get("sourceIdentifier", "")
    vuln_status = cve.get("vulnStatus", "")

    # Extract CVSS Metrics (Prioritize v3, then v2)
    cvss_v3 = cve.get("metrics", {}).get("cvssMetricV3", [{}])[0]
    cvss_v2 = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0]

    if "cvssData" in cvss_v3:
        cvss_data = cvss_v3["cvssData"]
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        vector_string = cvss_data.get("vectorString")
        access_vector = cvss_data.get("attackVector")  # CVSS v3
        access_complexity = cvss_data.get("attackComplexity")  # CVSS v3
        authentication = cvss_data.get("privilegesRequired")  # CVSS v3
        confidentiality_impact = cvss_data.get("confidentialityImpact")
        integrity_impact = cvss_data.get("integrityImpact")
        availability_impact = cvss_data.get("availabilityImpact")
        exploitability_score = cvss_v3.get("exploitabilityScore")
        impact_score = cvss_v3.get("impactScore")
    elif "cvssData" in cvss_v2:
        cvss_data = cvss_v2["cvssData"]
        base_score = cvss_data.get("baseScore")
        severity = cvss_v2.get("baseSeverity")  # Some CVSS v2 records may have it
        vector_string = cvss_data.get("vectorString")
        access_vector = cvss_data.get("accessVector")  # CVSS v2
        access_complexity = cvss_data.get("accessComplexity")  # CVSS v2
        authentication = cvss_data.get("authentication")  # CVSS v2
        confidentiality_impact = cvss_data.get("confidentialityImpact")
        integrity_impact = cvss_data.get("integrityImpact")
        availability_impact = cvss_data.get("availabilityImpact")
        exploitability_score = cvss_v2.get("exploitabilityScore")
        impact_score = cvss_v2.get("impactScore")
    else:
        # Default to None if neither v3 nor v2 is found
        base_score = severity = vector_string = access_vector = access_complexity = None
        authentication = confidentiality_impact = integrity_impact = availability_impact = None
        exploitability_score = impact_score = None

    # Extract only the date part from timestamps
    published_date = cve.get("published", "")[:10] if cve.get("published") else None
    last_modified_date = cve.get("lastModified", "")[:10] if cve.get("lastModified") else None

    cursor.execute(insert_query, (
        cve_id, description, base_score, published_date, last_modified_date, source_identifier, vuln_status,
        severity, vector_string, access_vector, access_complexity, authentication, confidentiality_impact,
        integrity_impact, availability_impact, exploitability_score, impact_score
    ))

# Commit changes to database
db.commit()

# Step 4: Print 5 rows to verify data insertion
cursor.execute("SELECT * FROM cve_data LIMIT 5")
rows = cursor.fetchall()

print("\n✅ CVE Data Successfully Inserted into MySQL Database!")
print("\n🔹 Sample 5 Rows from cve_data Table:")
for row in rows:
    print(row)

# Close DB Connection
cursor.close()
db.close()
