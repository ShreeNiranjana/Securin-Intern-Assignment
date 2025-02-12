import requests
import mysql.connector


db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Niranju+6",
    database="cve_db"
)
cursor = db.cursor()


cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve_criteria_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        cve_id VARCHAR(50),
        criteria TEXT,
        criteria_id VARCHAR(100),
        vuln_status VARCHAR(50)
    )
""")


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
        break  

    all_data.extend(vulnerabilities)
    start_index += results_per_page

    if len(all_data) >= 2000:
        break 


insert_cve_query = """
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


insert_criteria_query = """
    INSERT INTO cve_criteria_data 
    (cve_id, criteria, criteria_id, vuln_status)
    VALUES (%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE 
        criteria = VALUES(criteria), 
        vuln_status = VALUES(vuln_status)
"""

for item in all_data:
    cve = item["cve"]
    cve_id = cve["id"]
    description = cve.get("descriptions", [{}])[0].get("value", "")
    source_identifier = cve.get("sourceIdentifier", "")
    vuln_status = cve.get("vulnStatus", "")


    cvss_v3 = cve.get("metrics", {}).get("cvssMetricV3", [{}])[0]
    cvss_v2 = cve.get("metrics", {}).get("cvssMetricV2", [{}])[0]

    if "cvssData" in cvss_v3:
        cvss_data = cvss_v3["cvssData"]
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        vector_string = cvss_data.get("vectorString")
        access_vector = cvss_data.get("attackVector")
        access_complexity = cvss_data.get("attackComplexity")
        authentication = cvss_data.get("privilegesRequired")
        confidentiality_impact = cvss_data.get("confidentialityImpact")
        integrity_impact = cvss_data.get("integrityImpact")
        availability_impact = cvss_data.get("availabilityImpact")
        exploitability_score = cvss_v3.get("exploitabilityScore")
        impact_score = cvss_v3.get("impactScore")
    elif "cvssData" in cvss_v2:
        cvss_data = cvss_v2["cvssData"]
        base_score = cvss_data.get("baseScore")
        severity = cvss_v2.get("baseSeverity")
        vector_string = cvss_data.get("vectorString")
        access_vector = cvss_data.get("accessVector")
        access_complexity = cvss_data.get("accessComplexity")
        authentication = cvss_data.get("authentication")
        confidentiality_impact = cvss_data.get("confidentialityImpact")
        integrity_impact = cvss_data.get("integrityImpact")
        availability_impact = cvss_data.get("availabilityImpact")
        exploitability_score = cvss_v2.get("exploitabilityScore")
        impact_score = cvss_v2.get("impactScore")
    else:
        base_score = severity = vector_string = access_vector = access_complexity = None
        authentication = confidentiality_impact = integrity_impact = availability_impact = None
        exploitability_score = impact_score = None

    published_date = cve.get("published", "")[:10] if cve.get("published") else None
    last_modified_date = cve.get("lastModified", "")[:10] if cve.get("lastModified") else None

    cursor.execute(insert_cve_query, (
        cve_id, description, base_score, published_date, last_modified_date, source_identifier, vuln_status,
        severity, vector_string, access_vector, access_complexity, authentication, confidentiality_impact,
        integrity_impact, availability_impact, exploitability_score, impact_score
    ))


    configurations = cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe in cpe_matches:
                criteria = cpe.get("criteria", "")
                criteria_id = cpe.get("matchCriteriaId", "")
                cursor.execute(insert_criteria_query, (
                    cve_id, criteria, criteria_id, vuln_status
                ))


db.commit()


cursor.execute("SELECT * FROM cve_data LIMIT 5")
rows = cursor.fetchall()
print("\n✅ CVE Data Successfully Inserted into MySQL Database!")
print("\n🔹 Sample 5 Rows from cve_data Table:")
for row in rows:
    print(row)

cursor.execute("SELECT * FROM cve_criteria_data LIMIT 5")
criteria_rows = cursor.fetchall()
print("\n✅ CVE Criteria Data Successfully Inserted into MySQL Database!")
print("\n🔹 Sample 5 Rows from cve_criteria_data Table:")
for row in criteria_rows:
    print(row)


cursor.close()
db.close()
