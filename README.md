# Securin-Intern-Assignment

# CVE Data Management and Display System

This repository contains the solution to manage and display security vulnerabilities (CVEs) from the National Vulnerability Database (NVD) using Python, SQL, and Flask.

## Problem Statement

The goal is to fetch CVE data from the NVD API, store it in a database, and provide an accessible backend and frontend for users to search and filter this data based on different criteria.

## Logical Approach

### Step 1: Get CVE Data from the API
- **Data Fetching**: Fetch CVE data in chunks using the NVD CVE API with pagination to avoid large data loads.
- **Data Storage**: Store the fetched data in a relational SQL database.
- **Data Cleaning**: Clean the data by removing duplicates, filtering unnecessary information, and ensuring correct formatting before storing it.

### Step 2: Keep the Data Fresh
- **Full Refresh**: Occasionally, the entire dataset will be refreshed by clearing the database and pulling all new data.
- **Incremental Updates**: To keep the database up-to-date with minimal impact, only fetch CVEs that have been modified or added since the last update.
- **Automated Updates**: Use a Python scheduler to automate the process of fetching updates regularly.

### Step 3: Build the Backend (Flask API)
With the data in the database, I will create the following APIs using Flask and SQL:
- **Get Specific CVE**: Fetch details of a particular CVE by its ID (e.g., `/api/cves/CVE-2023-12345`).
- **Filter by Year**: Retrieve CVEs from a particular year (e.g., `/api/cves?year=2023`).
- **Filter by Severity**: Allow users to filter CVEs by their severity score (e.g., `/api/cves?min_score=7&max_score=10`).
- **Recent Changes**: Show recently modified CVEs (e.g., `/api/cves?last_modified=30`).
- **Pagination**: Handle pagination to avoid overwhelming the user with large datasets.

### Step 4: Build the Frontend (UI with JavaScript, HTML, and CSS)
The user interface will provide a dynamic webpage to display CVE data:
- **CVE List Page**: Display CVE data in a table with:
  - Total record count.
  - Option for users to choose the number of records per page (10, 50, or 100).
  - Dynamic loading of new data when users select a different page.
  - JavaScript will be used to call the Flask APIs and update the table without reloading the page.

### Step 5: Click a Row → Go to Details Page
When a user clicks a row in the table, they will be redirected to a detailed CVE page (e.g., `/cves/CVE-2023-12345`):
- **Detailed View**: Make an API call to retrieve the full details of the selected CVE and display all its information in a well-organized and easy-to-read format.

## Code Explanation
- **Backend**: Flask API with routes to fetch CVE data, filter, and handle pagination.
- **Database**: SQL used for storing and managing CVE data.
- **Scheduler**: Python-based scheduling for regular data updates.

## Conclusion
This project provides an efficient system to fetch, store, update, and display CVE data using Python, SQL, and Flask. The system is scalable and can handle large amounts of CVE data while keeping it fresh and accessible for users.
