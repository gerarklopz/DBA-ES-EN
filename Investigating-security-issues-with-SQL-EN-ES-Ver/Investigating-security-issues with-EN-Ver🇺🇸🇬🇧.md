# Investigating Security Issues with SQL EN-Ver🇺🇸🇬🇧

## Scenario:
As a security professional in a large organization, we might be tasked with investigating potential incidents related to login attempts and employee machines. To conduct the investigation, we would use the `employees` and `log_in_attempts` tables, applying SQL filters to identify records that could represent vulnerabilities.

---

### 1. Retrieve Failed Login Attempts After Business Hours

**Description:**
We have identified a potential security incident that occurred after business hours. To investigate it, we need to query the `log_in_attempts` table and review login attempts outside of normal business hours. The query should identify all failed attempts that occurred after 6:00 PM. The `login_time` field contains the time of the attempt, and the `success` field has a value of 0 when the attempt fails.

**SQL Query:**
```sql
SELECT *
FROM log_in_attempts
WHERE login_time > "18:00:00" AND success = 0
ORDER BY login_time;
```
**Explanation:**

- **Filter:** The query selects failed login attempts (`success = 0`) that occurred after 6:00 PM.
- **Sort:** The results are sorted by the time of the attempt (`login_time`) to facilitate chronological analysis.

**Example Result:**

| event_id | username | login_date | login_time | country | ip_address | success |
|----------|------------|------------|------------|---------|--------|--------|
| 104 | asundara | 2022-05-11 | 18:38:07 | US | 192.168.96.200 | 0 |
| 20 | tshah | 2022-05-12 | 18:56:36 | MEXICO | 192.168.109.50 | 0 |
| 28 | estrada | 2022-05-09 | 19:28:12 | MEXICO | 192.168.27.57 | 0 |
| 18 | pwashing | 2022-05-11 | 19:28:50 | US | 192.168.66.142 | 0 |
| 199 | yappiah | 2022-05-11 | 19:34:48 | MEXICO | 192.168.44.232 | 0 |
| 69 | wjaffrey | 2022-05-11 | 19:55:15 | USA | 192.168.100.17 | 0 |

### Part 2: Retrieve login attempts on specific dates

**Description:**
Suspicious activity was detected on May 8th and 9th, 2022. We need to review all login attempts made on these specific dates. The `login_date` column contains the date of the attempt.

**SQL Query:**
```sql
SELECT *
FROM log_in_attempts
WHERE login_date BETWEEN "2022-05-08" AND "2022-05-09"
ORDER BY login_time;
```
**Explanation:**

- **Filter:** The query selects login attempts that occurred between May 8 and May 9, 2022.
- **Sort:** Results are sorted by login_time to make it easier to identify patterns.

**Example Result:**

| event_id | username  | login_date | login_time | country | ip_address       | success |
|----------|-----------|------------|------------|---------|------------------|---------|
| 110      | mabadi    | 2022-05-09 | 00:01:54   | USA     | 192.168.90.124   | 1       |
| 117      | bsand     | 2022-05-08 | 00:19:11   | USA     | 192.168.197.187  | 0       |
| 92       | pwashing  | 2022-05-08 | 00:36:12   | US      | 192.168.247.219  | 0       |
| 187      | arusso    | 2022-05-09 | 00:36:26   | MEX     | 192.168.77.137   | 0       |
| 90       | gesparza  | 2022-05-09 | 00:49:05   | CANADA  | 192.168.87.201   | 0       |
| 8        | bisles    | 2022-05-08 | 01:30:17   | US      | 192.168.119.173  | 0       |

### Part 3: Recover Login Attempts from Outside of Mexico

**Description:**
Suspicious activity has been identified, but it has been determined not to be originating from Mexico. We need to review login attempts that were made outside of Mexico. The `country` column contains values ​​like 'MEX' and 'MEXICO' to identify attempts originating from Mexico. In this case, we use the `NOT LIKE` operator to exclude these records.

**SQL query:**
```sql
SELECT *
FROM log_in_attempts
WHERE login_date BETWEEN "2022-05-08" AND "2022-05-09"
AND NOT country LIKE "MEX%"
ORDER BY login_date, login_time;
```
**Explanation:**
**Filter:**
This query excludes login attempts made from Mexico, using the `NOT LIKE "MEX%"` operator, which implicitly excludes parameters like: "MEXICO" also present in records in the `country` column.

**Date Range:**
Filters attempts that occurred between May 8 and 9, 2022.

**Sort:**
Results are sorted by date and time (`login_date` and `login_time`).

**Example Result:**

| event_id | username | login_date | login_time | country  | ip_address     | success |
|----------|----------|------------|------------|----------|----------------|---------|
| 1        | jdoe     | 2022-05-08 | 10:15:30   | USA      | 192.168.96.200 | 0       |
| 2        | rsmith   | 2022-05-08 | 11:45:00   | CANADA   | 192.168.197.50 | 1       |
| 3        | pbrown   | 2022-05-08 | 13:30:20   | BRAZIL   | 192.168.101.100| 0       |
| 4        | jblack   | 2022-05-09 | 09:10:15   | ARGENTINA| 192.168.105.15 | 1       |
| 5        | kgreen   | 2022-05-09 | 14:05:45   | CHILE    | 192.168.77.58  | 0       |

---

### 4. Retrieve employees in the Marketing department in the East building

**Description:**
We need to update the machines of the Marketing department employees located in the East building offices. We need to filter the records in the `employees` table to obtain the relevant information.

**SQL Query:**
```sql
SELECT *
FROM employees
WHERE department = "Marketing"
AND office LIKE "East%";
```
**Explanation:**

**Filter:**
Selects employees belonging to the Marketing department who work in offices in the East building (identified by the 'East' prefix in the `office` column).

**Search Pattern:**
The `LIKE "East%"` operator is used to identify all offices in the East building.

**Example Result:**

| id | name | department | office |
|----|--------------|------------|-----------|
| 1 | Alice Brown | Marketing | East-150 |
| 2 | Bob White | Marketing | East-267 |
| 3 | Carol Black | Marketing | East-320 |
| 4 | Dave Green | Marketing | East-410 |
| 5 | Eve Blue | Marketing | East-590 |

---

### 5. Retrieve employees in the Finance and Sales departments

**Description:**
You need to update the employee machines in the Finance and Sales departments. To do this, you must run a query that filters employees in these departments.

**SQL Query:**

```sql
SELECT *
FROM employees
WHERE department IN ("Finance", "Sales");
```
**Explanation:**

**Filter:**
Employees from the Finance or Sales departments are selected using the `IN` operator.

**Example Result:**

| id | name | department | office |
|----|--------------|------------|-----------|
| 6 | Frank Red | Finance | West-101 |
| 7 | Grace Purple | Finance | West-105 |
| 8 | Hank Green | Sales | West-305 |
| 9 | Isabel Blue | Sales | West-400 |

---

### 6. Employees not in the IT department

**Description:**
Our team needs to perform an additional update on employee machines. Employees in the Information Technology (IT) department have already received this update, but those in other departments still need to be updated. The task is to identify all employees who are not in the IT department.

**SQL Query:**

```sql
SELECT *
FROM employees
WHERE department NOT LIKE "Information Technology";
```
**Explanation:**

**Filter:**
The query selects employees whose `department` field does not contain the value "Information Technology." The `NOT LIKE` operator is used to exclude IT employees.

**Expected Results:**
This query will return all employees belonging to other departments, excluding those in the Information Technology department.

**Example Result:**

| id | name | department | office |
|----|-------------|--------------------|------------|
| 1 | Sam Hill | Finance | HQ-101 |
| 2 | Lucy Lane | Sales | East-102 |
| 3 | Mike Chan | Marketing | West-201 |
| 4 | Peter Wong | Human Resources | HQ-305 |
| 5 | Sara Hall | Customer Support | North-410 |

---

