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

### Practical application of related queries:
For example, a failed login attempt from an unexpected country could be an indication of a brute-force attack, where an attacker attempts to access an account using multiple attempts with different password combinations. By using a `NOT LIKE` query to exclude certain countries or a `BETWEEN` query to filter attempts within a specific time range, we can quickly identify these possible threats.

---
### 7. Identifying Employees and Their Machines (INNER JOIN)
**Description:**
The `INNER JOIN` query will allow us to identify which employees are using which machines. The machines and employees tables will be joined on the common `device_id` column.

**SQL Query:**
```sql
SELECT *
FROM machines
INNER JOIN employees
ON machines.device_id = employees.device_id;
```
**Explanation:**
The `INNER JOIN` query returns a complete list of machine details along with the employee information associated with them.Only records that exist in both tables will be included in the result.

**Expected Result:**

| device_id | machine_name | employee_id | employee_name | department  | office     |
|-----------|--------------|-------------|---------------|-------------|------------|
|    101    |  Laptop A    |      1      |  Alice Brown  |  Marketing  |  East-150  |
|    102    |  Laptop B    |      2      |   Bob White   |  Marketing  |  East-267  |
|    103    |  Desktop C   |      3      |  Carol Black  |  Marketing  |  East-320  |
|    104    |  Desktop D   |      4      |  Dave Green   |   Sales     |  West-400  |
|    105    |  Laptop E    |      5      |   Eve Blue    |  Finance    |  West-101  |
---

### 8. Retrieve All Machine and Employee Data (LEFT JOIN and RIGHT JOIN)
### LEFT JOIN:
**Description:**
We use a `LEFT JOIN` to retrieve all machine records, even if they are not assigned to an employee.
**SQL Query (LEFT JOIN):**
```sql
SELECT *
FROM machines
LEFT JOIN employees
ON machines.device_id = employees.device_id;
```
**Explanation:**
The `LEFT JOIN` returns all records from the machines table and corresponding employee details when available. If no employee is assigned, the corresponding employee columns will have `NULL` values.

**Expected Result (LEFT JOIN):**

device_id | machine_name | employee_id | employee_name | department | office
--------- | ------------ | ----------- | ------------- | ---------- | --------
101       | Laptop A     | 1           | Alice Brown   | Marketing  | East-150
102       | Laptop B     | 2           | Bob White     | Marketing  | East-267
103       | Desktop C    | 3           | Carol Black   | Marketing  | East-320
104       | Desktop D    | 4           | Dave Green    | Sales      | West-400
105       | Laptop E     | 5           | Eve Blue      | Finance    | West-101
106       | Tablet F     | NULL        | NULL          | NULL       | NULL
---
### RIGHT JOIN
**Description:**
We use a `RIGHT JOIN` to return all employee records, even if they don't have an assigned machine.

**SQL Query (RIGHT JOIN):**
```sql
SELECT *
FROM machines
RIGHT JOIN employees
ON machines.device_id = employees.device_id;
```
**Explanation:**
We use a `RIGHT JOIN` to retrieve all employee records, even if they do not have an assigned machine,if any. 
If an employee doesn't have an assigned machine, the `machines` columns will be `NULL`.

**Expected Result (RIGHT JOIN):**
device_id | machine_name | employee_id | employee_name | department | office
--------- | ------------ | ----------- | ------------- | ---------- | --------
101       | Laptop A     | 1           | Alice Brown   | Marketing  | East-150
102       | Laptop B     | 2           | Bob White     | Marketing  | East-267
103       | Desktop C    | 3           | Carol Black   | Marketing  | East-320
104       | Desktop D    | 4           | Dave Green    | Sales      | West-400
105       | Laptop E     | 5           | Eve Blue      | Finance    | West-101
NULL      | NULL         | 6           | Frank Red     | Finance    | West-105
NULL      | NULL         | 7           | Grace Purple  | Sales      | West-305
---
### 9. Full Outer Join Between Employees and Machines
**Description:**
Finally, we use a Full Outer Join to return all records from both tables (employees and machines), filling in nulls where there are no matches between the tables.

**SQL Query (Full Outer Join):**
```sql
SELECT *
FROM employees
FULL OUTER JOIN machines
ON employees.device_id = machines.device_id;
```
**Explanation:**
The Full Outer Join returns all records from both tables, filling in nulls where there are no matches. This way, all machines and all employees are included, regardless of whether they are related or not.

**Expected Result (Full Outer Join):**
device_id | machine_name | employee_id | employee_name | department | office
--------- | ------------ | ----------- | ------------- | ---------- | --------
101       | Laptop A     | 1           | Alice Brown   | Marketing  | East-150
102       | Laptop B     | 2           | Bob White     | Marketing  | East-267
103       | Desktop C    | 3           | Carol Black   | Marketing  | East-320
104       | Desktop D    | 4           | Dave Green    | Sales      | West-400
105       | Laptop E     | 5           | Eve Blue      | Finance    | West-101
106       | Tablet F     | NULL        | NULL          | NULL       | NULL
NULL      | NULL         | 6           | Frank Red     | Finance    | West-105
NULL      | NULL         | 7           | Grace Purple  | Sales      | West-305
---
### Using JOINs in Security Investigations:
Using different types of **JOINs (INNER, LEFT, RIGHT, FULL OUTER)** in security data analysis allows significant flexibility when cross-referencing information from different tables. Depending on the type of information we are looking for, an **INNER JOIN** might be ideal for identifying the most relevant events (for example, only failed login attempts from active users), while a LEFT JOIN might be more useful for obtaining all login attempts, even those not associated with a specific employee.

### In Security Situations:
As we can see from a failed login attempt from an unexpected country, a **LEFT JOIN** might be useful to more thoroughly investigate all activities and detect possible irregular access patterns. On the other hand, a **RIGHT JOIN** might be more appropriate when we want to ensure all employees are included in our investigation, regardless of whether or not they have an assigned machine. Finally, a **FULL OUTER JOIN** would be useful to obtain a comprehensive view of both sides of the data, ensuring that no access attempts or unusual activity are overlooked.

### Conclusion
In the context of computer security, **SQL queries** play a crucial role in allowing security professionals to conduct detailed investigations into suspicious events. Through the proper use of filters and functions such as **BETWEEN**, **LIKE**, and **NOT LIKE**, we can identify anomalous patterns and behavior in login attempts. However, the true power of these queries is revealed when tables are combined using joins, such as the different types of **JOIN** used in this investigation exercise.

---


