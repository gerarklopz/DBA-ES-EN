# Investigación de Problemas de Seguridad con SQL ES-Ver🇪🇸

## Escenario:
Como profesional de seguridad en una gran organización, nos podríamos encargar de investigar posibles incidentes relacionados con intentos de inicio de sesión y máquinas de empleados. Para realizar la investigación, utilizaríamos las tablas `employees` y `log_in_attempts`, aplicando filtros SQL para identificar registros que podrían representar vulnerabilidades.

---

### 1. Recuperar intentos fallidos de inicio de sesión después de horas laborales

**Descripción:**  
Hemos identificado un posible incidente de seguridad que ocurrió después del horario laboral. Para investigarlo, necesitamos consultar la tabla `log_in_attempts` y revisar los intentos de inicio de sesión fuera del horario normal de trabajo. La consulta debe identificar todos los intentos fallidos que ocurrieron después de las 18:00. El campo `login_time` contiene la hora del intento, y el campo `success` tiene un valor de 0 cuando el intento falla.

**Consulta SQL:**
```sql
SELECT * 
FROM log_in_attempts 
WHERE login_time > "18:00:00" AND success = 0
ORDER BY login_time;
```
**Explicación:**

- **Filtro:** La consulta selecciona los intentos de inicio de sesión fallidos (`success = 0`) que ocurrieron después de las 18:00 horas.
- **Ordenación:** Los resultados se ordenan por la hora del intento (`login_time`) para facilitar el análisis cronológico.

**Resultado Ejemplo:**

| event_id | username  | login_date | login_time | country | ip_address       | success |
|----------|-----------|------------|------------|---------|------------------|---------|
| 104      | asundara  | 2022-05-11 | 18:38:07   | US      | 192.168.96.200   | 0       |
| 20       | tshah     | 2022-05-12 | 18:56:36   | MEXICO  | 192.168.109.50   | 0       |
| 28       | aestrada  | 2022-05-09 | 19:28:12   | MEXICO  | 192.168.27.57    | 0       |
| 18       | pwashing  | 2022-05-11 | 19:28:50   | US      | 192.168.66.142   | 0       |
| 199      | yappiah   | 2022-05-11 | 19:34:48   | MEXICO  | 192.168.44.232   | 0       |
| 69       | wjaffrey  | 2022-05-11 | 19:55:15   | USA     | 192.168.100.17   | 0       |
---
### Parte 2: Recuperar intentos de inicio de sesión en fechas específicas 

**Descripción:**  
Se detectó una actividad sospechosa en las fechas del 8 y 9 de mayo de 2022. Necesitamos revisar todos los intentos de inicio de sesión realizados en estas fechas específicas. La columna `login_date` contiene la fecha del intento.

**Consulta SQL:**
```sql
SELECT * 
FROM log_in_attempts
WHERE login_date BETWEEN "2022-05-08" AND "2022-05-09"
ORDER BY login_time;
```
**Explicación:**

- **Filtro:** La consulta selecciona los intentos de inicio de sesión ocurridos entre el 8 y el 9 de mayo de 2022.
- **Ordenación:** Los resultados se ordenan por la hora del inicio de sesión (`login_time`) para facilitar la identificación de patrones.

**Resultado Ejemplo:**

| event_id | username  | login_date | login_time | country | ip_address       | success |
|----------|-----------|------------|------------|---------|------------------|---------|
| 110      | mabadi    | 2022-05-09 | 00:01:54   | USA     | 192.168.90.124   | 1       |
| 117      | bsand     | 2022-05-08 | 00:19:11   | USA     | 192.168.197.187  | 0       |
| 92       | pwashing  | 2022-05-08 | 00:36:12   | US      | 192.168.247.219  | 0       |
| 187      | arusso    | 2022-05-09 | 00:36:26   | MEX     | 192.168.77.137   | 0       |
| 90       | gesparza  | 2022-05-09 | 00:49:05   | CANADA  | 192.168.87.201   | 0       |
| 8        | bisles    | 2022-05-08 | 01:30:17   | US      | 192.168.119.173  | 0       |
---
### Parte 3: Recuperar intentos de inicio de sesión fuera de México

**Descripción:**  
Se ha identificado actividad sospechosa, pero se ha determinado que no proviene de México. Necesitamos revisar los intentos de inicio de sesión que se realizaron fuera de México. La columna `country` contiene valores como 'MEX' y 'MEXICO' para identificar los intentos provenientes de México. Usamos en éste caso el operador `NOT LIKE` para excluir estos registros.

**Consulta SQL:**
```sql
SELECT * 
FROM log_in_attempts 
WHERE login_date BETWEEN "2022-05-08" AND "2022-05-09" 
AND NOT country LIKE "MEX%" 
ORDER BY login_date, login_time;
```
**Explicación:**

**Filtro:**
Esta consulta excluye los intentos de inicio de sesión realizados desde México, utilizando el operador `NOT LIKE "MEX%"` que implicitamente excluye parám. como: "MEXICO" presentes también en los registros de la columna `country`.

**Rango de fechas:**
Filtra los intentos que ocurrieron entre el 8 y 9 de mayo de 2022.

**Ordenación:**
Los resultados se ordenan por la fecha y hora (`login_date` y `login_time`).

**Resultado Ejemplo:**

| event_id | username | login_date | login_time | country  | ip_address     | success |
|----------|----------|------------|------------|----------|----------------|---------|
| 1        | jdoe     | 2022-05-08 | 10:15:30   | USA      | 192.168.96.200 | 0       |
| 2        | rsmith   | 2022-05-08 | 11:45:00   | CANADA   | 192.168.197.50 | 1       |
| 3        | pbrown   | 2022-05-08 | 13:30:20   | BRAZIL   | 192.168.101.100| 0       |
| 4        | jblack   | 2022-05-09 | 09:10:15   | ARGENTINA| 192.168.105.15 | 1       |
| 5        | kgreen   | 2022-05-09 | 14:05:45   | CHILE    | 192.168.77.58  | 0       |

---

### 4. Recuperar empleados en el departamento de Marketing en el edificio Este 

**Descripción:**
Se necesitan actualizar las máquinas de los empleados del departamento de Marketing ubicados en las oficinas del edificio Este. Necesitamos filtrar los registros de la tabla `employees` para obtener la información pertinente.

**Consulta SQL:**
```sql
SELECT * 
FROM employees 
WHERE department = "Marketing" 
AND office LIKE "East%";
```
**Explicación:**

**Filtro:**
Selecciona a los empleados que pertenecen al departamento de Marketing y que trabajan en oficinas del edificio Este (identificado por el prefijo 'East' en la columna `office`).

**Patrón de búsqueda:**
Se usa el operador `LIKE "East%"` para identificar todas las oficinas del edificio Este.

**Resultado Ejemplo:**

| id | name         | department | office    |
|----|--------------|------------|-----------|
| 1  | Alice Brown  | Marketing  | East-150  |
| 2  | Bob White    | Marketing  | East-267  |
| 3  | Carol Black  | Marketing  | East-320  |
| 4  | Dave Green   | Marketing  | East-410  |
| 5  | Eve Blue     | Marketing  | East-590  |

---

### 5. Recuperar empleados en los departamentos de Finanzas y Ventas

**Descripción:**
Se necesita actualizar las máquinas de los empleados en los departamentos de Finanzas y Ventas. Para esto, debes realizar una consulta que filtre a los empleados de estos departamentos.

**Consulta SQL:**

```sql
SELECT * 
FROM employees 
WHERE department IN ("Finance", "Sales");
```
**Explicación:**

**Filtro:**
Se seleccionan los empleados de los departamentos de Finanzas o Ventas utilizando el operador `IN`.

**Resultado Ejemplo:**

| id | name         | department | office    |
|----|--------------|------------|-----------|
| 6  | Frank Red    | Finance    | West-101  |
| 7  | Grace Purple | Finance    | West-105  |
| 8  | Hank Green   | Sales      | West-305  |
| 9  | Isabel Blue  | Sales      | West-400  |

---

### 6. Empleados no en el departamento de TI

**Descripción:**
Nuestro equipo necesita hacer una actualización adicional en las máquinas de los empleados. Los empleados del departamento de Tecnología de la Información (TI) ya recibieron esta actualización, pero aquellos de otros departamentos aún necesitan ser actualizados. La tarea consiste en identificar a todos los empleados que no están en el departamento de TI.

**Consulta SQL:**

```sql
SELECT * 
FROM employees 
WHERE department NOT LIKE "Information Technology";
```
**Explicación:**

**Filtro:**
La consulta selecciona a los empleados cuyo campo `department` no contiene el valor "Information Technology". Se utiliza el operador `NOT LIKE` para excluir a los empleados de TI.

**Resultados esperados:**
Esta consulta devolverá a todos los empleados que pertenecen a otros departamentos, excluyendo a los que están en el departamento de Tecnología de la Información.

**Resultado Ejemplo:**

| id | name        | department         | office     |
|----|-------------|--------------------|------------|
| 1  | Sam Hill    | Finance            | HQ-101     |
| 2  | Lucy Lane   | Sales              | East-102   |
| 3  | Mike Chan   | Marketing          | West-201   |
| 4  | Peter Wong  | Human Resources    | HQ-305     |
| 5  | Sara Hall   | Customer Support   | North-410  |

---

### Aplicación práctica de estas consultas:
Por ejemplo, un intento fallido de inicio de sesión desde un país inesperado podría ser un indicio de un ataque de fuerza bruta, donde un atacante intenta acceder a una cuenta mediante múltiples intentos con diferentes combinaciones de contraseñas. Al utilizar una consulta con `NOT LIKE` para excluir ciertos países o con `BETWEEN` para filtrar intentos dentro de un intervalo de tiempo específico, podemos identificar rápidamente estas amenazas.

---


### 7. Identifying Employees and Their Machines (INNER JOIN)
**Descripción:**
La consulta `INNER JOIN` nos permitirá identificar qué empleados están usando qué máquinas. Se unirán las tablas machines y employees en la columna común `device_id`

**Consulta SQL:**
```sql
SELECT * 
FROM machines 
INNER JOIN employees 
ON machines.device_id = employees.device_id;
```
**Explicación:**
La consulta `INNER JOIN` devuelve una lista completa de los detalles de las máquinas junto con la información del empleado asociado a ellas. Solo aparecerán aquellos registros donde haya coincidencias entre ambas tablas.

**Resultado Esperado:**


| device_id | machine_name | employee_id | employee_name | department  | office     |
|-----------|--------------|-------------|---------------|-------------|------------|
|    101    |  Laptop A    |      1      |  Alice Brown  |  Marketing  |  East-150  |
|    102    |  Laptop B    |      2      |   Bob White   |  Marketing  |  East-267  |
|    103    |  Desktop C   |      3      |  Carol Black  |  Marketing  |  East-320  |
|    104    |  Desktop D   |      4      |  Dave Green   |   Sales     |  West-400  |
|    105    |  Laptop E    |      5      |   Eve Blue    |  Finance    |  West-101  |
---


### 8. Retrieve All Machine and Employee Data (LEFT JOIN y RIGHT JOIN)
### LEFT JOIN:
**Descripción:**
Usamos un `LEFT JOIN` para obtener todos los registros de máquinas, incluso si no están asignadas a un empleado.
**Consulta SQL (LEFT JOIN):**
```sql
SELECT * 
FROM machines 
LEFT JOIN employees 
ON machines.device_id = employees.device_id;
```
**Explicación:**
El `LEFT JOIN` devuelve todos los registros de la tabla machines y los detalles correspondientes de los empleados cuando están disponibles. Si no hay un empleado asignado, las columnas correspondientes de empleados tendrán valores `NULL`

**Resultado Esperado (LEFT JOIN):**

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
**Descripción:**
Usamos un `RIGHT JOIN` para obtener todos los registros de empleados, incluso si no tienen máquina asignada.

**Consulta SQL (RIGHT JOIN):**
```sql
SELECT * 
FROM machines 
RIGHT JOIN employees 
ON machines.device_id = employees.device_id;
```
**Explicación:**
El `RIGHT JOIN` devuelve todos los registros de la tabla employees y sus máquinas asignadas, si las hay. Si un empleado no tiene máquina asignada, las columnas de `machines` serán `NULL`

**Resultado Esperado (RIGHT JOIN):**

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
**Descripción:**
Finalmente, usamos un `FULL OUTER JOIN` para devolver todos los registros de ambas tablas (employees y machines), llenando con `NULL` donde no haya coincidencias entre las tablas.

**Consulta SQL(FULL OUTER JOIN):**
```sql
SELECT * 
FROM employees 
FULL OUTER JOIN machines 
ON employees.device_id = machines.device_id;
```
**Explicación:**
El `FULL OUTER JOIN` devuelve todos los registros de ambas tablas, llenando las columnas con `NULL` en los casos donde no haya coincidencias. De esta forma, se incluyen todas las máquinas y todos los empleados, independientemente de si están relacionados o no.

**Resultado Esperado (FULL OUTER JOIN):**
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
### Uso de uniones en investigaciones de seguridad:
El uso de diferentes tipos de **JOINs (INNER, LEFT, RIGHT, FULL OUTER)** en el análisis de datos de seguridad ofrece una gran flexibilidad al cruzar información de diferentes tablas. Según el tipo de información que busquemos, una **INNER JOIN** podría ser ideal para identificar los eventos más relevantes (por ejemplo, solo intentos fallidos de inicio de sesión de usuarios activos), mientras que una LEFT JOIN podría ser más útil para obtener todos los intentos de inicio de sesión, incluso aquellos no asociados a un empleado específico.

### En situaciones de seguridad:
Como podemos observar en un intento fallido de inicio de sesión desde un país inesperado, una **LEFT JOIN** podría ser útil para investigar más a fondo todas las actividades y detectar posibles patrones de acceso irregulares. Por otro lado, una **RIGHT JOIN** podría ser más apropiada cuando queremos asegurarnos de que todos los empleados estén incluidos en nuestra investigación, independientemente de si tienen o no una máquina asignada. Finalmente, una ***FULL OUTER JOIN** sería útil para obtener una visión completa de ambos lados de los datos, garantizando que no se pasen por alto intentos de acceso ni actividades inusuales.

### Conclusión
En el contexto de la seguridad informática, las **SQL queries** desempeñan un papel crucial para que los profesionales de seguridad puedan realizar investigaciones detalladas de eventos sospechosos. Mediante el uso adecuado de filtros y funciones como **BETWEEN**, **LIKE** y **NOT LIKE**, podemos identificar patrones y comportamientos anómalos en los intentos de inicio de sesión. Sin embargo, el verdadero poder de estas consultas se revela cuando se combinan tablas mediante uniones, como los diferentes tipos de **JOIN** utilizados en este ejercicio de investigación.

---





