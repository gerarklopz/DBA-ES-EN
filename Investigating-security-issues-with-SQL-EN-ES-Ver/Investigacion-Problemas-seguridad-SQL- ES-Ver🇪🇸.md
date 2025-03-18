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





