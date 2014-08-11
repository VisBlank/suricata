--
-- Eliminate an entire branch of nodes from the results
-- of a query, you add an AND clause to your CONNECT BY
-- PRIOR clause
--

CREATE TABLE employee (
    employee_id INTEGER,
    manager_id INTEGER,
    first_name VARCHAR2(10) NOT NULL,
    last_name VARCHAR2(10) NOT NULL,
    title VARCHAR2(20),
    salary NUMBER(6, 0)
);

insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 1 ,0 , 'James' ,'Smith' ,'CEO',800000); 
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 2 , 1 ,'Ron' ,'Johnson','Sales Manager',600000); 
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 3 , 2 ,'Fred' ,'Hobbs' ,'Sales Person',200000); 
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 4 , 1 ,'Susan' ,'Jones' ,'Support Manager',500000);
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 5 , 2 ,'Rob' ,'Green' ,'Sales Person', 40000);
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 6 , 4 ,'Jane' ,'Brown' ,'Support Person',45000);
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 7 , 4 ,'John' ,'Grey' ,'Support Manager',30000); 
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 8 , 7 ,'Jean' ,'Blue' ,'Support Person',29000); 
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 9 , 6 ,'Henry' ,'Heyson' ,'Support Person',30000); 
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 10 , 1 ,'Kevin' ,'Black' ,'Ops Manager',100000);
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 11 , 10 ,'Keith' ,'Long' ,'Ops Person',50000);
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 12 , 10 ,'Frank' ,'Howard' ,'Ops Person',45000);
insert into employee (EMPLOYEE_ID, MANAGER_ID,FIRST_NAME,LAST_NAME,TITLE,SALARY) values( 13 , 10 ,'Doreen' ,'Penn' ,'Ops Person',47000);

select * from employee;

-- Eliminate an entire branch of nodes from the results
-- of a query, you add an AND clause to your CONNECT BY
-- PRIOR clause
SELECT LEVEL,
    LPAD(' ', 2 * LEVEL - 1) || first_name || ' ' ||
    last_name AS employee
    FROM employee
    START WITH employee_id = 1
    CONNECT BY PRIOR employee_id = manager_id
    AND last_name != 'Johnson';

drop table employee;
