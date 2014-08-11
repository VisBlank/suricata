
CREATE TABLE employee (
    employee_id INTEGER,
    manager_id INTEGER,
    first_name VARCHAR2(256) NOT NULL,
    last_name VARCHAR2(256) NOT NULL,
    home_addr VARCHAR2(256) NOT NULL,
    title VARCHAR2(256),
    salary NUMBER(6, 0)
);
insert into employee(employee_id,manager_id,first_name,last_name,home_addr,title,salary) values(1,0,'ffffffffffffffffffffffffffff','llllllllllllllllllllllllllll','hhhhhhhhhhhhhhhhhhhhhhhhhhhh','OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO',800000);
DROP TABLE employee;
