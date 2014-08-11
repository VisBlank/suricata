--
-- Employee Tree: who is my manager.
-- This is a hierarchical query with ident
--
CREATE TABLE emp (
    empno NUMBER(4) constraint E_PK primary key,
    ename VARCHAR2(8),
    init VARCHAR2(5),
    job VARCHAR2(8),
    mgr NUMBER(4),
    bdate DATE,
    sal NUMBER(6,2),
    comm NUMBER(6,2),
    deptno NUMBER(2) DEFAULT 10);

INSERT INTO emp VALUES(1,'Tom','N','TRAINER',12,DATE'1965-12-17',800,NULL,20);
INSERT INTO emp VALUES(2,'Jack','Jam','TRAINER',6,DATE'1961-02-20',1600,300,20);
INSERT INTO emp VALUES(3,'Wil','TF','Tester',6,DATE'1962-02-22',1250,500,30);
INSERT INTO emp VALUES(4,'Jane','JM','Designer',9,DATE'1967-04-02',2975,NULL,20);
INSERT INTO emp VALUES(5,'Mary','P','Tester',6,DATE'1956-09-28',1250,1400,30);
INSERT INTO emp VALUES(6,'Black','R','Designer',9,DATE'1963-11-01',2850,NULL,30);
INSERT INTO emp VALUES(7,'Chris','AB','Designer',9,DATE'1965-06-09',2450,NULL,10);
INSERT INTO emp VALUES(8,'Smart','SCJ','TRAINER',4,DATE '1959-11-26',3000,NULL,20);
INSERT INTO emp VALUES(9,'Peter','CC','Designer',NULL,DATE '1952-11-17',5000,NULL,10);
INSERT INTO emp VALUES(10,'Take','JJ','Tester',6,DATE '1968-09-28',1500,0,30);
INSERT INTO emp VALUES(11,'Ana','AA','TRAINER',8,DATE '1966-12-30',1100,NULL,20);
INSERT INTO emp VALUES(12,'Jane','R','Manager',6,DATE '1969-12-03',800,NULL,30);
INSERT INTO emp VALUES(13,'Fake','MG','TRAINER',4,DATE '1959-02-13',3000,NULL,20);
INSERT INTO emp VALUES(14,'Mike','TJA','Manager',7,DATE '1962-01-23',1300,NULL,10);

SELECT lpad('  ', 2 * level - 1) || ename as ename
FROM emp
START WITH mgr IS NULL
CONNECT BY nocycle PRIOR empno = mgr;

DROP TABLE emp;
