create table emp
( empno NUMBER(4) constraint E_PK primary key
    , ename VARCHAR2(8)
    , init VARCHAR2(5)
    , job VARCHAR2(8)
    , mgr NUMBER(4)
    , bdate DATE
    , sal NUMBER(6,2)
    , comm NUMBER(6,2)
    , deptno NUMBER(2) default 10
);

insert into emp values(1,'Tom','N', 'TRAINER', 13,date '1965-12-17', 800 , NULL, 20); 
insert into emp values(2,'Jack','JAM', 'Tester',6,date '1961-02-20', 1600, 300, 30); 
insert into emp values(3,'Wil','TF' , 'Tester',6,date '1962-02-22', 1250, 500, 30); 
insert into emp values(4,'Jane','JM', 'Designer', 9,date '1967-04-02', 2975, NULL, 20); 
insert into emp values(5,'Mary','P', 'Tester',6,date '1956-09-28', 1250, 1400, 30);
insert into emp values(6,'Black','R', 'Designer', 9,date '1963-11-01', 2850, NULL, 30);
insert into emp values(7,'Chris','AB', 'Designer', 9,date '1965-06-09', 2450, NULL, 10);
insert into emp values(8,'Smart','SCJ', 'TRAINER', 4,date '1959-11-26', 3000, NULL, 20);
insert into emp values(9,'Peter','CC', 'Designer',NULL,date '1952-11-17', 5000, NULL, 10);
insert into emp values(10,'Take','JJ', 'Tester',6,date '1968-09-28', 1500, 0, 30);
insert into emp values(11,'Ana','AA', 'TRAINER', 8,date '1966-12-30', 1100, NULL, 20);
insert into emp values(12,'Jane','R', 'Manager', 6,date '1969-12-03', 800 , NULL, 30);
insert into emp values(13,'Fake','MG', 'TRAINER', 4,date '1959-02-13', 3000, NULL, 20);
insert into emp values(14,'Mike','TJA','Manager', 7,date '1962-01-23', 1300, NULL, 10); 

with g as (select x.deptno , avg(x.sal) avg_sal from emp x group by x.deptno)
select e.ename, e.init, e.sal
    from emp e
    join g
    using (deptno)
    where e.sal > g.avg_sal;

drop table emp;
