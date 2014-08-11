CREATE TABLE emp (
    id         NUMBER PRIMARY KEY,
    fname VARCHAR2(50),
    lname  VARCHAR2(50)
);

INSERT INTO emp (id, fname, lname)VALUES (1, 'A', 'B');
INSERT INTO emp (id, fname, lname)VALUES (2, 'C', 'D');
INSERT INTO emp (id, fname, lname)VALUES (3, 'Enn', 'F');
INSERT INTO emp (id, fname, lname)VALUES (4, 'G', 'H');
INSERT INTO emp (id, fname, lname)VALUES (5, 'G', 'Z'); 

SET SERVEROUTPUT ON
DECLARE
v_rowid ROWID;
v_rowcount NUMBER := 0;

    CURSOR emp_cur1 IS SELECT rowid FROM emp WHERE id > 50;
    CURSOR emp_cur2 IS SELECT rowid FROM emp WHERE id > 50;

BEGIN
    OPEN emp_cur1;
    DELETE FROM emp WHERE id > 50;
    OPEN emp_cur2;
    FETCH emp_cur1 INTO v_rowid;
    IF emp_cur1%ROWCOUNT > 0
        THEN
            DBMS_OUTPUT.PUT_LINE('Cursor 1 includes the deleted rows');
    ELSE
        DBMS_OUTPUT.PUT_LINE('Cursor 1 does not include the deleted rows');
    END IF;

    v_rowcount := 0;

    FETCH emp_cur2 INTO v_rowid;
    IF emp_cur2%ROWCOUNT > 0
        THEN
        DBMS_OUTPUT.PUT_LINE('Cursor 2 includes the deleted rows');
    ELSE
        DBMS_OUTPUT.PUT_LINE('Cursor 2 does not include the deleted rows');
    END IF;

    CLOSE emp_cur1;
    CLOSE emp_cur2;

    ROLLBACK;

    EXCEPTION
    WHEN OTHERS
        THEN
        DBMS_OUTPUT.PUT_LINE(sqlerrm);
END;
/

DROP TABLE emp;
