begin
    case
    when 1 = 2 then
        dbms_output.put_line('Case [1 = 2]');
    when 2 = 2 then
        dbms_output.put_line('Case [2 = 2]');
    else
        dbms_output.put_line('No Match');
    end case;
end;
/
