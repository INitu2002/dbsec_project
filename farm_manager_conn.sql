-- 5 - cerinta suplimentara
-- testare rol emergency
select * from administrator.stoc_depozit;

exec administrator.pkg_emergency_role.enable_role;

select * from session_roles;

begin
  administrator.pkg_emergency_role.enable_role;
end;
/

select owner, object_name, object_type
from all_objects
where owner='ADMINISTRATOR'
  and object_name='PKG_EMERGENCY_ROLE';
  
select table_name, privilege
from all_tab_privs
where grantee = 'FARM_MANAGER'
  and table_name = 'PKG_EMERGENCY_ROLE';
  
exec administrator.pkg_emergency_role.enable_role;
select * from session_roles;

-- 5 c)
create or replace procedure p_cnt_dep as
  v_cnt number;
begin
  select count(*) into v_cnt from administrator.depozite;
  dbms_output.put_line(v_cnt);
end;
/

set role all;
select * from session_roles;

select * from administrator.depozite;



