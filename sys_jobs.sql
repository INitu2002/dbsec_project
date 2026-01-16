show con_name;

-- created administrator user to create the tables
create user administrator identified by administrator;
grant create session, create table, create sequence, create procedure, create trigger to administrator;
alter user administrator quota 50m on users;

grant execute on dbms_crypto to administrator;

grant execute on dbms_fga to administrator;

-- lab 2 - audit
-- creez userii de test:
create user fermier_test identified by fermier_test;
grant create session to fermier_test;

create user auditor_farm identified by auditor_farm;
grant create session to auditor_farm;

-- standard audit pe obiecte
-- pornesc audit pe obiecte
audit select, insert, update, delete on administrator.comenzi by access;
audit select, insert, update, delete on administrator.facturi by access;

-- 1 - raport audit:
select username, obj_name, action_name, to_char(timestamp,'dd-mm-yyyy hh24:mi:ss') ts
from dba_audit_trail
where obj_name in ('COMENZI','FACTURI')
order by timestamp desc;

-- opreste audit:
noaudit select, insert, update, delete on administrator.comenzi;
noaudit select, insert, update, delete on administrator.facturi;

-- ex 2, lab 2
-- audit "whenever not successful" pe solicitari
audit insert, update, delete on administrator.solicitari
by access whenever not successful;

select username, obj_name, action_name, returncode, to_char(timestamp,'dd-mm-yyyy hh24:mi:ss') ts
from dba_audit_trail
where obj_name='SOLICITARI'
order by timestamp desc;

noaudit insert, update, delete on administrator.solicitari;

-- ex 4, lab 2:
-- audit policy dbms_fga: fine-grain pe conditie
grant execute on dbms_fga to administrator;

select db_user, object_name, policy_name, to_char(timestamp,'dd-mm-yyyy hh24:mi:ss') ts, sql_text
from dba_fga_audit_trail
where object_name='PLATI'
order by timestamp desc;

-- 4 b
create profile secure_profile limit
failed_login_attempts 3
password_life_time 30
password_reuse_time 30
password_reuse_max 3
password_lock_time 1/24
password_grace_time 1
password_verify_function ora12c_verify_function;    -- minim 8 chars, 1 minusc, 1 majusc, 1 cifra, 1 special char

create user farmer_south identified by Farmer_100
profile secure_profile
quota 50m on users;

create user farmer_north identified by Farmer_200
profile secure_profile
quota 50m on users;

create user farmer_ilfov identified by Farmer_300
profile secure_profile
quota 50m on users;

create user sales_coordinator identified by Sales_123
profile secure_profile quota 30m on users;

create user warehouse_operator identified by Ware_123
profile secure_profile quota 30m on users;

create user finance_officer identified by Finance_123
profile secure_profile quota 30m on users;

create user farm_manager identified by FarmManager_123
profile secure_profile quota 0 on users;

grant create session to farmer_south;
grant create session to farmer_north;
grant create session to farmer_ilfov;

grant create session to sales_coordinator;
grant create session to warehouse_operator;
grant create session to finance_officer;
grant create session to farm_manager;

-- mandatory passw change:
alter user farmer_south password expire;
alter user farmer_north password expire;
alter user farmer_ilfov password expire;

grant create view to administrator;

-- adaugare consitie de maxim 2 sesiuni per user, maxim idle time 10 min;
alter session set container=pdb2;
alter system set resource_limit = true;

alter profile secure_profile limit
sessions_per_user 2
idle_time 2
connect_time 30;






