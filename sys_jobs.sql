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

select username,
       count(*) as sesiuni_active
from   v$session
where  username is not null
group  by username
order  by sesiuni_active desc, username;

-- cerinta 5 - a)
-- creez user inventory_auditor:
create user inventory_auditor identified by Invent_123
profile secure_profile
quota 0 on users;

grant create session to inventory_auditor;

-- 5a) - creez rol nou:
create role r_stock_read;
-- acord drepturi pe view-uri noului rol
grant select on administrator.v_stock_depozit_safe to r_stock_read;
grant select on administrator.v_stock_magazin_safe to r_stock_read;

-- warehouse_operator poate delega acest rol mai departe:
grant r_stock_read to warehouse_operator with admin option;

-- cerinta 5b) - roluri ierarhice:
-- capabilitati mici
create role r_read_catalog;
create role r_farmer_self_read;
create role r_sales_exec;
create role r_warehouse_exec;
create role r_finance_exec;

-- job roles
create role r_farmer;
create role r_sales;
create role r_warehouse;
create role r_finance;

-- roluri de supervizor
create role r_ops_supervisor;
create role r_business_admin;

-- ierarhie de roluri:
grant r_read_catalog      to r_farmer;
grant r_farmer_self_read  to r_farmer;

grant r_read_catalog      to r_sales;
grant r_sales_exec        to r_sales;

grant r_stock_read        to r_warehouse;
grant r_warehouse_exec    to r_warehouse;

grant r_finance_exec      to r_finance;

-- supervisory roles
grant r_sales     to r_ops_supervisor;
grant r_warehouse to r_ops_supervisor;

grant r_ops_supervisor to r_business_admin;
grant r_finance        to r_business_admin;

-- atribuire roluri catre useri:
grant r_farmer to farmer_south;
grant r_farmer to farmer_north;
grant r_farmer to farmer_ilfov;

grant r_sales to sales_coordinator;
grant r_warehouse to warehouse_operator;
grant r_finance to finance_officer;

-- manager primește “business admin”
grant r_business_admin to farm_manager;

-- demonstratie ierarhie:
select grantee, granted_role, admin_option
from dba_role_privs
where grantee in ('FARM_MANAGER')
order by grantee, granted_role;

-- demonstratie efect de cascada (daca scot unul din roluri, nu mai functioneaza select-ul => se pierd drepturile)
revoke r_stock_read from r_warehouse;

-- readaugare rol:
grant r_stock_read to r_warehouse;

-- creare rol securizat:
create role r_ops_emergency identified using administrator.pkg_emergency_role;

-- da rolul doar catre farm_manager, dar nu il poate folosi fara procedura:
grant r_ops_emergency to farm_manager;
grant execute on administrator.p_enable_emergency_role to farm_manager;
grant execute on set_role to administrator;

-- rolul r_ops_emergency sa nu fie default:
alter user farm_manager default role all except r_ops_emergency;

-- 5 c)
SELECT * FROM dba_tab_privs WHERE grantee='INVENTORY_AUDITOR';

-- 5 c) demo 2:
-- create role r_dep_test;
grant create procedure to farm_manager;

grant r_fm_dep to farm_manager;
grant create procedure to farm_manager;

-- cerinta 6:
-- Crearea contextului (este un obiect global la nivel de bază de date)
CREATE OR REPLACE CONTEXT CTX_FARM_SECURITY USING administrator.pkg_session_context;

-- Acordarea dreptului de a citi IP-ul (pentru partea "exquisite")
GRANT SELECT ANY DICTIONARY TO administrator;

CREATE OR REPLACE TRIGGER trg_on_logon
AFTER LOGON ON DATABASE
BEGIN
  -- Doar dacă userul nu este SYS, activăm contextul
  IF USER NOT IN ('SYS', 'SYSTEM') THEN
    administrator.pkg_session_context.set_farm_context;
  END IF;
EXCEPTION WHEN OTHERS THEN NULL; -- Evităm blocarea logării în caz de eroare
END;
/

-- cerinta 7 - data masking (1 = ca in lab):
create or replace directory direxp as 'c:\secbd';
grant read, write on directory direxp to administrator;

-- masking cu dbms_redact:
GRANT EXECUTE ON DBMS_REDACT TO administrator;











