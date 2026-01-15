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




