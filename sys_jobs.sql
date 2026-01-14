-- created administrator user to create the tables
create user administrator identified by administrator;
grant create session, create table, create sequence, create procedure, create trigger to administrator;
alter user administrator quota 50m on users;


