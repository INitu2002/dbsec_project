create table producatori_email_crypt(
  id_producator number(3) primary key,
  email_crypt raw(2000)
);

create table producatori_email_decrypt(
  id_producator number(3) primary key,
  email_plain varchar2(200)
);

create or replace procedure encrypt_email_prod as
  key varchar2(8) := '12345678';
  raw_key raw(100);
  raw_text raw(2000);
  op_mode pls_integer;
  result_raw raw(2000);

  cursor c_prod is
    select id_producator, nvl(email,'fara_email') email
    from producatori;
begin
  raw_key := utl_i18n.string_to_raw(key, 'AL32UTF8');
  op_mode := dbms_crypto.encrypt_des + dbms_crypto.pad_zero + dbms_crypto.chain_ecb;

  delete from producatori_email_crypt;

  for rec in c_prod loop
    raw_text := utl_i18n.string_to_raw(rec.email, 'AL32UTF8');
    result_raw := dbms_crypto.encrypt(raw_text, op_mode, raw_key);
    insert into producatori_email_crypt values(rec.id_producator, result_raw);
  end loop;

  commit;
  dbms_output.put_line('emails encrypted in producatori_email_crypt');
end;
/

create or replace procedure decrypt_email_prod as
  key varchar2(8) := '12345678';
  raw_key raw(100);
  op_mode pls_integer;

  cursor c_crypt is
    select id_producator, email_crypt
    from producatori_email_crypt;
begin
  raw_key := utl_i18n.string_to_raw(key, 'AL32UTF8');
  op_mode := dbms_crypto.encrypt_des + dbms_crypto.pad_zero + dbms_crypto.chain_ecb;

  delete from producatori_email_decrypt;

  for rec in c_crypt loop
    insert into producatori_email_decrypt
    values(rec.id_producator,
           utl_i18n.raw_to_char(dbms_crypto.decrypt(rec.email_crypt, op_mode, raw_key), 'AL32UTF8'));
  end loop;

  commit;
  dbms_output.put_line('emails decrypted in producatori_email_decrypt');
end;
/

execute encrypt_email_prod;
select * from producatori_email_crypt order by id_producator;

execute decrypt_email_prod;
select p.id_producator, p.email original_email, d.email_plain decrypted_email
from producatori p, producatori_email_decrypt d
where d.id_producator=p.id_producator
order by p.id_producator;

-- creezi un “alias” criptat (reversibil) ca sa poti afisa date fara email real, dar sa poti recupera email-ul daca ai cheia.
/*
arati ca poti expune alias_view fara email; iar alias_crypt e acolo pentru reversibilitate (tu poti mentiona ca in practica cheia nu se tine in sesiune, ci in keys_table / wallet).
*/
create table producatori_alias(
  id_producator number(3) primary key,
  alias_crypt raw(2000),
  alias_view varchar2(40)
);

create or replace procedure gen_alias_prod as
  key_raw raw(16);
  op_mode pls_integer;

  raw_text raw(2000);
  enc_raw raw(2000);

  cursor c_prod is
    select id_producator, nume, prenume
    from producatori
    order by id_producator;

  alias_txt varchar2(40);
begin
  key_raw := dbms_crypto.randombytes(16);
  op_mode := dbms_crypto.encrypt_aes128 + dbms_crypto.pad_pkcs5 + dbms_crypto.chain_cbc;

  delete from producatori_alias;

  for rec in c_prod loop
    alias_txt := lower(substr(rec.nume,1,1) || rec.prenume || '_' || rec.id_producator);

    raw_text := utl_i18n.string_to_raw(alias_txt,'AL32UTF8');
    enc_raw := dbms_crypto.encrypt(raw_text, op_mode, key_raw);

    insert into producatori_alias values(rec.id_producator, enc_raw, alias_txt);
  end loop;

  dbms_output.put_line('alias created + encrypted (key kept only in session)');
  commit;
end;
/

execute gen_alias_prod;
select * from producatori_alias order by id_producator;

/*  cerinta 2 (crypto + key mgmt): semnatura de integritate pentru facturi, fara sa atingi tabelul facturi
creez un tabel de “semnaturi” (hash) pentru facturi. apoi o procedura care:
calculeaza hash pe campuri relevante (id_comanda + valoare_totala + status)
salveaza semnatura
o alta procedura care verifica daca s-a schimbat ceva (“integrity ok/ko”)
*/
create table facturi_sig(
  id_factura number(6) primary key,
  sig raw(32) not null,
  data_sig date default sysdate not null
);

-- procedura: calculeaza semnatura
create or replace procedure sign_facturi as
  v_str varchar2(400);
  v_sig raw(32);

  cursor c_fact is
    select id_factura, id_comanda, valoare_totala, status
    from facturi
    order by id_factura;
begin
  delete from facturi_sig;

  for rec in c_fact loop
    v_str := rec.id_factura || '|' || rec.id_comanda || '|' || rec.valoare_totala || '|' || rec.status;
    v_sig := dbms_crypto.hash(utl_raw.cast_to_raw(v_str), dbms_crypto.hash_sh256);

    insert into facturi_sig(id_factura, sig) values(rec.id_factura, v_sig);
  end loop;

  commit;
  dbms_output.put_line('facturi signed (sha256)');
end;
/

-- procedura: verifica semnatura
create or replace procedure verify_facturi as
  v_str varchar2(400);
  v_now raw(32);
  v_old raw(32);

  cursor c_fact is
    select f.id_factura, f.id_comanda, f.valoare_totala, f.status
    from facturi f
    order by f.id_factura;

  bad_cnt number := 0;
begin
  for rec in c_fact loop
    v_str := rec.id_factura || '|' || rec.id_comanda || '|' || rec.valoare_totala || '|' || rec.status;
    v_now := dbms_crypto.hash(utl_raw.cast_to_raw(v_str), dbms_crypto.hash_sh256);

    select sig into v_old from facturi_sig where id_factura = rec.id_factura;

    if v_now != v_old then
      bad_cnt := bad_cnt + 1;
      dbms_output.put_line('integritate incalcata pentru ' || rec.id_factura);
    end if;
  end loop;

  if bad_cnt = 0 then
    dbms_output.put_line('integritate ok pentru toate facturile');
  end if;
end;
/

execute sign_facturi;
-- fiecare factura are acum o semnatura sha256 pe campuri
select * from facturi_sig order by id_factura;

execute verify_facturi;

update facturi set valoare_totala = valoare_totala + 10 where id_comanda=1001;
execute verify_facturi;
rollback;


/*
Ideea:
creezi un HMAC (hash cu cheie secretă) pentru fiecare comandă
doar cine are cheia poate genera un HMAC valid
demonstrezi că dacă cineva modifică datele → verificarea pică
Este mai avansat decât hash simplu, dar tot în linia labului.
*/
create table comenzi_hmac (
  id_comanda number primary key,
  sig raw(32),
  data_gen date default sysdate
);

create or replace procedure gen_sign_comenzi as
  secret_key varchar2(40) := 'secret_project_key';
  v_str varchar2(400);
  v_sig raw(32);

  cursor c_cmd is
    select id_comanda, id_magazin, id_recolta, cantitate, pret, status
    from comenzi
    order by id_comanda;
begin
  delete from comenzi_hmac;

  for rec in c_cmd loop
    v_str := rec.id_comanda || '|' ||
             rec.id_magazin || '|' ||
             rec.id_recolta || '|' ||
             rec.cantitate || '|' ||
             rec.pret || '|' ||
             rec.status;

    v_sig := dbms_crypto.hash(
               utl_raw.cast_to_raw(secret_key || '||' || v_str),
               dbms_crypto.hash_sh256
             );

    insert into comenzi_hmac values(rec.id_comanda, v_sig, sysdate);
  end loop;

  commit;
  dbms_output.put_line('am generat semnaturi pentru comenzi');
end;
/

create or replace procedure verify_sign_comenzi as
  secret_key varchar2(40) := 'secret_project_key';
  v_str varchar2(400);
  v_now raw(32);
  v_old raw(32);
  errors number := 0;

  cursor c_cmd is
    select id_comanda, id_magazin, id_recolta, cantitate, pret, status
    from comenzi
    order by id_comanda;
begin
  for rec in c_cmd loop
    v_str := rec.id_comanda || '|' ||
             rec.id_magazin || '|' ||
             rec.id_recolta || '|' ||
             rec.cantitate || '|' ||
             rec.pret || '|' ||
             rec.status;

    v_now := dbms_crypto.hash(
               utl_raw.cast_to_raw(secret_key || '||' || v_str),
               dbms_crypto.hash_sh256
             );

    select sig into v_old
    from comenzi_hmac
    where id_comanda = rec.id_comanda;

    if v_now != v_old then
      dbms_output.put_line('semnatura invalida pentru comanda ' || rec.id_comanda);
      errors := errors + 1;
    end if;
  end loop;

  if errors = 0 then
    dbms_output.put_line('TOATE comenzile au semnaturi valide!');
  end if;
end;
/

select * from comenzi;

execute gen_sign_comenzi;
execute verify_sign_comenzi;

update comenzi
set status='anulata'
where id_comanda=1001;

execute verify_sign_comenzi;

rollback;
execute verify_sign_comenzi;

-- LAB 2 - audit
-- administrator dă privilegii minime pe obiectele lui
grant select, insert, update, delete on comenzi to fermier_test;
grant select, insert, update, delete on facturi to fermier_test;
grant select, insert, update, delete on plati to fermier_test;
grant select, insert, update, delete on livrari to fermier_test;

grant select on comenzi to auditor_farm;
grant select on facturi to auditor_farm;
grant select on plati to auditor_farm;
grant select on livrari to auditor_farm;

-- ex 2, lab 2:
grant select, insert, update, delete on solicitari to fermier_test;

-- ex 3, lab 2:
create table audit_preturi_recolte(
  id_audit number primary key,
  username varchar2(30),
  ts date,
  id_recolta number(3),
  pret_vechi number(6,2),
  pret_nou number(6,2),
  proc_mod number(6,2)
);

create sequence seq_audit start with 1 increment by 1;

create or replace trigger trg_audit_pret_recolte
before update of pret_kg on recolte
for each row
declare
  v_proc number(6,2);
begin
  if :old.pret_kg > 0 then
    v_proc := round(((:new.pret_kg - :old.pret_kg) / :old.pret_kg) * 100, 2);
  end if;

  -- daca e prea mare, blocam
  if v_proc is not null and abs(v_proc) > 30 then
    raise_application_error(-20501, 'modificare pret > 30% blocata');
  end if;

  -- log doar pentru update-urile permise (mai curat)
  insert into audit_preturi_recolte
  values(
    seq_audit.nextval,
    user,
    sysdate,
    :old.id_recolta,
    :old.pret_kg,
    :new.pret_kg,
    v_proc
  );
end;
/

grant select, update on recolte to fermier_test;
grant select on audit_preturi_recolte to fermier_test;

select * from audit_preturi_recolte
where id_recolta=11
order by id_audit desc;

-- ex 4, lab 2:
begin
  dbms_fga.add_policy(
    object_schema   => 'ADMINISTRATOR',
    object_name     => 'PLATI',
    policy_name     => 'FGA_PLATI_SUMA_MARE',
    audit_condition => 'SUMA > 5000',
    audit_column    => 'SUMA',
    statement_types => 'UPDATE',
    enable          => true
  );
end;
/

-- dezactivare policy fga:
begin
  dbms_fga.disable_policy(
    object_schema => 'ADMINISTRATOR',
    object_name   => 'PLATI',
    policy_name   => 'FGA_PLATI_SUMA_MARE'
  );
end;
/

/*
4. Management of Database Users and Computational Resources
b. Implementing the identity management configuration in the database
*/
show con_name;

-- farm_manager (I,U,D,S pe ferme/parcele/recolte/culturi/utilaje/producatori etc.)
grant delete, insert, select, update on administrator.ferme to farm_manager;
grant delete, insert, select, update on administrator.parcele to farm_manager;
grant delete, insert, select, update on administrator.recolte to farm_manager;
grant delete, insert, select, update on administrator.culturi to farm_manager;
grant delete, insert, select, update on administrator.utilaje to farm_manager;
grant delete, insert, select, update on administrator.producatori to farm_manager;
grant insert, select, update on administrator.lucrari_agricole to farm_manager;

-- farmers: S pe parcele/recolte/culturi + I,U,S pe lucrari_agricole + I,U,S pe solicitari
grant select on administrator.parcele to farmer_south;
grant select on administrator.parcele to farmer_north;
grant select on administrator.parcele to farmer_ilfov;

grant select on administrator.recolte to farmer_south;
grant select on administrator.recolte to farmer_north;
grant select on administrator.recolte to farmer_ilfov;

grant select on administrator.culturi to farmer_south;
grant select on administrator.culturi to farmer_north;
grant select on administrator.culturi to farmer_ilfov;

grant insert, select, update on administrator.lucrari_agricole to farmer_south;
grant insert, select, update on administrator.lucrari_agricole to farmer_north;
grant insert, select, update on administrator.lucrari_agricole to farmer_ilfov;

grant insert, select, update on administrator.solicitari to farmer_south;
grant insert, select, update on administrator.solicitari to farmer_north;
grant insert, select, update on administrator.solicitari to farmer_ilfov;

-- sales_coordinator: S pe magazine + I,U,D,S pe solicitari + I,U,S pe comenzi + S pe livrari/facturi/plati + S pe stoc_magazin
grant select on administrator.magazine to sales_coordinator;
grant delete, insert, select, update on administrator.solicitari to sales_coordinator;
grant insert, select, update on administrator.comenzi to sales_coordinator;
grant select on administrator.livrari to sales_coordinator;
grant select on administrator.facturi to sales_coordinator;
grant select on administrator.plati to sales_coordinator;
grant select on administrator.stoc_magazin to sales_coordinator;

-- warehouse_operator: S pe comenzi/depozite + I,U,S pe livrari + I,U,S pe stoc_depozit
grant select on administrator.comenzi to warehouse_operator;
grant select on administrator.depozite to warehouse_operator;
grant insert, select, update on administrator.livrari to warehouse_operator;
grant insert, select, update on administrator.stoc_depozit to warehouse_operator;

-- finance_officer: S pe comenzi/livrari + I,U,S pe facturi/plati
grant select on administrator.comenzi to finance_officer;
grant select on administrator.livrari to finance_officer;
grant insert, select, update on administrator.facturi to finance_officer;
grant insert, select, update on administrator.plati to finance_officer;

-- plus ce mai cere matricea: farm_manager are S pe magazine/solicitari/comenzi/livrari/facturi/plati/depozite/stoc_depozit
grant select on administrator.magazine to farm_manager;
grant select on administrator.solicitari to farm_manager;
grant select on administrator.comenzi to farm_manager;
grant select on administrator.livrari to farm_manager;
grant select on administrator.facturi to farm_manager;
grant select on administrator.plati to farm_manager;
grant select on administrator.depozite to farm_manager;
grant select on administrator.stoc_depozit to farm_manager;

-- test if all the grants have been given to who deserves them:
select grantee, table_name, privilege
from all_tab_privs
where grantor='ADMINISTRATOR'
and grantee in ('FARM_MANAGER','FARMER_SOUTH','FARMER_NORTH','FARMER_ILFOV','SALES_COORDINATOR','WAREHOUSE_OPERATOR','FINANCE_OFFICER')
order by grantee, table_name, privilege;

-- grant direct pe tabele => farmer_south va vedea toate randurile din tabelele pe care are select (de ex. culturi, lucrari_agricole, solicitari) => de la toti agricultorii
-- doar cu GRANT-uri pe tabele, toți fermierii văd toate rândurile din tabelele pe care au SELECT
-- vreau ca farmer_south să vadă doar datele lui => row-level security (VPD / Fine-Grained Access Control cu DBMS_RLS)
create table farmer_ferma_map(
  username varchar2(30) primary key,
  id_ferma number(3) not null
);

insert into farmer_ferma_map values('FARMER_SOUTH',1);
insert into farmer_ferma_map values('FARMER_NORTH',2);
insert into farmer_ferma_map values('FARMER_ILFOV',3);
commit;

-- se creeaza view-uri filtrate a.i. fermierii sa vada doar parcelele/solicitarile/utilajele etc lor
create or replace view v_parcele_mine as
select p.*
from administrator.parcele p
join administrator.farmer_ferma_map m on m.id_ferma=p.id_ferma
where m.username = user;

-- revocare drept pe tabela in sine
revoke select on administrator.parcele from farmer_south;
revoke select on administrator.parcele from farmer_north;
revoke select on administrator.parcele from farmer_ilfov;

select grantee, table_name, privilege
from all_tab_privs
where grantor='ADMINISTRATOR'
and grantee in ('FARMER_ILFOV')
order by table_name, privilege;

grant select on administrator.v_parcele_mine to farmer_south;
grant select on administrator.v_parcele_mine to farmer_north;
grant select on administrator.v_parcele_mine to farmer_ilfov;

-- separare informatii parcele si culturi
create or replace view v_parcele_mine as
select p.*
from parcele p
join farmer_ferma_map m on m.id_ferma = p.id_ferma
where m.username = user;

create or replace view v_culturi_mine as
select c.*
from culturi c
join parcele p on p.id_parcela = c.id_parcela
join farmer_ferma_map m on m.id_ferma = p.id_ferma
where m.username = user;

create or replace view v_lucrari_mine as
select l.*
from lucrari_agricole l
join culturi c on c.id_cultura = l.id_cultura
join parcele p on p.id_parcela = c.id_parcela
join farmer_ferma_map m on m.id_ferma = p.id_ferma
where m.username = user;

revoke select on culturi from farmer_south;
revoke select on culturi from farmer_north;
revoke select on culturi from farmer_ilfov;

grant select on v_parcele_mine to farmer_south;
grant select on v_parcele_mine to farmer_north;
grant select on v_parcele_mine to farmer_ilfov;

grant select on v_culturi_mine to farmer_south;
grant select on v_culturi_mine to farmer_north;
grant select on v_culturi_mine to farmer_ilfov;

grant select on v_lucrari_mine to farmer_south;
grant select on v_lucrari_mine to farmer_north;
grant select on v_lucrari_mine to farmer_ilfov;

select * from culturi;

-- check all the rights on tables/views:
select grantee, table_name, privilege
from user_tab_privs_made
where grantee in ('FARMER_SOUTH','FARMER_NORTH','FARMER_ILFOV','SALES_COORDINATOR','WAREHOUSE_OPERATOR','FINANCE_OFFICER')
order by grantee, table_name, privilege;

-- pachet cu 5 proceduri = procesele alese pentru entity-process matrix:
create or replace package pkg_processes as
  procedure submit_store_request(
    p_id_solicitare in number,
    p_id_magazin    in number,
    p_id_recolta    in number,
    p_cantitate     in number,
    p_pret          in number,
    p_data          in date default sysdate
  );

  procedure approve_request(
    p_id_solicitare in number,
    p_status        in varchar2 -- aprobata/respinsa
  );

  procedure create_order_from_request(
    p_id_comanda    in number,
    p_id_solicitare in number,
    p_data          in date default sysdate
  );

  procedure record_delivery(
    p_id_comanda    in number,
    p_cantitate     in number,
    p_id_depozit    in number,
    p_status        in varchar2 default 'trimisa', -- trimisa/receptionata
    p_data          in date default sysdate
  );

  procedure register_payment(
    p_id_factura    in number,
    p_suma          in number,
    p_metoda        in varchar2, -- cash/card/transfer
    p_data          in date default sysdate
  );
end pkg_processes;
/

create or replace package body pkg_processes as
  procedure submit_store_request(
    p_id_solicitare in number,
    p_id_magazin    in number,
    p_id_recolta    in number,
    p_cantitate     in number,
    p_pret          in number,
    p_data          in date default sysdate
  ) as
  begin
    insert into solicitari(id_solicitare,id_magazin,id_recolta,cantitate,pret,data_solicitare,status)
    values(p_id_solicitare,p_id_magazin,p_id_recolta,p_cantitate,p_pret,p_data,'nou');
  end;

  procedure approve_request(
    p_id_solicitare in number,
    p_status        in varchar2
  ) as
  begin
    if p_status not in ('aprobata','respinsa') then
      raise_application_error(-20101,'status invalid (foloseste aprobata/respinsa)');
    end if;

    update solicitari
    set status = p_status
    where id_solicitare = p_id_solicitare;

    if sql%rowcount = 0 then
      raise_application_error(-20102,'solicitare inexistenta');
    end if;
  end;

  procedure create_order_from_request(
    p_id_comanda    in number,
    p_id_solicitare in number,
    p_data          in date default sysdate
  ) as
  begin
    insert into comenzi(id_comanda,id_solicitare,id_magazin,id_recolta,cantitate,pret,data_comanda,status)
    values(p_id_comanda,p_id_solicitare,null,null,null,null,p_data,'creata');
  end;

  procedure record_delivery(
    p_id_comanda    in number,
    p_cantitate     in number,
    p_id_depozit    in number,
    p_status        in varchar2 default 'trimisa',
    p_data          in date default sysdate
  ) as
  begin
    if p_status not in ('trimisa','receptionata','anulata') then
      raise_application_error(-20111,'status livrare invalid');
    end if;

    insert into livrari(id_comanda,cantitate_livrata,data_livrare,status,id_depozit)
    values(p_id_comanda,p_cantitate,p_data,p_status,p_id_depozit);
  end;

  procedure register_payment(
    p_id_factura    in number,
    p_suma          in number,
    p_metoda        in varchar2,
    p_data          in date default sysdate
  ) as
  begin
    insert into plati(id_factura,data_plata,suma,metoda)
    values(p_id_factura,p_data,p_suma,p_metoda);
  end;

end pkg_processes;
/

grant execute on pkg_processes to sales_coordinator;
grant execute on pkg_processes to warehouse_operator;
grant execute on pkg_processes to finance_officer;

-- cerinta 5 din proiect - a)
-- creez view safe pe stocuri pentru inventory_auditor:
create or replace view v_stock_depozit_safe as
select sd.id_depozit,
       d.denumire as depozit,
       sd.id_recolta,
       r.denumire_recolta,
       r.categorie_recolta,
       sd.cantitate_kg,
       sd.data_update
from stoc_depozit sd
join depozite d on d.id_depozit = sd.id_depozit
join recolte  r on r.id_recolta = sd.id_recolta;

create or replace view v_stock_magazin_safe as
select sm.id_magazin,
       m.denumire_magazin,
       m.tip_magazin,
       sm.id_recolta,
       r.denumire_recolta,
       r.categorie_recolta,
       sm.cantitate_kg,
       sm.data_update
from stoc_magazin sm
join magazine m on m.id_magazin = sm.id_magazin
join recolte  r on r.id_recolta = sm.id_recolta;

-- acorda catre warehouse_operator select pe view cu WITH GRANT OPTION:
grant select on administrator.v_stock_depozit_safe to warehouse_operator with grant option;

-- 5b
-- catalog
grant select on administrator.recolte  to r_read_catalog;
grant select on administrator.magazine to r_read_catalog;

-- farmer “mine” (row-level)
grant select on administrator.v_parcele_mine to r_farmer_self_read;
grant select on administrator.v_culturi_mine to r_farmer_self_read;
grant select on administrator.v_lucrari_mine to r_farmer_self_read;

-- procese (dml prin proces, nu direct)
grant execute on administrator.pkg_processes to r_sales_exec;
grant execute on administrator.pkg_processes to r_warehouse_exec;
grant execute on administrator.pkg_processes to r_finance_exec;

-- stergere drepturi acordate anterior, in contradictie cu ierarhia:
revoke select on administrator.recolte from farmer_south;
revoke select on administrator.recolte from farmer_north;
revoke select on administrator.recolte from farmer_ilfov;

revoke select on administrator.magazine from sales_coordinator;

revoke select on administrator.v_stock_depozit_safe from warehouse_operator;

-- cerinta suplimentara (creare rol securizat):
grant select on administrator.stoc_depozit to r_ops_emergency;
grant select on administrator.stoc_magazin to r_ops_emergency;

-- procedura care activeaza rolul doar daca user-ul este farm_manager:
create or replace package pkg_emergency_role as
  procedure enable_role;
end pkg_emergency_role;
/

create or replace package body pkg_emergency_role as
  procedure enable_role is
  begin
    if user <> 'FARM_MANAGER' then
      raise_application_error(-20901,'only farm_manager can enable emergency role');
    end if;

    if to_number(to_char(sysdate,'hh24')) not between 8 and 18 then
      raise_application_error(-20902,'emergency role allowed only 08-18');
    end if;

    dbms_session.set_role('R_OPS_EMERGENCY');
  end enable_role;
end pkg_emergency_role;
/

commit;
select object_name, status from user_objects where object_name='PKG_EMERGENCY_ROLE';

grant execute on administrator.pkg_emergency_role to farm_manager;

select text
from user_source
where name='PKG_EMERGENCY_ROLE'
  and type='PACKAGE'
order by line;

-- 5 c):
create or replace view v_depozite_status as
select d.id_depozit,
       d.denumire,
       d.capacitate_kg,
       nvl(sum(sd.cantitate_kg),0) total_in_stoc
from depozite d
left join stoc_depozit sd on sd.id_depozit=d.id_depozit
group by d.id_depozit, d.denumire, d.capacitate_kg;

-- acordare drept pe view doar pt user inventory_auditor:
grant select on administrator.v_depozite_status to inventory_auditor;

-- 5 c) demo 2:
create role r_fm_dep;
grant select on administrator.depozite to r_fm_dep;

-- cerinta 6:
CREATE OR REPLACE VIEW v_culturi_active AS
SELECT c.*, r.denumire_recolta, p.denumire as nume_parcela
FROM administrator.culturi c
JOIN administrator.recolte r ON c.id_recolta = r.id_recolta
JOIN administrator.parcele p ON c.id_parcela = p.id_parcela
WHERE p.id_ferma = SYS_CONTEXT('CTX_FARM_SECURITY', 'CURRENT_FERMA_ID')
OR SYS_CONTEXT('CTX_FARM_SECURITY', 'CURRENT_FERMA_ID') = 0; -- Admin vede tot

GRANT SELECT ON v_culturi_active TO farmer_north;

-- 6b) - SQL Injection:
CREATE OR REPLACE PROCEDURE search_producatori_vuln(p_nume IN VARCHAR2) AS
  v_sql   VARCHAR2(4000);
  v_id_producator  NUMBER;
  v_nume VARCHAR2(50);
  v_prenume VARCHAR2(40);
  v_email varchar2(40);
  v_id_utilaj NUMBER;
  v_id_sef NUMBER;
  c SYS_REFCURSOR;
BEGIN
  v_sql := 'SELECT id_producator, nume, prenume, email, id_utilaj, id_sef FROM producatori ' ||
           'WHERE UPPER(nume) LIKE ''%' || UPPER(p_nume) || '%''';
  OPEN c FOR v_sql;
  LOOP
    FETCH c INTO v_id_producator, v_nume, v_prenume, v_email, v_id_utilaj, v_id_sef;
    EXIT WHEN c%NOTFOUND;
    DBMS_OUTPUT.PUT_LINE('FOUND: ' || v_id_producator || ' nume=' || v_nume || ' prenume=' || v_prenume || ' email=' || v_email || ' id_sef=' || v_id_sef || ' id_utilaj=' || v_id_utilaj);
  END LOOP;
  CLOSE c;
END;
/

GRANT EXECUTE ON search_producatori_vuln TO inventory_auditor;

-- patch pt UNION based SQL Injection:
CREATE OR REPLACE PROCEDURE search_producatori_safe(p_nume IN VARCHAR2) AS
  v_sql   VARCHAR2(4000);
  v_id_producator  NUMBER;
  v_nume VARCHAR2(50);
  v_prenume VARCHAR2(40);
  v_email VARCHAR2(40);
  v_id_utilaj NUMBER;
  v_id_sef NUMBER;
  c SYS_REFCURSOR;
BEGIN
  v_sql := 'SELECT id_producator, nume, prenume, email, id_utilaj, id_sef
            FROM producatori
            WHERE UPPER(nume) LIKE :p';
  OPEN c FOR v_sql USING '%' || UPPER(p_nume) || '%';
  LOOP
    FETCH c INTO v_id_producator, v_nume, v_prenume, v_email, v_id_utilaj, v_id_sef;
    EXIT WHEN c%NOTFOUND;
    DBMS_OUTPUT.PUT_LINE('FOUND: ' || v_id_producator ||
                         ' nume=' || v_nume ||
                         ' prenume=' || v_prenume ||
                         ' email=' || v_email ||
                         ' id_sef=' || v_id_sef ||
                         ' id_utilaj=' || v_id_utilaj);
  END LOOP;
  CLOSE c;
END;
/

GRANT EXECUTE ON search_producatori_safe TO inventory_auditor;

-- cerinta 7 - data masking (1 = ca in lab):
create table utilaje_test as select * from utilaje;

CREATE OR REPLACE PACKAGE pack_utilaje AS
  FUNCTION f_text(p_txt IN VARCHAR2) RETURN VARCHAR2 DETERMINISTIC;
  FUNCTION f_durata(p_val IN NUMBER)  RETURN NUMBER  DETERMINISTIC;
END pack_utilaje;
/

CREATE OR REPLACE PACKAGE BODY pack_utilaje AS
  FUNCTION f_text(p_txt IN VARCHAR2) RETURN VARCHAR2 DETERMINISTIC IS
    v_raw   RAW(2000);
    v_hash  RAW(32);
    v_hex   VARCHAR2(64);
    v_first VARCHAR2(1);
  BEGIN
    IF p_txt IS NULL THEN
      RETURN NULL;
    END IF;

    v_first := SUBSTR(TRIM(p_txt), 1, 1);

    -- Hash determinist folosind DBMS_CRYPTO
    v_raw  := UTL_RAW.cast_to_raw(UPPER(TRIM(p_txt)));
    v_hash := DBMS_CRYPTO.hash(v_raw, DBMS_CRYPTO.hash_sh256);
    v_hex  := RAWTOHEX(v_hash);

    -- Ex: g-9F3A12BC
    RETURN LOWER(v_first) || '-' || SUBSTR(v_hex, 1, 8);
  END f_text;


  FUNCTION f_durata(p_val IN NUMBER) RETURN NUMBER DETERMINISTIC IS
    v_raw   RAW(2000);
    v_hash  RAW(32);
    v_hex   VARCHAR2(64);
    v_byte  NUMBER;
    v_base  NUMBER;
    v_noise NUMBER;
  BEGIN
    IF p_val IS NULL THEN
      RETURN NULL;
    END IF;

    -- cuantizare la 0.5
    v_base := ROUND(p_val * 2) / 2;

    -- noise determinist derivat din hash
    v_raw  := UTL_RAW.cast_to_raw(TO_CHAR(p_val));
    v_hash := DBMS_CRYPTO.hash(v_raw, DBMS_CRYPTO.hash_sh256);
    v_hex  := RAWTOHEX(v_hash);

    v_byte := TO_NUMBER(SUBSTR(v_hex, 1, 2), 'XX');
    v_noise := (MOD(v_byte, 5) - 2) / 10;  -- {-0.2, -0.1, 0, 0.1, 0.2}

    RETURN GREATEST(0, v_base + v_noise);
  END f_durata;

END pack_utilaje;
/

-- din utilaje_test
SELECT id_utilaj,
       pack_utilaje.f_text(denumire_utilaj) AS expected_denumire,
       pack_utilaje.f_durata(durata_utilizare) AS expected_durata
FROM utilaje_test
ORDER BY id_utilaj;

-- din utilaje_final, dupa import
SELECT id_utilaj,
       denumire_utilaj AS actual_denumire,
       durata_utilizare AS actual_durata
FROM utilaje_final
ORDER BY id_utilaj;

-- mascare nr 2:
CREATE TABLE facturi_test AS
SELECT * FROM facturi;

BEGIN
  DBMS_REDACT.ADD_POLICY(
    object_schema   => 'ADMINISTRATOR',
    object_name     => 'FACTURI_TEST',
    column_name     => 'VALOARE_TOTALA',
    policy_name     => 'MASK_FACTURI_VALOARE',
    function_type   => DBMS_REDACT.RANDOM,
    expression      => 'SYS_CONTEXT(''USERENV'',''SESSION_USER'') <> ''ADMINISTRATOR'''
  );
END;
/

SELECT * FROM facturi_test;
GRANT SELECT on facturi_test TO warehouse_operator;






