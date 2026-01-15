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
















