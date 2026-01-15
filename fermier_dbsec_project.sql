select * from administrator.comenzi;
update administrator.comenzi set status='in_livrare' where id_comanda=1001;
select * from administrator.facturi;

-- ex 2, lab 2:
-- fermier_test: încearcă o solicitare ilogica (triggerul o respinge)
-- 500 e angro, 14 e legume => trebuie sa pice
insert into administrator.solicitari(id_solicitare,id_magazin,id_recolta,cantitate,pret,status)
values(9999,500,14,10,7,'nou');

-- ex 3, lab 2:
select id_recolta, pret_kg
from administrator.recolte
where id_recolta=11;

update administrator.recolte
set pret_kg = pret_kg * 1.10
where id_recolta=11;

commit;

select id_recolta, pret_kg
from administrator.recolte
where id_recolta=11;

-- log din audit:
select *
from administrator.audit_preturi_recolte
where id_recolta=11
order by id_audit desc;

-- update, test 2, blocat pt ca modificare pret > 30%:
update administrator.recolte
set pret_kg = pret_kg * 2
where id_recolta=11;

-- verificare tabel audit_preturi_recolte:
select *
from administrator.audit_preturi_recolte
where id_recolta=11
order by id_audit desc;

-- ex 4, lab 2:
update administrator.plati
set suma = 6000
where id_plata = (select min(id_plata) from administrator.plati);

commit;





