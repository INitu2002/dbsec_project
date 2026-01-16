-- test if farmer_south can access only the "parcele" that are under his tutela:
select * from administrator.v_parcele_mine;

-- selectare prin view a culturilor doar pt farmer_south:
select c.id_cultura, p.id_parcela, p.denumire as denumire_parcela, p.judet, p.localitate, c.id_recolta
from administrator.v_culturi_mine c, administrator.v_parcele_mine p
where c.id_parcela = p.id_parcela;