-- test if farmer_south can access only the "parcele" that are under his tutela:
select * from administrator.v_parcele_mine;

-- selectare prin view a culturilor doar pt farmer_south:
select c.id_cultura, p.id_parcela, p.denumire as denumire_parcela, p.judet, p.localitate, c.id_recolta
from administrator.v_culturi_mine c, administrator.v_parcele_mine p
where c.id_parcela = p.id_parcela;

-- cerinta 6:
-- Verifică dacă contextul s-a activat automat la logare
SELECT SYS_CONTEXT('CTX_FARM_SECURITY', 'CURRENT_FERMA_ID') FROM DUAL;

SELECT * FROM administrator.v_culturi_active;

-- verificare culturi farmer_south:
select * from administrator.v_culturi_mine;

EXEC search_products_vuln('%'' UNION SELECT username FROM users_private --');


