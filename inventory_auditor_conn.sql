-- cerinta 5a):
-- testez daca merge dreptul de select pe view acordat de warehouse_operator prin rol
-- verific ca nu merge select pe tabela
select * from administrator.v_stock_depozit_safe;
select * from administrator.v_stock_magazin_safe;
select * from administrator.stoc_depozit;

select * from administrator.v_depozite_status;

select * from administrator.stoc_depozit;

-- cerinta 6b):
SET SERVEROUTPUT ON;
EXEC administrator.search_producatori_vuln('olarU');

EXEC administrator.search_producatori_vuln('%'' UNION SELECT NULL FROM dual --');
EXEC administrator.search_producatori_vuln('%'' UNION SELECT NULL, NULL FROM dual --');
EXEC administrator.search_producatori_vuln('%'' UNION SELECT NULL, NULL, NULL FROM dual --');
EXEC administrator.search_producatori_vuln('%'' UNION SELECT NULL, NULL, NULL, NULL FROM dual --');
EXEC administrator.search_producatori_vuln('%'' UNION SELECT NULL, NULL, NULL, NULL, NULL FROM dual --');
EXEC administrator.search_producatori_vuln('%'' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL FROM dual --');

EXEC administrator.search_producatori_vuln('%'' UNION SELECT 9999, ''HACK'', ''X'', ''hack@demo'', 0, 0 FROM dual --');

EXEC administrator.search_producatori_safe('%'' UNION SELECT 9999, NULL, NULL FROM dual --');




