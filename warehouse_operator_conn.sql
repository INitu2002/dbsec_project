-- cerinta 5a):
-- deleaga rol r_stock_read catre user inventory_audit:
grant r_stock_read to inventory_auditor;

-- 5 b):
-- arată rolurile active
select * from session_roles;
select * from administrator.v_stock_depozit_safe;

-- testare drept dupa revoke r_stock_read from r_warehouse din SYS:
set role all;  -- in loc de reconectare
select * from session_roles;
select * from administrator.v_stock_depozit_safe; 

-- cerinta 7 - data masking
-- testare dmbs_redact:
SELECT * FROM administrator.facturi_test;





