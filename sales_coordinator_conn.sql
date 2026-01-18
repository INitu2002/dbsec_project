begin
  administrator.pkg_processes.submit_store_request(31,502,14,10,7.2,sysdate);
  administrator.pkg_processes.approve_request(31,'aprobata');
  administrator.pkg_processes.create_order_from_request(2001,31,sysdate);
end;
/
commit;

select * from administrator.solicitari;
select * from administrator.comenzi;