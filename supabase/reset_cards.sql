begin;
do $$ declare t text; begin foreach t in array array['public.card_transfers','public.orders','public.auctions','public.collectibles','public.users'] loop if to_regclass(t) is not null then execute format('truncate table %s restart identity cascade',t); end if; end loop; end $$;
create unique index if not exists collectibles_card_username_ci_unique on public.collectibles (lower(card_username)) where card_username is not null and btrim(card_username) <> '';
commit;