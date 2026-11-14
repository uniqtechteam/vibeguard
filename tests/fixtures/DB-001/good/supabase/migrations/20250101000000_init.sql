create table if not exists "public"."Notes" (id bigint primary key, body text);
create table private.audit_log (id bigint primary key, event text);
create table scratch (id int);
drop table scratch;
-- alter table forgotten enable row level security (a comment, not a statement)
