create table posts (id bigint primary key, author uuid, body text);
alter table posts enable row level security;
create policy "anyone can read" on posts for select using (true);
create policy "owners edit" on posts for update to authenticated using (auth.uid() = author);
create policy "owners insert" on posts for insert to authenticated with check ((select auth.uid()) = author);
