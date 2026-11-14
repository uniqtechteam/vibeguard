create table posts (id bigint primary key, author uuid, body text);
alter table posts enable row level security;

create policy "anyone can read" on posts for select using (true);
create policy "signed in users edit posts" on posts
  for update to authenticated
  using (true);
create policy "open insert" on public.posts for insert to anon with check ( true );
