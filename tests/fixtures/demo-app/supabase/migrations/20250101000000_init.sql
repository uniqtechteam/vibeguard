create table profiles (
  id uuid primary key references auth.users,
  plan text
);

create table orders (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  paid boolean default false
);
alter table orders enable row level security;
create policy "anyone can mark orders" on orders for update to anon using (true);
