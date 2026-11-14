-- profiles is created but RLS is never turned on
create table public.profiles (
  id uuid primary key references auth.users,
  full_name text
);

create table todos (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  title text
);
alter table todos enable row level security;
