insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "upload avatars" on storage.objects for insert to anon, authenticated
  with check (bucket_id = 'avatars');
