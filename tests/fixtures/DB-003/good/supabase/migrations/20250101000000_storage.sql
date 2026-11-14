insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "users upload their avatar" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
