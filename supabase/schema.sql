-- Nuestro Adviento · esquema Supabase
-- Ejecutar entero en: Supabase → SQL Editor → New query → Run

create extension if not exists pgcrypto with schema extensions;

-- ---------- tablas ----------
create table if not exists public.couples (
  id uuid primary key default gen_random_uuid(),
  code text unique not null,
  year int not null,
  unlock text not null default 'libre' check (unlock in ('libre','diario')),
  capsule_text text not null default '',
  capsule_sealed boolean not null default false,
  capsule_sealed_at timestamptz,
  capsule_opened_early boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.members (
  couple_id uuid not null references public.couples(id) on delete cascade,
  slot text not null check (slot in ('a','b')),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  name text not null default '',
  recovery_hash text not null,
  joined_at timestamptz not null default now(),
  primary key (couple_id, slot)
);

create table if not exists public.days (
  couple_id uuid not null references public.couples(id) on delete cascade,
  n int not null check (n between 1 and 31),
  opened boolean not null default false,
  done boolean not null default false,
  mode text check (mode in ('juntos','individual','conjunta','reto')),
  custom jsonb,
  shared_note text not null default '',
  updated_at timestamptz not null default now(),
  primary key (couple_id, n)
);

create table if not exists public.answers (
  couple_id uuid not null references public.couples(id) on delete cascade,
  n int not null check (n between 1 and 31),
  slot text not null check (slot in ('a','b')),
  body text not null default '',
  submitted boolean not null default false,
  updated_at timestamptz not null default now(),
  primary key (couple_id, n, slot)
);

-- ---------- helpers (security definer: evitan recursión en RLS) ----------
create or replace function public.is_member(p_couple uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from members where couple_id = p_couple and user_id = auth.uid())
$$;

create or replace function public.my_slot(p_couple uuid) returns text
language sql stable security definer set search_path = public as $$
  select slot from members where couple_id = p_couple and user_id = auth.uid()
$$;

create or replace function public.both_submitted(p_couple uuid, p_n int) returns boolean
language sql stable security definer set search_path = public as $$
  select count(*) = 2 from answers where couple_id = p_couple and n = p_n and submitted
$$;

create or replace function public.gen_code(p_len int default 6) returns text
language sql volatile as $$
  select string_agg(substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + floor(random()*32)::int, 1), '')
  from generate_series(1, p_len)
$$;

-- ---------- RLS ----------
alter table public.couples enable row level security;
alter table public.members enable row level security;
alter table public.days    enable row level security;
alter table public.answers enable row level security;

drop policy if exists couples_select on public.couples;
drop policy if exists couples_update on public.couples;
create policy couples_select on public.couples for select using (public.is_member(id));
create policy couples_update on public.couples for update using (public.is_member(id)) with check (public.is_member(id));

drop policy if exists members_select on public.members;
drop policy if exists members_update on public.members;
create policy members_select on public.members for select using (public.is_member(couple_id));
create policy members_update on public.members for update using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists days_select on public.days;
drop policy if exists days_insert on public.days;
drop policy if exists days_update on public.days;
create policy days_select on public.days for select using (public.is_member(couple_id));
create policy days_insert on public.days for insert with check (public.is_member(couple_id));
create policy days_update on public.days for update using (public.is_member(couple_id)) with check (public.is_member(couple_id));

-- Respuestas individuales: ves la tuya siempre; la de tu pareja solo cuando las dos están enviadas.
drop policy if exists answers_select on public.answers;
drop policy if exists answers_insert on public.answers;
drop policy if exists answers_update on public.answers;
create policy answers_select on public.answers for select
  using (public.is_member(couple_id) and (slot = public.my_slot(couple_id) or public.both_submitted(couple_id, n)));
create policy answers_insert on public.answers for insert with check (slot = public.my_slot(couple_id));
create policy answers_update on public.answers for update
  using (slot = public.my_slot(couple_id)) with check (slot = public.my_slot(couple_id));

-- Columnas editables desde la app (el resto solo vía funciones)
revoke update on public.couples from anon, authenticated;
grant update (year, unlock, capsule_text, capsule_sealed, capsule_sealed_at, capsule_opened_early) on public.couples to authenticated;
revoke update on public.members from anon, authenticated;
grant update (name) on public.members to authenticated;
revoke insert, delete on public.couples, public.members from anon, authenticated;
revoke all on public.days, public.answers from anon;
grant select, insert, update on public.days, public.answers to authenticated;
grant select on public.couples, public.members to authenticated;

-- ---------- funciones de la app ----------
create or replace function public.create_couple(p_name text, p_year int, p_unlock text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_uid uuid := auth.uid(); v_id uuid; v_code text; v_rec text;
begin
  if v_uid is null then raise exception 'NOT_AUTHENTICATED'; end if;
  if exists(select 1 from members where user_id = v_uid) then raise exception 'ALREADY_MEMBER'; end if;
  loop
    v_code := gen_code(6);
    exit when not exists(select 1 from couples where code = v_code);
  end loop;
  v_rec := gen_code(12);
  insert into couples(code, year, unlock)
    values (v_code, coalesce(p_year, extract(year from now())::int), coalesce(nullif(p_unlock,''), 'libre'))
    returning id into v_id;
  insert into members(couple_id, slot, user_id, name, recovery_hash)
    values (v_id, 'a', v_uid, coalesce(p_name,''), encode(digest(v_rec, 'sha256'), 'hex'));
  return json_build_object('couple_id', v_id, 'code', v_code, 'slot', 'a', 'recovery', v_rec);
end $$;

create or replace function public.join_couple(p_code text, p_name text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_uid uuid := auth.uid(); v_id uuid; v_code text; v_slot text; v_rec text;
begin
  if v_uid is null then raise exception 'NOT_AUTHENTICATED'; end if;
  if exists(select 1 from members where user_id = v_uid) then raise exception 'ALREADY_MEMBER'; end if;
  select id, code into v_id, v_code from couples where code = upper(trim(p_code));
  if v_id is null then raise exception 'CODE_NOT_FOUND'; end if;
  select s into v_slot from unnest(array['a','b']) s
    where not exists(select 1 from members where couple_id = v_id and slot = s) limit 1;
  if v_slot is null then raise exception 'COUPLE_FULL'; end if;
  v_rec := gen_code(12);
  insert into members(couple_id, slot, user_id, name, recovery_hash)
    values (v_id, v_slot, v_uid, coalesce(p_name,''), encode(digest(v_rec, 'sha256'), 'hex'));
  return json_build_object('couple_id', v_id, 'code', v_code, 'slot', v_slot, 'recovery', v_rec);
end $$;

create or replace function public.recover_member(p_code text, p_recovery text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare v_uid uuid := auth.uid(); v_id uuid; v_code text; v_slot text;
begin
  if v_uid is null then raise exception 'NOT_AUTHENTICATED'; end if;
  select m.couple_id, m.slot, c.code into v_id, v_slot, v_code
    from members m join couples c on c.id = m.couple_id
    where c.code = upper(trim(p_code))
      and m.recovery_hash = encode(digest(upper(trim(p_recovery)), 'sha256'), 'hex');
  if v_id is null then raise exception 'RECOVERY_INVALID'; end if;
  if exists(select 1 from members where user_id = v_uid and couple_id <> v_id) then raise exception 'ALREADY_MEMBER'; end if;
  update members set user_id = v_uid where couple_id = v_id and slot = v_slot;
  return json_build_object('couple_id', v_id, 'code', v_code, 'slot', v_slot);
end $$;

create or replace function public.leave_couple()
returns void language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  delete from members where user_id = auth.uid() returning couple_id into v_id;
  if v_id is not null and not exists(select 1 from members where couple_id = v_id) then
    delete from couples where id = v_id;
  end if;
end $$;

-- Quién ha enviado ya su respuesta (sin revelar el texto)
create or replace function public.answer_status(p_couple uuid)
returns table(n int, slot text, submitted boolean)
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_member(p_couple) then raise exception 'NOT_MEMBER'; end if;
  return query select a.n, a.slot, a.submitted from answers a where a.couple_id = p_couple;
end $$;

revoke execute on function public.create_couple(text,int,text), public.join_couple(text,text),
  public.recover_member(text,text), public.leave_couple(), public.answer_status(uuid) from public, anon;
grant execute on function public.create_couple(text,int,text), public.join_couple(text,text),
  public.recover_member(text,text), public.leave_couple(), public.answer_status(uuid) to authenticated;

-- ---------- tiempo real ----------
do $$ begin
  begin alter publication supabase_realtime add table public.couples; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.members; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.days;    exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.answers; exception when duplicate_object then null; end;
end $$;
