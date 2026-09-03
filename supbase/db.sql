create table public.jn_users (
  user_id uuid not null default gen_random_uuid (),
  created_at timestamp without time zone not null default (now() AT TIME ZONE 'UTC'::text),
  first_name character varying null,
  last_name character varying null,
  nick_name character varying null,
  batch_id character varying null,
  auth_user_id uuid not null default gen_random_uuid (),
  email_id character varying not null,
  email_verified_flag smallint not null default '0'::smallint,
  email_verified_at timestamp without time zone null default (now() AT TIME ZONE 'utc'::text),
  constraint jn_users_pkey primary key (user_id)
) TABLESPACE pg_default;