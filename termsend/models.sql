create type AccountStatuses as enum ('pending', 'active', 'suspended');

create table users (
  id serial primary key,
  email varchar(255) not null unique,
  first_name varchar(63),
  last_name varchar(63),
  password_hash varchar(63)
);
