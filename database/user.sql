create table user_table
(
    id       integer not null
        primary key,
    uid      uuid    not null,
    username varchar not null,
    email    varchar not null,
    phone    varchar not null,
    password varchar not null,
    role     varchar
);

alter table user_table
    owner to ironpulse;