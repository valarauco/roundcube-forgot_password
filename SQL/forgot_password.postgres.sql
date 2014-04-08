CREATE TABLE "forgot_password" (
    "user_id" integer NOT NULL PRIMARY KEY,
    "alternative_email" varchar(200) NOT NULL,
    "token" varchar(40),
    "token_expiration" timestamp with time zone
);

