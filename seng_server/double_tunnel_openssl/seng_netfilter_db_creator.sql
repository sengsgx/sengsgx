CREATE TABLE "apps" (
    "id" INTEGER,
    "name" TEXT NOT NULL,
    "mr_enclave" BLOB NOT NULL,
    "mr_signer" BLOB NOT NULL,
    PRIMARY KEY("id"),
    UNIQUE(mr_enclave)
);

CREATE TABLE "categories" (
    "id" INTEGER,
    "name" TEXT NOT NULL,
    "apps_id" INTEGER NOT NULL,
    FOREIGN KEY("apps_id") REFERENCES "apps",
    UNIQUE(name,apps_id)
);

INSERT INTO apps
    VALUES(1,
        "DemoEnclave",
        x'd9237809ab399aa541e42ad54146a2a1bde310dd7dc9fccc1e964dacf4c5c3b0',
        x'100dbba6e9bee19a237cb6be1e79ba6ec5c9b77aa46c1b221dcb67d34edcce2a');

INSERT INTO apps
    VALUES(2,
        "SENG-NGINX",
        x'd5876e37d31ad62d4eafd36997820b18fdea7b104a0e2d3f81873230be2af792',
        x'ad373d1d526e45e3683aeaaf217ba2925024f05a626b0372da855ff4df057c6f');

/*INSERT INTO apps
    VALUES(3,
        "Firefox",
        x'...',
        x'...');

INSERT INTO apps
    VALUES(4,
        "Chromium",
        x'...',
        x'...');*/

INSERT INTO categories
    VALUES(1, "Demo", 1);

INSERT INTO categories
    VALUES(2, "Server", 2);

/*INSERT INTO categories
    VALUES(3, "Browsers", 3);

INSERT INTO categories
    VALUES(4, "Browsers", 4);*/
