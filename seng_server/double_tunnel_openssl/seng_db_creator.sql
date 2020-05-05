CREATE TABLE "enclave_subnets" (
	"id"	INTEGER,
	"subnet"	INTEGER NOT NULL,
	"submask"	INTEGER NOT NULL,
    "gateway"   INTEGER,
    UNIQUE(subnet,submask),
    PRIMARY KEY("id")
);

CREATE TABLE "apps" (
    "id"	INTEGER,
    "name" TEXT NOT NULL,
    "mr_enclave" BLOB NOT NULL,
    "mr_signer"	BLOB NOT NULL,
    "host_subnet"	INTEGER NOT NULL,
    "host_submask"	INTEGER NOT NULL,
    "enc_subnet_id" INTEGER NOT NULL,
    FOREIGN KEY("enc_subnet_id") REFERENCES "enclave_subnets",
    UNIQUE(mr_enclave,host_subnet, host_submask),
    PRIMARY KEY("id")
);

INSERT INTO enclave_subnets
    VALUES(1,0x001ca8c0,0x00ffffff,0x011ca8c0);

INSERT INTO enclave_subnets
    VALUES(2,0x001c10ac,0xc0ffffff,0x011c10ac);

INSERT INTO apps
    VALUES(1,
        "DemoEnclave",
        x'8795db4ce3df2a3964a91d4fb058f67b02b351f327439b073a113c7326929716',
        x'be7403a5952075531158572a50b7eb613821df2e18bf6c8b6e1d646dbf42d1a0',
        0x0100007f,0xc0ffffff,1);

INSERT INTO apps
    VALUES(2,
        "SDK-NGINX",
        x'7c6ca940d705e8ffc9614c86526bf24dab2890e7711324694375e9b644e396ea',
        x'be7403a5952075531158572a50b7eb613821df2e18bf6c8b6e1d646dbf42d1a0',
        0x0100007f,0xc0ffffff,2);
