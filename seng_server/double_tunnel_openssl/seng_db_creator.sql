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
        x'd0d8837438142d663ee2be21fe2f142ca3fe3d509e749f419cd20d8f673129e0',
        x'be7403a5952075531158572a50b7eb613821df2e18bf6c8b6e1d646dbf42d1a0',
        0x0100007f,0xc0ffffff,1);

INSERT INTO apps
    VALUES(2,
        "SDK-NGINX",
        x'42a5bd14b187bd85c369fa47a9fecbbfba7b73b3af6c111141a81dc4f46931bc',
        x'be7403a5952075531158572a50b7eb613821df2e18bf6c8b6e1d646dbf42d1a0',
        0x0100007f,0xc0ffffff,2);
