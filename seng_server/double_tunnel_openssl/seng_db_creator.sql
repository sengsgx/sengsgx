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
    VALUES(1,0x00b2a8c0,0x00ffffff,0x01b2a8c0);

INSERT INTO enclave_subnets
    VALUES(2,0x000010ac,0xc0ffffff,0x010010ac);

INSERT INTO apps
    VALUES(1,
        "DemoEnclave",
        x'82caa65f71213e5b228b8412bf6b808f3b5ce7d5ea3b5160d52f2475ad271e1d',
        x'34d49426c6379ed64b14c32ae57c02511141603fc5012860221fa56ceedae45b',
        0x0000000a,0xc0ffffff,1);

INSERT INTO apps
    VALUES(2,
        "SDK-NGINX",
        x'3bf7324a7aeb39cb82a085a891f483dbbf3a26dd2792ea354f9b7f9b8a875879',
        x'34d49426c6379ed64b14c32ae57c02511141603fc5012860221fa56ceedae45b',
        0x0000000a,0xc0ffffff,2);
