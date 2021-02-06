"use strict";

const { ServiceBroker } = require("moleculer");
const { Agents } = require("../index");
const { SecretsMixin } = require("imicros-minio");
const fs = require("fs");

// helper & mocks
const { ACL, ACLMiddleware, meta, ownerId } = require("./helper/acl");
const { Keys } = require("./helper/keys");

//const timestamp = Date.now();
process.env.JWT_SECRET = fs.readFileSync("dev/private.pem");

beforeAll( async () => {
});

afterAll( async () => {
});

describe("Test group service", () => {

    let broker, service, services = [], token = [];
    
    beforeAll( async () => {
    });

    afterAll(async () => {
    });
    
    describe("Test create service", () => {

        it("it should be created", async () => {
            broker = new ServiceBroker({
                middlewares: [ACLMiddleware],
                logger: console,
                logLevel: "info" //"debug"
            });
            service = broker.createService(Agents, Object.assign({ 
                mixins: [SecretsMixin({ service: "keys" })],
                dependencies: ["keys"],
                settings: { 
                    uri: process.env.URI || "bolt://localhost:7687",
                    user: "neo4j",
                    password: "neo4j",
                    services: {
                        // acl: "v1.acl"
                    }
                } 
            }));
            // Start additional services
            [ACL, Keys].map(service => { return broker.createService(service); }); 
            await broker.start();
            expect(service).toBeDefined();
        });

    });

    describe("Test agents  - part I", () => {
    
        let opts;
        
        beforeEach(() => {
            opts = { meta };
        });
        
        it("it should add an account", async () => {
            let params = {
                label: "my first account - initial",
                role: "member"
            };
            return broker.call("agents.create", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({
                    serviceId: expect.any(String)
                }));
                services.push(res);
            });
        });

        it("it should rename an account", async () => {
            let params = {
                serviceId: services[0].serviceId,
                label: "my first account"
            };
            return broker.call("agents.rename", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({
                    serviceId: params.serviceId,
                    label: params.label
                }));
            });
        });

        it("it should get the account", async () => {
            let params = {
                serviceId: services[0].serviceId
            };
            return broker.call("agents.get", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({
                    serviceId: expect.any(String),
                    label: "my first account",
                    token: []
                }));
            });
        });

        it("it should get all services", async () => {
            let params = {
            };
            return broker.call("agents.getAll", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.length).toEqual(1);
                expect(res).toContainEqual(expect.objectContaining({
                    serviceId: expect.any(String),
                    label: "my first account",
                    token: []
                }));
            });
        });

        it("it should generate an authToken", async () => {
            let params = {
                serviceId: services[0].serviceId
            };
            return broker.call("agents.generateAuthToken", params, opts).then(res => {
                expect(res).toBeDefined();
                // { tokenId, created, expire, authToken }
                expect(res).toEqual(expect.objectContaining({
                    tokenId: expect.any(String),
                    created: expect.any(Number),
                    expire: 1000 * 60 * 60 * 24 * 365,
                    authToken: expect.any(String)
                }));
                token.push(res);
            });
        });

        it("it should get the authToken", async () => {
            let params = {
                serviceId: services[0].serviceId,
                tokenId: token[0].tokenId
            };
            return broker.call("agents.getAuthToken", params, opts).then(res => {
                expect(res).toBeDefined();
                // { tokenId, created, expire, authToken }
                expect(res).toEqual(expect.objectContaining({
                    tokenId: token[0].tokenId,
                    created: token[0].created,
                    expire: 1000 * 60 * 60 * 24 * 365,
                    authToken: token[0].authToken
                }));
            });
        });

        it("it should generate a second authToken", async () => {
            let params = {
                serviceId: services[0].serviceId
            };
            return broker.call("agents.generateAuthToken", params, opts).then(res => {
                expect(res).toBeDefined();
                // { tokenId, created, expire, authToken }
                expect(res).toEqual(expect.objectContaining({
                    tokenId: expect.any(String),
                    created: expect.any(Number),
                    expire: 1000 * 60 * 60 * 24 * 365,
                    authToken: expect.any(String)
                }));
                token.push(res);
            });
        });
        
        it("it should get the account with token", async () => {
            let params = {
                serviceId: services[0].serviceId
            };
            return broker.call("agents.get", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({
                    serviceId: expect.any(String),
                    label: "my first account",
                    token: expect.any(Array)
                }));
                expect(res.token).toContainEqual(expect.objectContaining({
                    tokenId: token[0].tokenId,
                    expire: token[0].expire,
                    created: token[0].created
                }));
                expect(res.token).toContainEqual(expect.objectContaining({
                    tokenId: token[1].tokenId,
                    expire: token[1].expire,
                    created: token[1].created
                }));
            });
        });


        it("it should get all services", async () => {
            let params = {
            };
            return broker.call("agents.getAll", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toContainEqual(expect.objectContaining({
                    serviceId: expect.any(String),
                    label: "my first account",
                    role: "member",
                    token: expect.any(Array)
                }));
                expect(res[0].token).toContainEqual(expect.objectContaining({
                    tokenId: token[0].tokenId,
                    expire: token[0].expire,
                    created: token[0].created
                }));
                expect(res[0].token).toContainEqual(expect.objectContaining({
                    tokenId: token[1].tokenId,
                    expire: token[1].expire,
                    created: token[1].created
                }));
            });
        });

    });
        
    describe("Test login", () => {
    
        let opts, credentials;
        
        beforeEach(() => {
            opts = { meta };
        });

        
        it("it should login", async () => {
            let params = {
                serviceId: services[0].serviceId,
                authToken: token[0].authToken
            };
            return broker.call("agents.login", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(expect.objectContaining({
                    serviceToken: expect.any(String),
                    accessToken: expect.any(String)
                }));
                credentials = res;
                // console.log(res);
            });
        });
        
        it("it should verify session token", async () => {
            let params = {
                serviceToken: credentials.serviceToken
            };
            return broker.call("agents.verify", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.service).toBeDefined();
                // console.log(res);
                expect(res.service).toEqual(expect.objectContaining({
                    serviceId: services[0].serviceId,
                    label: "my first account",
                    ownerId: ownerId
                }));
            });
        });

        it("it should grant access", async () => {
            let opts = {
                meta
            };
            opts.meta.service = {
                serviceToken: credentials.serviceToken
            };
            let params = {};
            return broker.call("agents.grantAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });
        
        it("it should retrieve access token", async () => {
            let opts = {
                meta: {
                    service: {
                        serviceToken: credentials.serviceToken
                    }
                }
            };
            let params =  { ownerId: meta.ownerId };
            return broker.call("agents.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
            });
        });
        
    });
        
    describe("Test agents - part II", () => {
        
        let opts;
        
        beforeEach(() => {
            opts = { meta };
        });
        
        it("it should delete the authToken", async () => {
            let params = {
                serviceId: services[0].serviceId,
                tokenId: token[0].tokenId
            };
            return broker.call("agents.removeAuthToken", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });

        it("it should delete an account", async () => {
            let params = {
                serviceId: services[0].serviceId
            };
            return broker.call("agents.delete", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });

        it("it should return empty array", async () => {
            let params = {
            };
            return broker.call("agents.getAll", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual([]);
            });
        });

    });
    
    describe("Test stop broker", () => {
        it("should stop the broker", async () => {
            expect.assertions(1);
            await broker.stop();
            expect(broker).toBeDefined();
        });
    });        
});