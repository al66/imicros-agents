"use strict";

const { ServiceBroker } = require("moleculer");
const { Accounts } = require("../index");

//const timestamp = Date.now();

beforeAll( async () => {
});

afterAll( async () => {
});

describe("Test group service", () => {

    let broker, service;
    beforeAll( async () => {
    });

    afterAll(async () => {
    });
    
    describe("Test create service", () => {

        it("it should be created", async () => {
            broker = new ServiceBroker({
                logger: console,
                logLevel: "info" //"debug"
            });
            service = broker.createService(Accounts, Object.assign({ 
                settings: { 
                    uri: process.env.URI || "bolt://localhost:7687",
                    user: "neo4j",
                    password: "neo4j"
                } 
            }));
            await broker.start();
            expect(service).toBeDefined();
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