"use strict";

const { ServiceBroker } = require("moleculer");

const Middleware = {

    async started(broker) {
    },
    
    // Before broker starting (async)
    async starting(broker) {
    },

    // After broker is created
    async created(broker) {
        console.log(broker.options);
    }
    
};

const Service = {
    name: "Dummy"
};

let masterBroker = new ServiceBroker({
    namespace: "dev",
    nodeID: "A1-master",
    transporter: "nats://192.168.2.124:4222",
    logger: console,
    logLevel: "info", //"debug",
    customProperty: "any"
});

let broker = new ServiceBroker({
    namespace: "dev",
    nodeID: "A1-client",
    transporter: "nats://192.168.2.124:4222",
    logger: console,
    logLevel: "info", //"debug"
    middlewares: [Middleware],
});
broker.createService(Service);
broker.start()
.then(async () => {
    await console.log("Started");
})
.then(async () => {
    await broker.stop(); 
    await masterBroker.stop(); 
});


